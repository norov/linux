
/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/authenc.h>
#include <crypto/cryptd.h>
#include <crypto/crypto_wq.h>
#include <crypto/des.h>
#include <crypto/internal/aead.h>
#include <crypto/sha.h>
#include <crypto/xts.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/rtnetlink.h>
#include <linux/scatterlist.h>

#include "cptvf.h"
#include "cptvf_algs.h"

static DEFINE_SPINLOCK(lock);
struct cpt_device_handle {
	struct cpt_vf *dev[MAX_DEVICES];
	atomic_t count;
};

static struct cpt_device_handle se_dev_handle = {
	.count = ATOMIC_INIT(0)
};

static struct cpt_device_handle ae_dev_handle = {
	.count = ATOMIC_INIT(0)
};

static int is_crypto_registered;

static void cvm_callback(int status, void *arg)
{
	struct crypto_async_request *req = (struct crypto_async_request *)arg;

	req->complete(req, status);
}

static inline void update_input_iv(struct cpt_request_info *req_info,
				   u8 *iv, u32 enc_iv_len,
				   u32 *argcnt)
{
	/* Setting the iv information */
	req_info->in[*argcnt].vptr = (void *)iv;
	req_info->in[*argcnt].size = enc_iv_len;
	req_info->req.dlen += enc_iv_len;

	++(*argcnt);
}

static inline void update_output_iv(struct cpt_request_info *req_info,
				    u8 *iv, u32 enc_iv_len,
				    u32 *argcnt)
{
	/* Setting the iv information */
	req_info->out[*argcnt].vptr = (void *)iv;
	req_info->out[*argcnt].size = enc_iv_len;
	req_info->rlen += enc_iv_len;

	++(*argcnt);
}

static inline void update_input_data(struct cpt_request_info *req_info,
				     struct scatterlist *inp_sg,
				     u32 nbytes, u32 *argcnt)
{
	req_info->req.dlen += nbytes;

	while (nbytes) {
		u32 len = min(nbytes, inp_sg->length);
		u8 *ptr = sg_virt(inp_sg);

		req_info->in[*argcnt].vptr = (void *)ptr;
		req_info->in[*argcnt].size = len;
		nbytes -= len;
		++(*argcnt);
		inp_sg = sg_next(inp_sg);
	}
}

static inline void update_output_data(struct cpt_request_info *req_info,
				      struct scatterlist *outp_sg,
				      u32 nbytes, u32 *argcnt)
{
	req_info->rlen += nbytes;

	while (nbytes) {
		u32 len = min(nbytes, outp_sg->length);
		u8 *ptr = sg_virt(outp_sg);

		req_info->out[*argcnt].vptr = (void *)ptr;
		req_info->out[*argcnt].size = len;
		nbytes -= len;
		++(*argcnt);
		outp_sg = sg_next(outp_sg);
	}
}

static inline u32 create_ctx_hdr(struct ablkcipher_request *req, u32 enc,
				 u32 *argcnt)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct cvm_enc_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct cvm_req_ctx *rctx = ablkcipher_request_ctx(req);
	struct fc_context *fctx = &rctx->fctx;
	u64 *offset_control = &rctx->control_word;
	u32 enc_iv_len = crypto_ablkcipher_ivsize(tfm);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	u64 *ctrl_flags = NULL;

	req_info->ctrl.s.grp = 0;
	req_info->ctrl.s.dma_mode = DMA_GATHER_SCATTER;
	req_info->ctrl.s.se_req = SE_CORE_REQ;

	req_info->req.opcode.s.major = MAJOR_OP_FC |
					DMA_MODE_FLAG(DMA_GATHER_SCATTER);
	if (enc)
		req_info->req.opcode.s.minor = 2;
	else
		req_info->req.opcode.s.minor = 3;

	req_info->req.param1 = req->nbytes; /* Encryption Data length */
	req_info->req.param2 = 0; /*Auth data length */

	fctx->enc.enc_ctrl.e.enc_cipher = ctx->cipher_type;
	fctx->enc.enc_ctrl.e.aes_key = ctx->key_type;
	fctx->enc.enc_ctrl.e.iv_source = FROM_CTX;

	if (ctx->cipher_type == AES_XTS)
		memcpy(fctx->enc.encr_key, ctx->enc_key, ctx->key_len * 2);
	else
		memcpy(fctx->enc.encr_key, ctx->enc_key, ctx->key_len);

	memcpy(fctx->enc.encr_iv, req->info, enc_iv_len);

	ctrl_flags = (u64 *)&fctx->enc.enc_ctrl.flags;
	*ctrl_flags = cpu_to_be64(*ctrl_flags);

	*offset_control = 0;
	/* Storing  Packet Data Information in offset
	 * Control Word First 8 bytes
	 */
	req_info->in[*argcnt].vptr = (u8 *)offset_control;
	req_info->in[*argcnt].size = CONTROL_WORD_LEN;
	req_info->req.dlen += CONTROL_WORD_LEN;
	++(*argcnt);

	req_info->in[*argcnt].vptr = (u8 *)fctx;
	req_info->in[*argcnt].size = sizeof(struct fc_context);
	req_info->req.dlen += sizeof(struct fc_context);

	++(*argcnt);

	return 0;
}

static inline u32 create_input_list(struct ablkcipher_request  *req, u32 enc,
				    u32 enc_iv_len)
{
	struct cvm_req_ctx *rctx = ablkcipher_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	u32 argcnt =  0;

	create_ctx_hdr(req, enc, &argcnt);
	update_input_data(req_info, req->src, req->nbytes, &argcnt);
	req_info->incnt = argcnt;

	return 0;
}

static inline void store_cb_info(struct ablkcipher_request *req,
				 struct cpt_request_info *req_info)
{
	req_info->callback = (void *)cvm_callback;
	req_info->callback_arg = (void *)&req->base;
}

static inline void create_output_list(struct ablkcipher_request *req,
				      u32 enc_iv_len)
{
	struct cvm_req_ctx *rctx = ablkcipher_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	u32 argcnt = 0;

	/* OUTPUT Buffer Processing
	 * AES encryption/decryption output would be
	 * received in the following format
	 *
	 * ------IV--------|------ENCRYPTED/DECRYPTED DATA-----|
	 * [ 16 Bytes/     [   Request Enc/Dec/ DATA Len AES CBC ]
	 */
	/* Reading IV information */
	update_output_data(req_info, req->dst, req->nbytes, &argcnt);
	req_info->outcnt = argcnt;
}

static inline int cvm_enc_dec(struct ablkcipher_request *req, u32 enc)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct cvm_req_ctx *rctx = ablkcipher_request_ctx(req);
	u32 enc_iv_len = crypto_ablkcipher_ivsize(tfm);
	struct fc_context *fctx = &rctx->fctx;
	struct cpt_request_info *req_info = &rctx->cpt_req;
	struct cpt_vf *cptvf = NULL;
	int status, cpu;

	memset(req_info, 0, sizeof(struct cpt_request_info));
	memset(fctx, 0, sizeof(struct fc_context));
	create_input_list(req, enc, enc_iv_len);
	create_output_list(req, enc_iv_len);
	store_cb_info(req, req_info);
	cpu = get_cpu();
	if (cpu >= atomic_read(&se_dev_handle.count)) {
		put_cpu();
		return -ENODEV;
	}
	cptvf = se_dev_handle.dev[cpu];
	put_cpu();
	status = cptvf_do_request(cptvf, req_info);
	/* We perform an asynchronous send and once
	 * the request is completed the driver would
	 * intimate through registered call back functions
	 */
	return status;
}

int cvm_encrypt(struct ablkcipher_request *req)
{
	return cvm_enc_dec(req, true);
}

int cvm_decrypt(struct ablkcipher_request *req)
{
	return cvm_enc_dec(req, false);
}

int cvm_xts_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
		   u32 keylen)
{
	struct crypto_tfm *tfm = crypto_ablkcipher_tfm(cipher);
	struct cvm_enc_ctx *ctx = crypto_tfm_ctx(tfm);
	int err;
	const u8 *key1 = key;
	const u8 *key2 = key + (keylen / 2);

	err = xts_check_key(tfm, key, keylen);
	if (err)
		return err;
	ctx->key_len = keylen;
	memcpy(ctx->enc_key, key1, keylen / 2);
	memcpy(ctx->enc_key + KEY2_OFFSET, key2, keylen / 2);
	ctx->cipher_type = AES_XTS;
	switch (ctx->key_len) {
	case 32:
		ctx->key_type = AES_128_BIT;
		break;
	case 64:
		ctx->key_type = AES_256_BIT;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int cvm_validate_keylen(struct cvm_enc_ctx *ctx, u32 keylen)
{
	if ((keylen == 16) || (keylen == 24) || (keylen == 32)) {
		ctx->key_len = keylen;
		switch (ctx->key_len) {
		case 16:
			ctx->key_type = AES_128_BIT;
			break;
		case 24:
			ctx->key_type = AES_192_BIT;
			break;
		case 32:
			ctx->key_type = AES_256_BIT;
			break;
		default:
			return -EINVAL;
		}

		if (ctx->cipher_type == DES3_CBC)
			ctx->key_type = 0;

		return 0;
	}

	return -EINVAL;
}

static int cvm_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
		      u32 keylen, u8 cipher_type)
{
	struct crypto_tfm *tfm = crypto_ablkcipher_tfm(cipher);
	struct cvm_enc_ctx *ctx = crypto_tfm_ctx(tfm);

	ctx->cipher_type = cipher_type;
	if (!cvm_validate_keylen(ctx, keylen)) {
		memcpy(ctx->enc_key, key, keylen);
		return 0;
	}

	crypto_ablkcipher_set_flags(cipher, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

static int cvm_cbc_aes_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
			      u32 keylen)
{
	return cvm_setkey(cipher, key, keylen, AES_CBC);
}

static int cvm_ecb_aes_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
			      u32 keylen)
{
	return cvm_setkey(cipher, key, keylen, AES_ECB);
}

static int cvm_cfb_aes_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
			      u32 keylen)
{
	return cvm_setkey(cipher, key, keylen, AES_CFB);
}

static int cvm_cbc_des3_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
			       u32 keylen)
{
	return cvm_setkey(cipher, key, keylen, DES3_CBC);
}

static int cvm_ecb_des3_setkey(struct crypto_ablkcipher *cipher, const u8 *key,
			       u32 keylen)
{
	return cvm_setkey(cipher, key, keylen, DES3_ECB);
}

int cvm_enc_dec_init(struct crypto_tfm *tfm)
{
	struct cvm_enc_ctx *ctx = crypto_tfm_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	tfm->crt_ablkcipher.reqsize = sizeof(struct cvm_req_ctx) +
					sizeof(struct ablkcipher_request);
	/* Additional memory for ablkcipher_request is
	 * allocated since the cryptd daemon uses
	 * this memory for request_ctx information
	 */

	return 0;
}

static int cvm_aead_init(struct crypto_aead *tfm)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(tfm);

	ctx->hashalg = crypto_alloc_shash("sha1", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(ctx->hashalg))
		return PTR_ERR(ctx->hashalg);

	tfm->reqsize = sizeof(struct cvm_req_ctx) + sizeof(struct aead_request);

	return 0;
}

void cvm_aead_exit(struct crypto_aead *tfm)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(tfm);

	kfree(ctx->ipad);
	kfree(ctx->opad);
	if (ctx->hashalg)
		crypto_free_shash(ctx->hashalg);
	kfree(ctx->sdesc);
}

/* This is the Integrity Check Value (aka the authentication tag length and can
 * be 8, 12 or 16 bytes long.
 */
static int cvm_aead_set_authsize(struct crypto_aead *tfm,
				 unsigned int authsize)
{
	switch (authsize) {
	case 12: /* SHA1 Truncated Mac len of 96 Bit =12BYTES */
	case 16: /* MD5*/
	case 20: /* SHA1 */
	case 28: /* SHA224*/
	case 32: /* SHA256*/
	case 48: /* SHA384*/
	case 64: /* SHA512*/
		break;
	default:
		return -EINVAL;
	}
	tfm->authsize = authsize;

	return 0;
}

static struct sdesc *alloc_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return NULL;

	sdesc->shash.tfm = alg;
	sdesc->shash.flags = 0x0;

	return sdesc;
}

inline void swap_data(u32 *buf, u32 len, u32 unit)
{
	u32 *store = (u32 *)buf;
	int i = 0;

	for (i = 0 ; i < len/unit; i++, store++)
		*store = cpu_to_be32(*store);
}

static int calculateipadopad(struct crypto_aead *cipher)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(cipher);
	int bs = crypto_shash_blocksize(ctx->hashalg);
	int ds = crypto_shash_digestsize(ctx->hashalg);
	int state_size = crypto_shash_statesize(ctx->hashalg);
	int authkeylen = ctx->authkeylen;
	int err = 0, icount = 0;
	u8 *ipad = NULL, *opad = NULL;
	struct sha1_state *sha1;

	ctx->sdesc = alloc_sdesc(ctx->hashalg);
	if (IS_ERR(ctx->sdesc))
		return -ENOMEM;

	ctx->ipad = kzalloc(SHA1_BLOCK_SIZE, GFP_KERNEL);
	if (!ctx->ipad)
		goto calc_fail;

	ctx->opad = kzalloc(SHA1_BLOCK_SIZE, GFP_KERNEL);
	if (!ctx->opad)
		goto calc_fail;

	ipad = kzalloc(state_size, GFP_KERNEL);
	if (!ipad)
		goto calc_fail;

	opad = kzalloc(state_size, GFP_KERNEL);
	if (!opad)
		goto calc_fail;

	if (authkeylen > bs) {
		err = crypto_shash_digest(&ctx->sdesc->shash, ctx->key,
					  authkeylen, ipad);
		if (err)
			goto calc_fail;

		authkeylen = ds;
	} else {
		memcpy(ipad, ctx->key, authkeylen);
	}

	memset(ipad + authkeylen, 0, bs - authkeylen);
	memcpy(opad, ipad, bs);

	for (icount = 0; icount < bs; icount++) {
		ipad[icount] ^= 0x36;
		opad[icount] ^= 0x5c;
	}

	/* IPAD Calculation */
	crypto_shash_init(&ctx->sdesc->shash);
	crypto_shash_update(&ctx->sdesc->shash, ipad, bs);
	crypto_shash_export(&ctx->sdesc->shash, ipad);
	sha1 = (struct sha1_state *)ipad;
	/* Partial Hash calculated from the software
	 * algorithm is retrieved for IPAD & OPAD
	 */
	swap_data(sha1->state, ctx->authkeylen, sizeof(int));
	memcpy(ctx->ipad, &sha1->state, ctx->authkeylen);

	/* OPAD Calculation */
	crypto_shash_init(&ctx->sdesc->shash);
	crypto_shash_update(&ctx->sdesc->shash, opad, bs);
	crypto_shash_export(&ctx->sdesc->shash, opad);
	sha1 = (struct sha1_state *)opad;
	swap_data(sha1->state, ctx->authkeylen, sizeof(int));
	memcpy(ctx->opad, &sha1->state, ctx->authkeylen);

	kfree(ipad);
	kfree(opad);
	return 0;

calc_fail:
	kfree(ctx->ipad);
	kfree(ctx->opad);
	kfree(ipad);
	kfree(opad);
	kfree(ctx->sdesc);

	return -ENOMEM;
}

int cvm_aead_setkey(struct crypto_aead *cipher, const unsigned char *key,
		    unsigned int keylen)
{
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(cipher);
	struct rtattr *rta = (void *)key;
	struct crypto_authenc_key_param *param;
	int enckeylen = 0;
	int authkeylen = 0;
	int status = -EINVAL;

	if (!RTA_OK(rta, keylen))
		goto badkey;

	if (rta->rta_type != CRYPTO_AUTHENC_KEYA_PARAM)
		goto badkey;

	if (RTA_PAYLOAD(rta) < sizeof(*param))
		goto badkey;

	param = RTA_DATA(rta);
	enckeylen = be32_to_cpu(param->enckeylen);
	key += RTA_ALIGN(rta->rta_len);
	keylen -= RTA_ALIGN(rta->rta_len);
	if (keylen < enckeylen)
		goto badkey;

	if (keylen > MAX_KEY_SIZE)
		goto badkey;

	authkeylen = keylen - enckeylen;
	memcpy(ctx->key, key, keylen);
	ctx->keylen = keylen;
	ctx->enckeylen = enckeylen;
	ctx->authkeylen = authkeylen;
	status = calculateipadopad(cipher);
	if (status)
		goto badkey;

	return 0;
badkey:
	crypto_aead_set_flags(cipher, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return status;
}

static inline u32 create_aead_ctx_hdr(struct aead_request *req, u32 enc,
				      u32 cipher_type, u32 aes_key_type,
				      u32 hash_type,  u32 mac_len, u32 *argcnt)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct fc_context *fctx = &rctx->fctx;
	struct cpt_request_info *req_info = &rctx->cpt_req;
	u32 ivsize = crypto_aead_ivsize(tfm);
	u64 *offset_control = &rctx->control_word;
	u64 *ctrl_flags = NULL;
	u16 encr_data_len = 0;
	u16 encr_offset = req->assoclen;
	u16 auth_data_len = 0;

	fctx->enc.enc_ctrl.e.enc_cipher = cipher_type;
	fctx->enc.enc_ctrl.e.aes_key = aes_key_type;
	fctx->enc.enc_ctrl.e.iv_source = FROM_CTX;
	fctx->enc.enc_ctrl.e.hash_type = hash_type;
	fctx->enc.enc_ctrl.e.mac_len = mac_len;
	memcpy(fctx->enc.encr_key, ctx->key + ctx->authkeylen, ctx->enckeylen);
	memcpy(fctx->enc.encr_iv, req->iv, ivsize);
	if (ctx->ipad)
		memcpy(fctx->hmac.ipad, ctx->ipad, 64);

	if (ctx->opad)
		memcpy(fctx->hmac.opad, ctx->opad, 64);

	ctrl_flags = (u64 *)&(fctx->enc.enc_ctrl.flags);
	*ctrl_flags = cpu_to_be64(*ctrl_flags);

	req_info->ctrl.s.grp = 0;
	req_info->ctrl.s.dma_mode = DMA_GATHER_SCATTER;
	req_info->ctrl.s.se_req   = SE_CORE_REQ;
	req_info->req.opcode.s.major = MAJOR_OP_FC |
				 DMA_MODE_FLAG(DMA_GATHER_SCATTER);
	if (enc) {
		req_info->req.opcode.s.minor = 2;
		auth_data_len = req->cryptlen + req->assoclen;
		encr_data_len =	req->cryptlen;
	} else {
		req_info->req.opcode.s.minor = 3;
		auth_data_len = req->cryptlen + req->assoclen - mac_len;
		encr_data_len  = req->cryptlen - mac_len;
	}

	/*GP op header */
	req_info->req.param1 = encr_data_len;
	req_info->req.param2 = auth_data_len;
	*offset_control = cpu_to_be64((u64)encr_offset << 16);

	/* input */
	/* Storing  Packet Data Information in offset
	 * Control Word First 8 bytes
	 */
	req_info->in[*argcnt].vptr = (u8 *)offset_control;
	req_info->in[*argcnt].size = CONTROL_WORD_LEN;
	req_info->req.dlen += CONTROL_WORD_LEN;
	++(*argcnt);

	req_info->in[*argcnt].vptr = (u8 *)fctx;
	req_info->in[*argcnt].size = sizeof(struct fc_context);
	req_info->req.dlen += sizeof(struct fc_context);
	++(*argcnt);

	return 0;
}

static inline u32 create_aead_input_list(struct aead_request *req, u32 enc,
					 u32 cipher_type, u32 aes_key_type,
					 u32 mac_len, u32 hash_type,
					 u32 enc_iv_len)
{
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct cpt_request_info *req_info =  &rctx->cpt_req;
	u32 argcnt =  0;
	u32 inputlen =  req->cryptlen + req->assoclen;

	create_aead_ctx_hdr(req, enc, cipher_type, aes_key_type, hash_type,
			    mac_len, &argcnt);
	update_input_data(req_info, req->src, inputlen, &argcnt);
	req_info->incnt = argcnt;

	return 0;
}

static inline void create_aead_output_list(struct aead_request *req, u32 enc,
					   u32 cipher_type, u32 enc_iv_len,
					   u32 mac_len)
{
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct cpt_request_info *req_info =  &rctx->cpt_req;
	u32 argcnt = 0;
	u32 outputlen = 0;

	if (enc)
		outputlen = req->cryptlen +  req->assoclen + mac_len;
	else
		outputlen = req->cryptlen + req->assoclen - mac_len;

	update_output_data(req_info, req->dst, outputlen, &argcnt);
	req_info->outcnt = argcnt;
}

u32 cvm_aead_enc_dec(struct aead_request *req, u32 enc)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct cvm_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct cvm_req_ctx *rctx = aead_request_ctx(req);
	struct cpt_request_info *req_info = &rctx->cpt_req;
	int mac_len = crypto_aead_authsize(tfm);
	u32 enc_iv_len = crypto_aead_ivsize(tfm);
	struct fc_context *fctx = &rctx->fctx;
	u32 aes_key_type = AES_192_BIT;
	struct cpt_vf *cptvf = NULL;
	u32 status = 0, cpu;

	switch (ctx->enckeylen) {
	case 16:
		aes_key_type = AES_128_BIT;
		break;
	case 24:
		aes_key_type = AES_192_BIT;
		break;
	case 32:
		aes_key_type = AES_256_BIT;
		break;
	default:
		return -EINVAL;
	}

	memset(req_info, 0, sizeof(struct cpt_request_info));
	memset(fctx, 0, sizeof(struct fc_context));

	create_aead_input_list(req, enc, AES_CBC, aes_key_type, mac_len,
			       2, enc_iv_len);
	create_aead_output_list(req, enc, AES_CBC, enc_iv_len, mac_len);
	req_info->callback = (void *)cvm_callback;
	req_info->callback_arg = (void *)&req->base;
	cpu = get_cpu();
	if (cpu >= atomic_read(&se_dev_handle.count)) {
		put_cpu();
		return -ENODEV;
	}
	cptvf = se_dev_handle.dev[cpu];
	put_cpu();
	status = cptvf_do_request(cptvf, req_info);
	/* We perform an asynchronous send and once
	 * the request is completed the driver would
	 * intimate through registered call back functions
	 */
	return status;
}

static int cvm_aead_encrypt(struct aead_request *req)
{
	return cvm_aead_enc_dec(req, true);
}

static int cvm_aead_decrypt(struct aead_request *req)
{
	return cvm_aead_enc_dec(req, false);
}

struct crypto_alg algs[] = { {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_enc_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "xts(aes)",
	.cra_driver_name = "cavium-xts-aes",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.ivsize = AES_BLOCK_SIZE,
			.min_keysize = 2 * AES_MIN_KEY_SIZE,
			.max_keysize = 2 * AES_MAX_KEY_SIZE,
			.setkey = cvm_xts_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
}, {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_enc_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "cbc(aes)",
	.cra_driver_name = "cavium-cbc-aes",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.ivsize = AES_BLOCK_SIZE,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.setkey = cvm_cbc_aes_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
}, {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_enc_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "ecb(aes)",
	.cra_driver_name = "cavium-ecb-aes",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.ivsize = AES_BLOCK_SIZE,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.setkey = cvm_ecb_aes_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
}, {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_enc_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "cfb(aes)",
	.cra_driver_name = "cavium-cfb-aes",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.ivsize = AES_BLOCK_SIZE,
			.min_keysize = AES_MIN_KEY_SIZE,
			.max_keysize = AES_MAX_KEY_SIZE,
			.setkey = cvm_cfb_aes_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
}, {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = DES3_EDE_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_des3_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "cbc(des3_ede)",
	.cra_driver_name = "cavium-cbc-des3_ede",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.min_keysize = DES3_EDE_KEY_SIZE,
			.max_keysize = DES3_EDE_KEY_SIZE,
			.ivsize = DES_BLOCK_SIZE,
			.setkey = cvm_cbc_des3_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
}, {
	.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize = DES3_EDE_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct cvm_des3_ctx),
	.cra_alignmask = 7,
	.cra_priority = 4001,
	.cra_name = "ecb(des3_ede)",
	.cra_driver_name = "cavium-ecb-des3_ede",
	.cra_type = &crypto_ablkcipher_type,
	.cra_u = {
		.ablkcipher = {
			.min_keysize = DES3_EDE_KEY_SIZE,
			.max_keysize = DES3_EDE_KEY_SIZE,
			.ivsize = DES_BLOCK_SIZE,
			.setkey = cvm_ecb_des3_setkey,
			.encrypt = cvm_encrypt,
			.decrypt = cvm_decrypt,
		},
	},
	.cra_init = cvm_enc_dec_init,
	.cra_module = THIS_MODULE,
} };

struct aead_alg cvm_aeads[] = { {
	.base = {
		.cra_name = "authenc(hmac(sha1),cbc(aes))",
		.cra_driver_name = "authenc-hmac-sha1-cbc-aes-cavm",
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_ctxsize = sizeof(struct cvm_aead_ctx),
		.cra_priority = 4001,
		.cra_alignmask = 0,
		.cra_module = THIS_MODULE,
	},
	.init = cvm_aead_init,
	.exit = cvm_aead_exit,
	.setkey = cvm_aead_setkey,
	.setauthsize = cvm_aead_set_authsize,
	.encrypt = cvm_aead_encrypt,
	.decrypt = cvm_aead_decrypt,
	.ivsize = AES_BLOCK_SIZE,
	.maxauthsize = SHA1_DIGEST_SIZE,
} };

static inline int is_any_alg_used(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(algs); i++)
		if (atomic_read(&algs[i].cra_refcnt) != 1)
			return true;
	for (i = 0; i < ARRAY_SIZE(cvm_aeads); i++)
		if (atomic_read(&cvm_aeads[i].base.cra_refcnt) != 1)
			return true;
	return false;
}

static inline int cav_register_algs(void)
{
	int i, err = 0;

	for (i = 0; i < ARRAY_SIZE(algs); i++)
		algs[i].cra_flags &= ~CRYPTO_ALG_DEAD;
	err = crypto_register_algs(algs, ARRAY_SIZE(algs));
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(cvm_aeads); i++)
		cvm_aeads[i].base.cra_flags &= ~CRYPTO_ALG_DEAD;
	err = crypto_register_aeads(cvm_aeads, ARRAY_SIZE(cvm_aeads));
	if (err) {
		crypto_unregister_algs(algs, ARRAY_SIZE(algs));
		return err;
	}

	return 0;
}

static inline void cav_unregister_algs(void)
{
	crypto_unregister_algs(algs, ARRAY_SIZE(algs));
	crypto_unregister_aeads(cvm_aeads, ARRAY_SIZE(cvm_aeads));
}

int cvm_crypto_init(struct cpt_vf *cptvf)
{
	struct pci_dev *pdev = cptvf->pdev;
	int count;

	if (cptvf->vftype == SE_TYPES) {

		spin_lock(&lock);
		count = atomic_read(&se_dev_handle.count);
		se_dev_handle.dev[count++] = cptvf;
		atomic_inc(&se_dev_handle.count);
		spin_unlock(&lock);

		if (atomic_read(&se_dev_handle.count) == 1 &&
		    is_crypto_registered == false) {
			if (cav_register_algs()) {
				dev_err(&pdev->dev,
				   "Error in registering crypto algorithms\n");
				return -EINVAL;
			}
			try_module_get(THIS_MODULE);
			is_crypto_registered = true;
		}
	} else if (cptvf->vftype == AE_TYPES) {

		spin_lock(&lock);
		count = atomic_read(&ae_dev_handle.count);
		ae_dev_handle.dev[count++] = cptvf;
		atomic_inc(&ae_dev_handle.count);
		spin_unlock(&lock);
	} else
		dev_err(&pdev->dev, "Unknown VF type %d\n", cptvf->vftype);

	return 0;
}

void cvm_crypto_exit(void)
{
	spin_lock(&lock);
	if (atomic_dec_and_test(&se_dev_handle.count) &&
	    !is_any_alg_used()) {
		cav_unregister_algs();
		module_put(THIS_MODULE);
		is_crypto_registered = false;
	}
	spin_unlock(&lock);
}
