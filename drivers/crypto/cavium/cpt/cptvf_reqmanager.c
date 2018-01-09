/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include "cptvf.h"
#include "request_manager.h"



static void hexdump(void *buf, unsigned int len)
{
	print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,
		       16, 1, (unsigned char *)buf, len, false);
}

static void cpt_dump_req(struct cpt_request_info *req, struct pci_dev *pdev)
{
	int i;

	for (i = 0; i < req->incnt; i++) {
		dev_err(&pdev->dev, "Input Frag %d: %p\n", i,
			req->in[i].vptr);
		hexdump(req->in[i].vptr, req->in[i].size);
	}

	for (i = 0; i < req->outcnt; i++) {
		dev_err(&pdev->dev, "Output Frag %d: %p\n", i,
			req->out[i].vptr);
		hexdump(req->out[i].vptr, req->out[i].size);
	}
}
/**
 * get_free_pending_entry - get free entry from pending queue
 * @param pqinfo: pending_qinfo structure
 * @param qno: queue number
 */
static struct pending_entry *get_free_pending_entry(struct pci_dev *pdev,
						    struct pending_queue *q,
						    int qlen)
{
	struct pending_entry *ent = NULL;

	ent = &q->head[q->rear];
	if (unlikely(ent->busy)) {
		ent = NULL;
		goto no_free_entry;
	}

	q->rear++;
	if (unlikely(q->rear == qlen))
		q->rear = 0;

no_free_entry:
	return ent;
}

static inline u32 modulo_inc(u32 index, u32 length, u32 inc)
{
	if (WARN_ON(inc > length))
		inc = length;

	index += inc;
	if (index >= length)
		index -= length;

	return index;
}

static inline void free_pentry(struct pending_entry *pentry)
{
	pentry->completion_addr = NULL;
	pentry->post_arg = NULL;
	pentry->callback = NULL;
	pentry->callback_arg = NULL;
	pentry->resume_sender = false;
	pentry->busy = false;
}


static int setup_sgio_components(struct cpt_vf *cptvf, struct buf_ptr *list,
				 int buf_count, u8 *buffer)
{
	int ret = 0, i, j;
	int components;
	struct sglist_component *sg_ptr = NULL;
	struct pci_dev *pdev = cptvf->pdev;

	if (unlikely(!list)) {
		dev_err(&pdev->dev, "Input List pointer is NULL\n");
		return -EFAULT;
	}

	for (i = 0; i < buf_count; i++) {
		if (likely(list[i].vptr)) {
			list[i].dma_addr = dma_map_single(&pdev->dev,
							  list[i].vptr,
							  list[i].size,
							  DMA_BIDIRECTIONAL);
			if (unlikely(dma_mapping_error(&pdev->dev,
						       list[i].dma_addr))) {
				dev_err(&pdev->dev, "DMA map kernel buffer failed for component: %d\n",
					i);
				ret = -EIO;
				goto sg_cleanup;
			}
		}
	}

	components = buf_count / 4;
	sg_ptr = (struct sglist_component *)buffer;
	for (i = 0; i < components; i++) {
		sg_ptr->u.s.len0 = cpu_to_be16(list[i * 4 + 0].size);
		sg_ptr->u.s.len1 = cpu_to_be16(list[i * 4 + 1].size);
		sg_ptr->u.s.len2 = cpu_to_be16(list[i * 4 + 2].size);
		sg_ptr->u.s.len3 = cpu_to_be16(list[i * 4 + 3].size);
		sg_ptr->ptr0 = cpu_to_be64(list[i * 4 + 0].dma_addr);
		sg_ptr->ptr1 = cpu_to_be64(list[i * 4 + 1].dma_addr);
		sg_ptr->ptr2 = cpu_to_be64(list[i * 4 + 2].dma_addr);
		sg_ptr->ptr3 = cpu_to_be64(list[i * 4 + 3].dma_addr);
		sg_ptr++;
	}

	components = buf_count % 4;

	switch (components) {
	case 3:
		sg_ptr->u.s.len2 = cpu_to_be16(list[i * 4 + 2].size);
		sg_ptr->ptr2 = cpu_to_be64(list[i * 4 + 2].dma_addr);
		/* Fall through */
	case 2:
		sg_ptr->u.s.len1 = cpu_to_be16(list[i * 4 + 1].size);
		sg_ptr->ptr1 = cpu_to_be64(list[i * 4 + 1].dma_addr);
		/* Fall through */
	case 1:
		sg_ptr->u.s.len0 = cpu_to_be16(list[i * 4 + 0].size);
		sg_ptr->ptr0 = cpu_to_be64(list[i * 4 + 0].dma_addr);
		break;
	default:
		break;
	}

	return ret;

sg_cleanup:
	for (j = 0; j < i; j++) {
		if (list[j].dma_addr) {
			dma_unmap_single(&pdev->dev, list[i].dma_addr,
					 list[i].size, DMA_BIDIRECTIONAL);
		}

		list[j].dma_addr = 0;
	}

	return ret;
}

static inline int setup_sgio_list(struct cpt_vf *cptvf,
				  struct cpt_info_buffer *info,
				  struct cpt_request_info *req)
{
	u16 g_sz_bytes = 0, s_sz_bytes = 0;
	int ret = 0;
	struct pci_dev *pdev = cptvf->pdev;

	if (req->incnt > MAX_SG_IN_CNT || req->outcnt > MAX_SG_OUT_CNT) {
		dev_err(&pdev->dev, "Request SG components are higher than supported\n");
		ret = -EINVAL;
		goto  scatter_gather_clean;
	}

	/* Setup gather (input) components */
	g_sz_bytes = ((req->incnt + 3) / 4) * sizeof(struct sglist_component);
	info->gather_components = kzalloc(g_sz_bytes, GFP_KERNEL);
	if (!info->gather_components) {
		ret = -ENOMEM;
		goto  scatter_gather_clean;
	}

	ret = setup_sgio_components(cptvf, req->in,
				    req->incnt,
				    info->gather_components);
	if (ret) {
		dev_err(&pdev->dev, "Failed to setup gather list\n");
		ret = -EFAULT;
		goto  scatter_gather_clean;
	}

	/* Setup scatter (output) components */
	s_sz_bytes = ((req->outcnt + 3) / 4) * sizeof(struct sglist_component);
	info->scatter_components = kzalloc(s_sz_bytes, GFP_KERNEL);
	if (!info->scatter_components) {
		ret = -ENOMEM;
		goto  scatter_gather_clean;
	}

	ret = setup_sgio_components(cptvf, req->out,
				    req->outcnt,
				    info->scatter_components);
	if (ret) {
		dev_err(&pdev->dev, "Failed to setup gather list\n");
		ret = -EFAULT;
		goto  scatter_gather_clean;
	}

	/* Create and initialize DPTR */
	info->dlen = g_sz_bytes + s_sz_bytes + SG_LIST_HDR_SIZE;
	info->in_buffer = kzalloc(info->dlen, GFP_KERNEL);
	if (!info->in_buffer) {
		ret = -ENOMEM;
		goto  scatter_gather_clean;
	}

	((u16 *)info->in_buffer)[0] = req->outcnt;
	((u16 *)info->in_buffer)[1] = req->incnt;
	((u16 *)info->in_buffer)[2] = 0;
	((u16 *)info->in_buffer)[3] = 0;
	*(u64 *)info->in_buffer = cpu_to_be64p((u64 *)info->in_buffer);

	memcpy(&info->in_buffer[8], info->gather_components,
	       g_sz_bytes);
	memcpy(&info->in_buffer[8 + g_sz_bytes],
	       info->scatter_components, s_sz_bytes);

	info->dptr_baddr = dma_map_single(&pdev->dev,
					  (void *)info->in_buffer,
					  info->dlen,
					  DMA_BIDIRECTIONAL);
	if (dma_mapping_error(&pdev->dev, info->dptr_baddr)) {
		dev_err(&pdev->dev, "Mapping DPTR Failed %d\n", info->dlen);
		ret = -EIO;
		goto  scatter_gather_clean;
	}

	/* Create and initialize RPTR */
	info->out_buffer = kzalloc(COMPLETION_CODE_SIZE, GFP_KERNEL);
	if (!info->out_buffer) {
		ret = -ENOMEM;
		goto scatter_gather_clean;
	}

	*((u64 *)info->out_buffer) = ~((u64)COMPLETION_CODE_INIT);
	info->rptr_baddr = dma_map_single(&pdev->dev,
					  (void *)info->out_buffer,
					  COMPLETION_CODE_SIZE,
					  DMA_BIDIRECTIONAL);
	if (dma_mapping_error(&pdev->dev, info->rptr_baddr)) {
		dev_err(&pdev->dev, "Mapping RPTR Failed %d\n",
			COMPLETION_CODE_SIZE);
		ret = -EIO;
		goto  scatter_gather_clean;
	}

	return 0;

scatter_gather_clean:
	return ret;
}

int send_cpt_command(struct cpt_vf *cptvf, union cpt_inst_s *cmd,
		     u32 qno)
{
	struct pci_dev *pdev = cptvf->pdev;
	struct command_qinfo *qinfo = NULL;
	struct command_queue *queue;
	u8 *ent;
	int ret = 0;

	if (unlikely(qno >= cptvf->nr_queues)) {
		dev_err(&pdev->dev, "Invalid queue (qno: %d, nr_queues: %d)\n",
			qno, cptvf->nr_queues);
		return -EINVAL;
	}

	qinfo = &cptvf->cqinfo;
	queue = &qinfo->queue[qno];
	/* lock commad queue */
	spin_lock(&queue->lock);
	ent = &queue->qhead->head[queue->idx * qinfo->cmd_size];
	memcpy(ent, (void *)cmd, qinfo->cmd_size);

	if (++queue->idx >= queue->qhead->size / 64) {
		struct command_chunk *curr = queue->qhead;

		if (list_is_last(&curr->nextchunk, &queue->chead))
			queue->qhead = queue->base;
		else
			queue->qhead = list_next_entry(queue->qhead, nextchunk);
		queue->idx = 0;
	}
	/* make sure all memory stores are done before ringing doorbell */
	smp_wmb();
	cptvf_write_vq_doorbell(cptvf, 1);
	/* unlock command queue */
	spin_unlock(&queue->lock);

	return ret;
}

void do_request_cleanup(struct cpt_vf *cptvf,
			struct cpt_info_buffer *info)
{
	int i;
	struct pci_dev *pdev = cptvf->pdev;
	struct cpt_request_info *req;

	if (info->dptr_baddr)
		dma_unmap_single(&pdev->dev, info->dptr_baddr,
				 info->dlen, DMA_BIDIRECTIONAL);

	if (info->rptr_baddr)
		dma_unmap_single(&pdev->dev, info->rptr_baddr,
				 COMPLETION_CODE_SIZE, DMA_BIDIRECTIONAL);

	if (info->comp_baddr)
		dma_unmap_single(&pdev->dev, info->comp_baddr,
				 sizeof(union cpt_res_s), DMA_BIDIRECTIONAL);

	if (info->req) {
		req = info->req;
		for (i = 0; i < req->outcnt; i++) {
			if (req->out[i].dma_addr)
				dma_unmap_single(&pdev->dev,
						 req->out[i].dma_addr,
						 req->out[i].size,
						 DMA_BIDIRECTIONAL);
		}

		for (i = 0; i < req->incnt; i++) {
			if (req->in[i].dma_addr)
				dma_unmap_single(&pdev->dev,
						 req->in[i].dma_addr,
						 req->in[i].size,
						 DMA_BIDIRECTIONAL);
		}
	}

	if (info->scatter_components)
		kzfree(info->scatter_components);

	if (info->gather_components)
		kzfree(info->gather_components);

	if (info->out_buffer)
		kzfree(info->out_buffer);

	if (info->in_buffer)
		kzfree(info->in_buffer);

	if (info->completion_addr)
		kzfree((void *)info->completion_addr);

	kzfree(info);
}

void do_post_process(struct cpt_vf *cptvf, struct cpt_info_buffer *info)
{
	struct pci_dev *pdev = cptvf->pdev;

	if (!info) {
		dev_err(&pdev->dev, "incorrect cpt_info_buffer for post processing\n");
		return;
	}

	do_request_cleanup(cptvf, info);
}

static inline void process_pending_queue(struct cpt_vf *cptvf,
					 struct pending_qinfo *pqinfo,
					 int qno)
{
	struct pending_queue *pqueue = &pqinfo->queue[qno];
	struct pending_entry *resume_pentry = NULL;
	struct cpt_info_buffer *cpt_info = NULL;
	struct pci_dev *pdev = cptvf->pdev;
	struct pending_entry *pentry = NULL;
	struct cpt_request_info *req = NULL;
	union cpt_res_s *cpt_status = NULL;
	void (*callback)(int, void *);
	void *callback_arg;
	u32 res_code, resume_index;
	u8 ccode;

	while (1) {
		spin_lock_bh(&pqueue->lock);
		pentry = &pqueue->head[pqueue->front];

		if (WARN_ON(!pentry)) {
			spin_unlock_bh(&pqueue->lock);
			break;
		}

		res_code = -EINVAL;
		if (unlikely(!pentry->busy)) {
			spin_unlock_bh(&pqueue->lock);
			break;
		}

		if (unlikely(!pentry->callback) ||
			unlikely(!pentry->callback_arg)) {
			dev_err(&pdev->dev, "Callback or callback arg NULL\n");
			goto process_pentry;
		}

		cpt_info = (struct cpt_info_buffer *) pentry->post_arg;
		if (unlikely(!cpt_info)) {
			dev_err(&pdev->dev, "Pending entry post arg NULL\n");
			goto process_pentry;
		}

		req = cpt_info->req;
		if (unlikely(!req)) {
			dev_err(&pdev->dev, "Request NULL\n");
			goto process_pentry;
		}

		cpt_status = (union cpt_res_s *) pentry->completion_addr;
		if (unlikely(!cpt_status)) {
			dev_err(&pdev->dev, "Completion address NULL\n");
			goto process_pentry;
		}

		ccode = cpt_status->s.compcode;
		switch (ccode) {
		case CPT_COMP_E_FAULT:
			dev_err(&pdev->dev,
				"Request failed with DMA fault\n");
			cpt_dump_req(req, pdev);
		break;

		case CPT_COMP_E_SWERR:
			dev_err(&pdev->dev,
				"Request failed with Software error\n");
			cpt_dump_req(req, pdev);
		break;

		case CPT_COMP_E_HWERR:
			dev_err(&pdev->dev,
				"Request failed with Hardware error\n");
			cpt_dump_req(req, pdev);
		break;

		case COMPLETION_CODE_INIT:
			/* check for timeout */
			if (time_after_eq(jiffies,
					  (cpt_info->time_in +
					  (CPT_COMMAND_TIMEOUT * HZ)))) {
				dev_err(&pdev->dev, "Request timed out\n");
			} else if ((ccode == (COMPLETION_CODE_INIT)) &&
				   (cpt_info->extra_time <
				    TIME_IN_RESET_COUNT)) {
				cpt_info->time_in = jiffies;
				cpt_info->extra_time++;
				spin_unlock_bh(&pqueue->lock);
				return;
			}
		break;

		case CPT_COMP_E_GOOD:
			res_code = 0;
		break;

		default:
			dev_err(&pdev->dev, "Request returned invalid status\n");
		break;
		}

process_pentry:
		/*
		 * Check if we should inform sending side to resume
		 * We do it CPT_VQ_RESUME_MARGIN elements in advance before
		 * pending queue becomes empty
		 */
		resume_index = modulo_inc(pqueue->front, pqinfo->qlen,
					  CPT_VQ_RESUME_MARGIN);
		resume_pentry = &pqueue->head[resume_index];
		if (resume_pentry &&
		    resume_pentry->resume_sender) {
			resume_pentry->resume_sender = false;
			callback = resume_pentry->callback;
			callback_arg = resume_pentry->callback_arg;

			if (callback && callback_arg) {
				spin_unlock_bh(&pqueue->lock);
				/*
				 * EINPROGRESS is an indication for sending
				 * side that it can resume sending requests
				 */
				callback(-EINPROGRESS, callback_arg);
				spin_lock_bh(&pqueue->lock);
			}
		}

		callback = pentry->callback;
		callback_arg = pentry->callback_arg;
		free_pentry(pentry);

		pqueue->pending_count--;
		pqueue->front = modulo_inc(pqueue->front, pqinfo->qlen, 1);
		spin_unlock_bh(&pqueue->lock);

		if (cpt_info)
			do_request_cleanup(cptvf, cpt_info);
		/*
		 * Call callback after current pending entry has been been
		 * processed we don't do it if the callback pointer or
		 * argument pointer is invalid
		 */
		if (callback && callback_arg)
			callback(res_code, callback_arg);
	}
}

int process_request(struct cpt_vf *cptvf, struct cpt_request_info *req)
{
	struct cptvf_request *cpt_req = NULL;
	struct cpt_info_buffer *info = NULL;
	struct pending_entry *pentry = NULL;
	struct pending_queue *pqueue = NULL;
	struct pci_dev *pdev = cptvf->pdev;
	union cpt_res_s *result = NULL;
	union ctrl_info *ctrl = NULL;
	struct cpt_vq_command vq_cmd;
	union cpt_inst_s cptinst;
	int retry, queue, ret = 0;
	u8 group, resume_sender;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (unlikely(!info)) {
		dev_err(&pdev->dev, "Unable to allocate memory for info_buffer\n");
		return -ENOMEM;
	}

	cpt_req = (struct cptvf_request *)&req->req;
	ctrl = (union ctrl_info *)&req->ctrl;

	info->cptvf = cptvf;
	group = ctrl->s.grp;
	ret = setup_sgio_list(cptvf, info, req);
	if (ret) {
		dev_err(&pdev->dev, "Setting up SG list failed");
		goto request_cleanup;
	}

	cpt_req->dlen = info->dlen;
	/*
	 * Get buffer for union cpt_res_s response
	 * structure and its physical address
	 */
	info->completion_addr = kzalloc(sizeof(union cpt_res_s), GFP_KERNEL);
	if (unlikely(!info->completion_addr)) {
		dev_err(&pdev->dev, "Unable to allocate memory for completion_addr\n");
		return -ENOMEM;
	}

	result = (union cpt_res_s *)info->completion_addr;
	result->s.compcode = COMPLETION_CODE_INIT;
	info->comp_baddr = dma_map_single(&pdev->dev,
					       (void *)info->completion_addr,
					       sizeof(union cpt_res_s),
					       DMA_BIDIRECTIONAL);
	if (dma_mapping_error(&pdev->dev, info->comp_baddr)) {
		dev_err(&pdev->dev, "mapping compptr Failed %lu\n",
			sizeof(union cpt_res_s));
		ret = -EFAULT;
		goto  request_cleanup;
	}

	/* Fill the VQ command */
	vq_cmd.cmd.u64 = 0;
	vq_cmd.cmd.s.opcode = cpu_to_be16(cpt_req->opcode.flags);
	vq_cmd.cmd.s.param1 = cpu_to_be16(cpt_req->param1);
	vq_cmd.cmd.s.param2 = cpu_to_be16(cpt_req->param2);
	vq_cmd.cmd.s.dlen   = cpu_to_be16(cpt_req->dlen);

	/* 64-bit swap for microcode data reads, not needed for addresses*/
	vq_cmd.cmd.u64 = cpu_to_be64(vq_cmd.cmd.u64);
	vq_cmd.dptr = info->dptr_baddr;
	vq_cmd.rptr = info->rptr_baddr;
	vq_cmd.cptr.u64 = 0;
	vq_cmd.cptr.s.grp = group;
	/* Get Pending Entry to submit command */
	/* Always queue 0, because 1 queue per VF */
	queue = 0;
	pqueue = &cptvf->pqinfo.queue[queue];

	spin_lock_bh(&pqueue->lock);
	pentry = get_free_pending_entry(pdev, pqueue, cptvf->pqinfo.qlen);
	retry = CPT_PENTRY_TIMEOUT / CPT_PENTRY_STEP;
	while (unlikely(!pentry) && retry--) {
		spin_unlock_bh(&pqueue->lock);
		udelay(CPT_PENTRY_STEP);

		spin_lock_bh(&pqueue->lock);
		pentry = get_free_pending_entry(pdev, pqueue,
						cptvf->pqinfo.qlen);
	}

	if (!pentry)
		return -ENOSPC;
	/*
	 * Check if we are close to filling in entire pending queue,
	 * if so then tell the sender to stop by returning -EBUSY
	 */
	if (pqueue->pending_count > (cptvf->pqinfo.qlen - CPT_VQ_STOP_MARGIN))
		pentry->resume_sender = true;
	else
		pentry->resume_sender = false;
	resume_sender = pentry->resume_sender;

	pentry->completion_addr = info->completion_addr;
	pentry->post_arg = (void *)info;
	pentry->callback = req->callback;
	pentry->callback_arg = req->callback_arg;
	pentry->busy = true;
	pqueue->pending_count++;

	/* Send CPT command */
	info->pentry = pentry;
	info->time_in = jiffies;
	info->req = req;

	/* Create the CPT_INST_S type command for HW intrepretation */
	cptinst.s.doneint = true;
	cptinst.s.res_addr = (u64)info->comp_baddr;
	cptinst.s.tag = 0;
	cptinst.s.grp = 0;
	cptinst.s.wq_ptr = 0;
	cptinst.s.ei0 = vq_cmd.cmd.u64;
	cptinst.s.ei1 = vq_cmd.dptr;
	cptinst.s.ei2 = vq_cmd.rptr;
	cptinst.s.ei3 = vq_cmd.cptr.u64;

	ret = send_cpt_command(cptvf, &cptinst, queue);
	spin_unlock_bh(&pqueue->lock);
	if (unlikely(ret)) {
		dev_err(&pdev->dev, "Send command failed for AE\n");
		ret = -EFAULT;
		goto request_cleanup;
	}

	ret = resume_sender ? -EBUSY : -EINPROGRESS;
	return ret;

request_cleanup:
	dev_dbg(&pdev->dev, "Failed to submit CPT command\n");
	do_request_cleanup(cptvf, info);

	return ret;
}

void vq_post_process(struct cpt_vf *cptvf, u32 qno)
{
	struct pci_dev *pdev = cptvf->pdev;

	if (unlikely(qno > cptvf->nr_queues)) {
		dev_err(&pdev->dev, "Request for post processing on invalid pending queue: %u\n",
			qno);
		return;
	}

	process_pending_queue(cptvf, &cptvf->pqinfo, qno);
}

int cptvf_do_request(void *vfdev, struct cpt_request_info *req)
{
	struct cpt_vf *cptvf = (struct cpt_vf *)vfdev;
	struct pci_dev *pdev = cptvf->pdev;

	if (!cpt_device_ready(cptvf)) {
		dev_err(&pdev->dev, "CPT Device is not ready");
		return -ENODEV;
	}

	if ((cptvf->vftype == SE_TYPES) && (!req->ctrl.s.se_req)) {
		dev_err(&pdev->dev, "CPTVF-%d of SE TYPE got AE request",
			cptvf->vfid);
		return -EINVAL;
	} else if ((cptvf->vftype == AE_TYPES) && (req->ctrl.s.se_req)) {
		dev_err(&pdev->dev, "CPTVF-%d of AE TYPE got SE request",
			cptvf->vfid);
		return -EINVAL;
	}

	return process_request(cptvf, req);
}
