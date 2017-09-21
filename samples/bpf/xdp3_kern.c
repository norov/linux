/* Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"
#include <linux/slab.h>
#include <net/ip_fib.h>

/* TODO: Try putting the arp field in the trie itself*/
struct trie_value {
	__u8 prefix[4];
	long value;
	int gw;
	int ifindex;
	int metric;
};
union key_4 {
	u32 b32[2];
	u8 b8[8];
};
struct arp_entry {
	int dst;
	long mac;
};
struct direct_map {
	long mac;
	int ifindex;
	struct arp_entry arp;
};

/* Map for trie implementation*/
struct bpf_map_def SEC("maps") lpm_map =
{
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = 8,
	.value_size =
		sizeof(struct trie_value),
	.max_entries = 50,
	.map_flags = BPF_F_NO_PREALLOC,
};

/* Map for  counter*/
struct bpf_map_def SEC("maps") rxcnt =
{
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

/* Map for ARP table*/
struct bpf_map_def SEC("maps") arp_table =
{
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(long),
	.max_entries = 50,
};
/* Map to keep the exact match entries in the route table*/
struct bpf_map_def SEC("maps") exact_match =
{
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct direct_map),
	.max_entries = 50,
};

/**
 * Function to set source and destination mac of the packet
 */
static inline void set_src_dst_mac(void *data, void *src, void *dst)
{
	unsigned short *p      = data;
	unsigned short *dest   = dst;
	unsigned short *source = src;

	p[3] = source[0];
	p[4] = source[1];
	p[5] = source[2];
	p[0] = dest[0];
	p[1] = dest[1];
	p[2] = dest[2];
}

/**
 * Parse IPV4 packet to get SRC, DST IP and protocol
 */
static inline int parse_ipv4(void *data, u64 nh_off, void *data_end,
			     unsigned int *src, unsigned int *dest)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	*src = (unsigned int)iph->saddr;
	*dest = (unsigned int)iph->daddr;
	return iph->protocol;
}

SEC("xdp3")
int xdp_prog3(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = XDP_DROP, forward_to;
	long *value;
	struct trie_value *prefix_value;
	long *dest_mac = NULL, *src_mac = NULL;
	u16 h_proto;
	u64 nh_off;
	u32 ipproto;
	union key_4 key4;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return rc;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == htons(ETH_P_ARP))
		return XDP_PASS;
	if (h_proto == htons(ETH_P_IP)) {
		int src_ip = 0, dest_ip = 0;
		struct direct_map *direct_entry;

		ipproto = parse_ipv4(data, nh_off, data_end, &src_ip, &dest_ip);
		direct_entry = (struct direct_map *)bpf_map_lookup_elem
			(&exact_match, &dest_ip);
		/*check for exact match, this would give a faster lookup*/
		if (direct_entry && direct_entry->mac &&
		    direct_entry->arp.mac) {
			src_mac = &(direct_entry->mac);
			dest_mac = &(direct_entry->arp.mac);
			forward_to = direct_entry->ifindex;
		} else {
			/*Look up in the trie for lpm*/
			// Key for trie
			key4.b32[0] = 32;
			key4.b8[4] = dest_ip % 0x100;
			key4.b8[5] = (dest_ip >> 8) % 0x100;
			key4.b8[6] = (dest_ip >> 16) % 0x100;
			key4.b8[7] = (dest_ip >> 24) % 0x100;
			prefix_value =
				((struct trie_value *)bpf_map_lookup_elem
				 (&lpm_map, &key4));
			if (!prefix_value)
				return XDP_DROP;

			else {
				src_mac = &prefix_value->value;
				if (src_mac) {
					dest_mac = (long *)bpf_map_lookup_elem
						(&arp_table, &dest_ip);
					if (!dest_mac) {
						if (prefix_value->gw) {
							dest_ip = *(unsigned int *)(&(prefix_value->gw));
							dest_mac = (long *)bpf_map_lookup_elem
								(&arp_table, &dest_ip);
						} else
							return XDP_DROP;
					}
					forward_to = prefix_value->ifindex;
				} else
					return XDP_DROP;
			}
		}
	} else
		ipproto = 0;
	if (src_mac && dest_mac) {
		set_src_dst_mac(data, src_mac,
				dest_mac);
		value = bpf_map_lookup_elem
			(&rxcnt, &ipproto);
		if (value)
			*value += 1;
		return  bpf_redirect(
				     forward_to,
				     0);
	}
	return rc;

}

char _license[] SEC("license") = "GPL";
