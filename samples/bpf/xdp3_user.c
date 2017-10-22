/* Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/bpf.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "bpf_load.h"
#include "libbpf.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

int sock, sock_arp, flags = 0;
char buf[8192];
static int total_ifindex;
char **index_list;

/*
 * This function is part of tools/testing/selftests/bpf/bpf-util.h
 * bpf self tests folder is not available in this version of linux kernel
 * so for time being we define the required function locally.
 */
static inline unsigned int bpf_num_possible_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/possible";
	unsigned int start, end, possible_cpus = 0;
	char buff[128];
	FILE *fp;

	fp = fopen(fcpu, "r");
	if (!fp) {
		printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
		exit(1);
	}

	while (fgets(buff, sizeof(buff), fp)) {
		if (sscanf(buff, "%u-%u", &start, &end) == 2) {
			possible_cpus = start == 0 ? end + 1 : 0;
			break;
		}
	}
	fclose(fp);
	if (!possible_cpus) {
		printf("Failed to retrieve # possible CPUs!\n");
		exit(1);
	}

	return possible_cpus;
}

static int set_link_xdp_fd(int ifindex, int fd, __u32 flags)
{
	struct sockaddr_nl sa;
	int sock, seq = 0, len, ret = -1;
	char buf[4096];
	struct nlattr *nla, *nla_xdp;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req;
	struct nlmsghdr *nh;
	struct nlmsgerr *err;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_SETLINK;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index = ifindex;

	/* started nested attribute for XDP */
	nla = (struct nlattr *)(((char *)&req)
				+ NLMSG_ALIGN(req.nh.nlmsg_len));
	nla->nla_type = NLA_F_NESTED | 43/*IFLA_XDP*/;
	nla->nla_len = NLA_HDRLEN;

	/* add XDP fd */
	nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
	nla_xdp->nla_type = 1/*IFLA_XDP_FD*/;
	nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
	memcpy((char *)nla_xdp + NLA_HDRLEN, &fd, sizeof(fd));
	nla->nla_len += nla_xdp->nla_len;

	/* if user passed in any flags, add those too */
	if (flags) {
		nla_xdp = (struct nlattr *)((char *)nla + nla->nla_len);
		nla_xdp->nla_type = 3/*IFLA_XDP_FLAGS*/;
		nla_xdp->nla_len = NLA_HDRLEN + sizeof(flags);
		memcpy((char *)nla_xdp + NLA_HDRLEN, &flags, sizeof(flags));
		nla->nla_len += nla_xdp->nla_len;
	}

	req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		printf("send to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		printf("recv from netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
	     nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_pid != getpid()) {
			printf("Wrong pid %d, expected %d\n",
			       nh->nlmsg_pid, getpid());
			goto cleanup;
		}
		if (nh->nlmsg_seq != seq) {
			printf("Wrong seq %d, expected %d\n",
			       nh->nlmsg_seq, seq);
			goto cleanup;
		}
		switch (nh->nlmsg_type) {
		case NLMSG_ERROR:
			err = (struct nlmsgerr *)NLMSG_DATA(nh);
			if (!err->error)
				continue;
			printf("nlmsg error %s\n", strerror(-err->error));
			goto cleanup;
		case NLMSG_DONE:
			break;
		}
	}

	ret = 0;

cleanup:
	close(sock);
	return ret;
}

static void int_exit(int sig)
{
	int i = 0, index;

	for (i = 0; i < total_ifindex; i++) {
		index = strtoul(index_list[i], NULL, 0);
		set_link_xdp_fd(index, -1, flags);
		printf("detaching from%d\n", index);
	}
	exit(0);
}

static void close_and_exit(int sig)
{
	int i = 0, index;

	close(sock);
	close(sock_arp);

	for (i = 0; i < total_ifindex; i++) {
		index = strtoul(index_list[i], NULL, 0);
		set_link_xdp_fd(index, -1, flags);
		printf("Detaching from%d\n", index);
	}
	exit(0);
}

/* Get the mac address of the interface given interface name */
static long *getmac(char *iface)
{
	int fd;
	struct ifreq ifr;
	long *mac = NULL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	mac = (long *)ifr.ifr_hwaddr.sa_data;
	close(fd);
	return mac;
}

static int recv_msg(struct sockaddr_nl sock_addr, int sock)
{
	char *buf_ptr;
	struct nlmsghdr *nh;
	int len, nll = 0;

	buf_ptr = buf;
	while (1) {
		len = recv(sock, buf_ptr, sizeof(buf) - nll, 0);
		if (len < 0)
			return len;

		nh = (struct nlmsghdr *)buf_ptr;

		if (nh->nlmsg_type == NLMSG_DONE)
			break;
		buf_ptr += len;
		nll += len;
		if ((sock_addr.nl_groups & RTMGRP_NEIGH) == RTMGRP_NEIGH)
			break;

		if ((sock_addr.nl_groups & RTMGRP_IPV4_ROUTE) ==
		    RTMGRP_IPV4_ROUTE)
			break;
	}
	return nll;
}

/* Function to parse the route entry returned by netlink
 * Updates the route entry related map entries
 */
static void read_route(struct nlmsghdr *nh, int nll)
{
	struct route_table {
		int dst, gw, dst_len, iface, metric;
		long *mac;
		char iface_name[IFNAMSIZ];
	} route;
	struct arp_table {
		int dst;
		long mac;
	};

	struct direct_map {
		long mac;
		int ifindex;
		struct arp_table arp;
	} direct_entry;
	int i;
	int rtm_family;
	struct bpf_lpm_trie_key *prefix_key;
	char dsts[24], gws[24], ifs[16], dsts_len[24], metrics[24];
	struct rtmsg *rt_msg;
	int rtl;
	struct rtattr *rt_attr;

	if (nh->nlmsg_type == RTM_DELROUTE)
		printf("DELETING Route entry\n");
	else if (nh->nlmsg_type == RTM_GETROUTE)
		printf("READING Route entry\n");
	else if (nh->nlmsg_type == RTM_NEWROUTE)
		printf("NEW Route entry\n");
	else
		printf("%d\n", nh->nlmsg_type);

	bzero(&route, sizeof(route));
	printf("Destination\tGateway\t\tGenmask\tMetric\tIface\n");
	for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
		rt_msg = (struct rtmsg *)NLMSG_DATA(nh);
		rtm_family = rt_msg->rtm_family;
		if (rtm_family == AF_INET)
			if (rt_msg->rtm_table != RT_TABLE_MAIN)
				continue;
		rt_attr = (struct rtattr *)RTM_RTA(rt_msg);
		rtl = RTM_PAYLOAD(nh);

		for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {
			switch (rt_attr->rta_type) {
			case NDA_DST:
				sprintf(dsts, "%d",
					*((int *)RTA_DATA(rt_attr)));
				break;
			case RTA_GATEWAY:
				sprintf(gws, "%d", *((int *)RTA_DATA(rt_attr)));
				break;
			case RTA_OIF:
				sprintf(ifs, "%d", *((int *)RTA_DATA(rt_attr)));
				break;
			case RTA_METRICS:
				sprintf(metrics, "%d",
					*((int *)RTA_DATA(rt_attr)));
			default:
				break;
			}

		}
		sprintf(dsts_len, "%d", rt_msg->rtm_dst_len);

		route.dst = atoi(dsts);
		route.dst_len = atoi(dsts_len);
		route.gw = atoi(gws);
		route.iface = atoi(ifs);
		route.metric = atoi(metrics);
		if_indextoname(route.iface, route.iface_name);
		route.mac = getmac(route.iface_name);
		printf("%x\t\t%x\t\t%d\t%d\t%d\n", route.dst, route.gw,
		       route.dst_len, route.metric, route.iface);
		if (rtm_family == AF_INET) {
			struct trie_value {
				__u8 prefix[4];
				long value;
				int gw;
				int ifindex;
				int metric;
			} *prefix_value;

			prefix_key = alloca(sizeof(*prefix_key) + 3);
			prefix_value = alloca(sizeof(*prefix_value));

			prefix_key->prefixlen = 32;
			prefix_key->prefixlen = route.dst_len;
			direct_entry.mac = *(route.mac) & 0xffffffffffff;
			direct_entry.ifindex = route.iface;
			direct_entry.arp.mac = 0;
			direct_entry.arp.dst = 0;
			if (route.dst_len == 32) {

				if (nh->nlmsg_type == RTM_DELROUTE)
					assert(bpf_delete_elem(
								   map_fd[3],
								   &route.dst)
					       == 0);
				else {
					if (bpf_lookup_elem(map_fd[2],
							&(route.dst),
							&direct_entry.arp.mac)
					    == 0)
						direct_entry.arp.dst = route.dst;

					assert(bpf_update_elem(map_fd[3],
								  &(route.dst),
								  &direct_entry,
								  0)
					       == 0);

				}

			}
			for (i = 0; i < 4; i++)
				prefix_key->data[i] =
					(route.dst >> i * 8) % 0x100;
			if (bpf_lookup_elem(map_fd[0], prefix_key,
						prefix_value) < 0) {
				for (i = 0; i < 4; i++)
					prefix_value->prefix[i] =
						prefix_key->data[i];
				prefix_value->value =
					*(route.mac) & 0xffffffffffff;
				prefix_value->ifindex = route.iface;
				prefix_value->gw = route.gw;
				prefix_value->metric = route.metric;

				assert(bpf_update_elem(map_fd[0],
							   prefix_key,
							   prefix_value, 0)
				       == 0);
			} else {
				if (nh->nlmsg_type == RTM_DELROUTE) {
					printf("deleting entry\n");
					/* Delete from triemap.trie map
					 * deletion not implemented
					 */
				} else if (prefix_key->data[0] ==
					   prefix_value->prefix[0] &&
					   prefix_key->data[1] ==
					   prefix_value->prefix[1] &&
					   prefix_key->data[2] ==
					   prefix_value->prefix[2] &&
					   prefix_key->data[3] ==
					   prefix_value->prefix[3] &&
					   route.metric >= prefix_value->metric)
					continue;
				else {
					for (i = 0; i < 4; i++)
						prefix_value->prefix[i] =
							prefix_key->data[i];
					prefix_value->value =
						*(route.mac) & 0xffffffffffff;
					prefix_value->ifindex = route.iface;
					prefix_value->gw = route.gw;
					prefix_value->metric = route.metric;
					assert(bpf_update_elem(
								   map_fd[0],
								   prefix_key,
								   prefix_value,
								   0)
					       == 0);
				}
			}
		}
		bzero(&route, sizeof(route));
		bzero(dsts, sizeof(dsts));
		bzero(dsts_len, sizeof(dsts_len));
		bzero(gws, sizeof(gws));
		bzero(ifs, sizeof(ifs));
		bzero(&route, sizeof(route));
	}
}

/* Function to read the existing route table  when the process is launched*/
static int get_route_table(int rtm_family)
{
	struct {
		struct nlmsghdr nl;
		struct rtmsg rt;
		char buf[8192];
	} req;

	int sock, seq = 0;
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct iovec iov;
	int ret = 0;
	struct nlmsghdr *nh;
	int nll;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}
	bzero(&sa, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	}
	bzero(&req, sizeof(req));
	req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nl.nlmsg_type = RTM_GETROUTE;

	req.rt.rtm_family = rtm_family;
	req.rt.rtm_table = RT_TABLE_MAIN;
	req.nl.nlmsg_pid = 0;
	req.nl.nlmsg_seq = ++seq;
	bzero(&msg, sizeof(msg));
	iov.iov_base = (void *)&req.nl;
	iov.iov_len = req.nl.nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		printf("send to netlink: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	}
	bzero(buf, sizeof(buf));
	nll = recv_msg(sa, sock);
	if (nll < 0) {
		printf("recv from netlink: %s\n", strerror(nll));
		ret = -1;
		goto cleanup;
	}
	nh = (struct nlmsghdr *)buf;
	read_route(nh, nll);
cleanup:
	close(sock);
	return ret;
}

/* Function to parse the arp entry returned by netlink
 * Updates the arp entry related map entries
 */
static void read_arp(struct nlmsghdr *nh, int nll)
{
	struct arp_table {
		int dst;
		long mac;
	} arp_entry;
	struct direct_map {
		long mac;
		int ifindex;
		struct arp_table arp;
	} direct_entry;

	char dsts[24], mac[24];
	struct ndmsg *rt_msg;
	int rtl, i = 0, ndm_family;
	struct rtattr *rt_attr;

	if (nh->nlmsg_type == RTM_GETNEIGH)
		printf("READING arp entry\n");
	printf("Address\tHwAddress\n");
	for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
		i++;
		rt_msg = (struct ndmsg *)NLMSG_DATA(nh);
		rt_attr = (struct rtattr *)RTM_RTA(rt_msg);
		ndm_family = rt_msg->ndm_family;
		rtl = RTM_PAYLOAD(nh);
		for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {
			switch (rt_attr->rta_type) {
			case NDA_DST:
				sprintf(dsts, "%d",
					*((int *)RTA_DATA(rt_attr)));
				break;
			case NDA_LLADDR:
				sprintf(mac, "%ld",
					*((long *)RTA_DATA(rt_attr)));
				break;
			default:
				break;
			}
		}
		arp_entry.dst = atoi(dsts);
		arp_entry.mac = atol(mac);
		printf("%x\t\t%lx\n", arp_entry.dst, arp_entry.mac);
		if (ndm_family == AF_INET) {

			if (bpf_lookup_elem(map_fd[3], &(arp_entry.dst),
						&direct_entry) == 0) {
				if (nh->nlmsg_type == RTM_DELNEIGH) {
					direct_entry.arp.dst = 0;
					direct_entry.arp.mac = 0;
				} else if (nh->nlmsg_type == RTM_NEWNEIGH) {
					direct_entry.arp.dst = arp_entry.dst;
					direct_entry.arp.mac = arp_entry.mac;
				}
				assert(bpf_update_elem(map_fd[3],
							   &(arp_entry.dst),
							   &direct_entry, 0)
				       == 0);
				bzero(&direct_entry, sizeof(direct_entry));
			}
			if (nh->nlmsg_type == RTM_DELNEIGH) {

				assert(bpf_delete_elem(map_fd[2],
							   &(arp_entry.dst))
				       == 0);
			} else if (nh->nlmsg_type == RTM_NEWNEIGH) {

				assert(bpf_update_elem(map_fd[2],
							   &(arp_entry.dst),
							   &(arp_entry.mac), 0)
				       == 0);
			}
		}
		bzero(&arp_entry, sizeof(arp_entry));
		bzero(dsts, sizeof(dsts));
	}
}

/* Function to read the existing arp table  when the process is launched*/
static int get_arp_table(int rtm_family)
{
	struct {
		struct nlmsghdr nl;
		struct ndmsg rt;
		char buf[8192];
	} req;

	int sock, seq = 0;
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct iovec iov;
	int ret = 0;
	struct nlmsghdr *nh;
	int nll;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}
	bzero(&sa, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	}
	bzero(&req, sizeof(req));
	req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nl.nlmsg_type = RTM_GETNEIGH;
	req.rt.ndm_state = NUD_REACHABLE;
	req.rt.ndm_family = rtm_family;
	req.nl.nlmsg_pid = 0;
	req.nl.nlmsg_seq = ++seq;
	bzero(&msg, sizeof(msg));
	iov.iov_base = (void *)&req.nl;
	iov.iov_len = req.nl.nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		printf("send to netlink: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	}
	bzero(buf, sizeof(buf));
	nll = recv_msg(sa, sock);
	if (nll < 0) {
		printf("recv from netlink: %s\n", strerror(nll));
		ret = -1;
		goto cleanup;
	}
	nh = (struct nlmsghdr *)buf;
	read_arp(nh, nll);
cleanup:
	close(sock);
	return ret;
}
/* Function to keep track and update changes in route and arp table
 * Give regular statistics of packets forwarded
 */
static int monitor_route(void)
{
	struct sockaddr_nl la, lr;
	struct nlmsghdr *nh;
	int nll, ret = 0;
	const unsigned int nr_keys = 256;
	int interval = 5;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus], prev[nr_keys][nr_cpus];
	__u32 key;
	int i;
	struct pollfd fds_route, fds_arp;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);
	bzero(&lr, sizeof(lr));
	lr.nl_family = AF_NETLINK;
	lr.nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_NOTIFY;
	if (bind(sock, (struct sockaddr *)&lr, sizeof(lr)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	}
	fds_route.fd = sock;
	fds_route.events = POLL_IN;

	sock_arp = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock_arp < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}

	fcntl(sock_arp, F_SETFL, O_NONBLOCK);
	bzero(&la, sizeof(la));
	la.nl_family = AF_NETLINK;
	la.nl_groups = RTMGRP_NEIGH | RTMGRP_NOTIFY;
	if (bind(sock_arp, (struct sockaddr *)&la, sizeof(la)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	}
	fds_arp.fd = sock_arp;
	fds_arp.events = POLL_IN;

	memset(prev, 0, sizeof(prev));
	do {
		signal(SIGINT, close_and_exit);
		signal(SIGTERM, close_and_exit);

		sleep(interval);
		for (key = 0; key < nr_keys; key++) {
			__u64 sum = 0;

			assert(bpf_lookup_elem(map_fd[1], &key, values)
			       == 0);
			for (i = 0; i < nr_cpus; i++)
				sum += (values[i] - prev[key][i]);
			if (sum)
				printf("proto %u: %10llu pkt/s\n",
				       key, sum / interval);
			memcpy(prev[key], values, sizeof(values));
		}

		bzero(buf, sizeof(buf));
		if (poll(&fds_route, 1, 3) == POLL_IN) {

			nll = recv_msg(lr, sock);
			if (nll < 0) {
				printf("recv from netlink: %s\n",
				       strerror(nll));
				ret = -1;
				goto cleanup;
			}

			nh = (struct nlmsghdr *)buf;
			printf("Routing table updated.\n");
			read_route(nh, nll);
		}
		bzero(buf, sizeof(buf));
		if (poll(&fds_arp, 1, 3) == POLL_IN) {

			nll = recv_msg(la, sock_arp);
			if (nll < 0) {
				printf("recv from netlink: %s\n",
				       strerror(nll));
				ret = -1;
				goto cleanup;
			}

			nh = (struct nlmsghdr *)buf;
			read_arp(nh, nll);
		}

	} while (1);
cleanup:
	close(sock);
	return ret;
}
int main(int ac, char **argv)
{
	char filename[256];
	int i = 1, index;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	printf("Entering user program\n");
	if (ac < 2) {
		printf("usage: %s [-S] IFINDEX\n", argv[0]);
		return 1;
	}
	if (!strcmp(argv[1], "-S")) {
		flags = XDP_FLAGS_SKB_MODE;
		total_ifindex = ac-2;
		index_list = (argv+2);
	} else {
		flags = 0;
		total_ifindex = ac-1;
		index_list = (argv+1);
	}
printf("Loading bpf program\n");
	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}
	printf("\n**************loading bpf file*********************\n\n\n");
	if (!prog_fd[0]) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return 1;
	}

	for (i = 0; i < total_ifindex; i++) {
		index = strtoul(index_list[i], NULL, 0);
		if (set_link_xdp_fd(index, prog_fd[0], flags) < 0) {
			printf("link set xdp fd failed\n");
			return 1;
		}
		printf("Attached to %d\n", index);
	}
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	printf("*******************ROUTE TABLE*************************\n\n\n");
	get_route_table(AF_INET);
	printf("*******************ARP TABLE***************************\n\n\n");
	get_arp_table(AF_INET);
	if (monitor_route() < 0) {
		printf("Error in receiving route update");
		return 1;
	}

	return 0;
}
