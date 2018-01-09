/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef __CPTVF_H
#define __CPTVF_H

#include <linux/list.h>
#include "cpt_common.h"

/* Default command queue length */
#define CPT_CMD_QLEN (4*2046)
#define CPT_CMD_QCHUNK_SIZE 1023
#define CPT_VQ_CHUNK_ALIGN  128

/* Default threshold for stopping and resuming sender requests */
#define CPT_VQ_STOP_MARGIN 128
#define CPT_VQ_RESUME_MARGIN 512

/* Default timeout when waiting for free pending entry in us */
#define CPT_PENTRY_TIMEOUT 1000
#define CPT_PENTRY_STEP	50

/* Minimum and maximum values for interrupt coalescing */
#define CPT_COALESC_MIN_TIME_WAIT 0x0
#define CPT_COALESC_MAX_TIME_WAIT ((1<<16)-1)
#define CPT_COALESC_MIN_NUM_WAIT 0x0
#define CPT_COALESC_MAX_NUM_WAIT ((1<<20)-1)

/* Default command timeout in seconds */
#define CPT_COMMAND_TIMEOUT 4
#define CPT_TIMER_THOLD	0x03F
#define CPT_COUNT_HOLD 32
#define CPT_NUM_QS_PER_VF 1
#define CPT_INST_SIZE 64
#define CPT_NEXT_CHUNK_PTR_SIZE 8

#define	CPT_VF_MSIX_VECTORS 2
#define CPT_VF_INTR_MBOX_MASK BIT(0)
#define CPT_VF_INTR_DOVF_MASK BIT(1)
#define CPT_VF_INTR_IRDE_MASK BIT(2)
#define CPT_VF_INTR_NWRP_MASK BIT(3)
#define CPT_VF_INTR_SERR_MASK BIT(4)
#define DMA_DIRECT_DIRECT 0 /* Input DIRECT, Output DIRECT */
#define DMA_GATHER_SCATTER 1
#define FROM_DPTR 1
#define FROM_CTX 0

/**
 * Enumeration cpt_vf_int_vec_e
 *
 * CPT VF MSI-X Vector Enumeration
 * Enumerates the MSI-X interrupt vectors.
 */
enum cpt_vf_int_vec_e {
	CPT_VF_INT_VEC_E_MISC = 0x00,
	CPT_VF_INT_VEC_E_DONE = 0x01
};

struct command_chunk {
	u8 *head;
	u8 *real_vaddr;
	dma_addr_t dma_addr;
	dma_addr_t real_dma_addr;
	u32 size; /* Chunk size, max CPT_INST_CHUNK_MAX_SIZE */
	struct list_head nextchunk;
};

struct command_queue {
	spinlock_t lock; /* command queue lock */
	u32 idx; /* Command queue host write idx */
	u32 nchunks; /* Number of command chunks */
	struct command_chunk *qhead;	/* Command queue head, instructions
					 * are inserted here
					 */
	struct command_chunk *base;
	struct list_head chead;
};

struct command_qinfo {
	u32 cmd_size;
	u32 qchunksize; /* Command queue chunk size */
	struct command_queue queue[CPT_NUM_QS_PER_VF];
};

struct pending_entry {
	u64 *completion_addr; /* Completion address */
	void *post_arg;
	void (*callback)(int, void *); /* Kernel ASYNC request callback */
	void *callback_arg; /* Kernel ASYNC request callback arg */
	u8 resume_sender; /* Notify sender to resume sending requests */
	u8 busy; /* Entry status (free/busy) */
};

struct pending_queue {
	struct pending_entry *head;	/* Head of the queue */
	u32 front; /* Process work from here */
	u32 rear; /* Append new work here */
	u32 pending_count; /* Pending requests count */
	spinlock_t lock; /* Queue lock */
};

struct pending_qinfo {
	u32 nr_queues;	/* Number of queues supported */
	u32 qlen; /* Queue length */
	struct pending_queue queue[CPT_NUM_QS_PER_VF];
};

#define for_each_pending_queue(qinfo, q, i)	\
	for (i = 0, q = &qinfo->queue[i]; i < qinfo->nr_queues; i++, \
	     q = &qinfo->queue[i])

struct cpt_vf {
	u16 flags; /* Flags to hold device status bits */
	u8 vfid; /* Device Index 0...CPT_MAX_VF_NUM */
	u8 vftype; /* VF type of SE_TYPE(2) or AE_TYPE(1) */
	u8 vfgrp; /* VF group (0 - 8) */
	u8 node; /* Operating node: Bits (46:44) in BAR0 address */
	u8 priority; /* VF priority ring: 1-High proirity round
		      * robin ring;0-Low priority round robin ring;
		      */
	struct pci_dev *pdev; /* pci device handle */
	void __iomem *reg_base; /* Register start address */
	void *wqe_info;	/* BH worker info */
	/* MSI-X */
	cpumask_var_t affinity_mask[CPT_VF_MSIX_VECTORS];
	/* Command and Pending queues */
	u32 qsize;
	u32 nr_queues;
	struct command_qinfo cqinfo; /* Command queue information */
	struct pending_qinfo pqinfo; /* Pending queue information */
	/* VF-PF mailbox communication */
	bool pf_acked;
	bool pf_nacked;
};

int cptvf_send_vf_up(struct cpt_vf *cptvf);
int cptvf_send_vf_down(struct cpt_vf *cptvf);
int cptvf_send_vf_to_grp_msg(struct cpt_vf *cptvf);
int cptvf_send_vf_priority_msg(struct cpt_vf *cptvf);
int cptvf_send_vq_size_msg(struct cpt_vf *cptvf);
int cptvf_check_pf_ready(struct cpt_vf *cptvf);
void cptvf_handle_mbox_intr(struct cpt_vf *cptvf);
void cvm_crypto_exit(void);
int cvm_crypto_init(struct cpt_vf *cptvf);
void vq_post_process(struct cpt_vf *cptvf, u32 qno);
void cptvf_write_vq_doorbell(struct cpt_vf *cptvf, u32 val);
#endif /* __CPTVF_H */
