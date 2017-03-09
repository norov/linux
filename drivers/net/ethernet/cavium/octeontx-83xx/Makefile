#
# Makefile for Cavium's Octeontx ethernet device
#

obj-$(CONFIG_OCTEONTX_FPA_PF) += fpapf.o
obj-$(CONFIG_OCTEONTX_FPA_VF) += fpavf.o
obj-$(CONFIG_OCTEONTX_RST) += rst.o
obj-$(CONFIG_OCTEONTX_SSO_PF) += ssopf.o
obj-$(CONFIG_OCTEONTX_SSOW_PF) += ssowpf.o
obj-$(CONFIG_OCTEONTX) += octeontx.o

fpapf-objs := fpapf_main.o
fpavf-objs := fpavf_main.o
rst-objs := rst_main.o
ssopf-objs := ssopf_main.o octeontx_mbox.o
ssowpf-objs := ssowpf_main.o
octeontx-objs := octeontx_main.o bgx.o
