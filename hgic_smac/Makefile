obj-$(CONFIG_HGICS)    += hgics.o

hgics-objs += core.o
hgics-objs += rx.o
hgics-objs += ap.o
hgics-objs += util.o
hgics-objs += event.o
hgics-objs += procfs.o
hgics-objs += hw.o
hgics-objs += ../utils/utils.o
hgics-objs += ../utils/fwdl.o
hgics-objs += ../utils/fwctrl.o
hgics-objs += ../utils/ota.o
hgics-objs += ../utils/fwinfo.o
hgics-objs += ../utils/iwpriv.o
hgics-objs += ../utils/bluetooth.o

hgics-$(CONFIG_HGIC_SDIO) += ../utils/if_sdio.o
hgics-$(CONFIG_HGIC_USB)  += ../utils/if_usb.o

hgics-$(CONFIG_HGIC_2G) += 11bgn.o
hgics-$(CONFIG_HGIC_AH) += 11ah.o

hgics-$(CONFIG_HGIC_STABR) += stabr.o stabr_arp.o stabr_ip.o

