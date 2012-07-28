#!/usr/bin/make -f

MODULES    := netfilter_demo
MODULES_KO := netfilter_demo.ko
obj-m      := netfilter_demo.o

KDIR       :=  /lib/modules/$(shell uname -r)/build
PWD        :=  $(shell pwd)

module:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

all: clean module insmod

rmmod:
	-rmmod $(MODULES)

insmod: $(NAME).ko
	sudo insmod $(MODULES_KO)

clean: rmmod
	-rm -rf .*.o.cmd .*.ko.cmd *.mod.c
	-rm -rf *.o *.ko
	-rm -rf modules.order Module.symvers .tmp_versions

