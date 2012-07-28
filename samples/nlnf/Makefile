#!/usr/bin/make -f

NAME       := nlnf

MODULES    := nlnf
MODULES_KO := nlnf.ko
obj-m      := nlnf.o

KDIR       :=  /lib/modules/$(shell uname -r)/build
PWD        :=  $(shell pwd)

all: clean module insmod run

module: dump
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

rmmod:
	-sudo rmmod $(MODULES)

insmod: module
	sudo insmod $(MODULES_KO)

dump: nlnf_dump.c
	$(CC) -Wall -Wextra nlnf_dump.c -o nlnf_dump

run: dump
	./nlnf_dump

clean: rmmod
	-rm -rf .*.o.cmd .*.ko.cmd *.mod.c
	-rm -rf *.o *.ko
	-rm -rf modules.order Module.symvers .tmp_versions
	-rm -rf nlnf_dump

