#!/usr/bin/make -f

NAME  := netlink_kernel

obj-m := $(NAME).o

module-objs += netlink_kernel.o

USER_CFLAGS := $(CFLAGS) -Wall -Wextra

KDIR :=  /lib/modules/$(shell uname -r)/build
PWD  :=  $(shell pwd)

target: module netlink_user

all: clean module netlink_user insmod

module:
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

netlink_user: netlink_user.c
	$(CC) $(USER_CFLAGS) netlink_user.c -o netlink_user

rmmod:
	-rmmod $(NAME)

insmod: $(NAME).ko
	sudo insmod $(NAME).ko

clean: rmmod
	-rmmod ${NAME}
	-rm -rf modules.order Module.symvers .tmp_versions
	-rm -rf $(NAME).ko $(NAME).mod.c $(NAME).mod.o $(NAME).o
	-rm -rf .$(NAME).ko.cmd .$(NAME).mod.o.cmd .$(NAME).o.cmd
	-rm -rf netlink_user

