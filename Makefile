CONFIG_MODULE_SIG=n
# AES Hook Makefile
ifneq ($(KERNELRELEASE),)
	obj-m := AESHookMod.o
	AESHookMod-objs := AESHook.o AESEncryptor.o netlink_com.o
else
	PWD := $(shell pwd)
	KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	rm -f .built-in.o.cmd .AESHook.o.cmd .netlink_com.o.cmd .AESHook*
	rm -f *.o *.o.cmd *.ko *.mod.c *.symvers *.order
	rm -rf .tmp_versions
endif
