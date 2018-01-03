# Netfilter-Encryption-System

## Introduction
This is a Data Package Encryption System. It will encrypt the L3 data to prevent the security of communication. This system is based on Netfilter and works in linux kernel. There is also a subsystem working in User Space and communicate with the kernel module by Netlink.

## Install
### Kernel Module
you need to compile it firstly.

```shell
cd Netfilter-Encryption-System-master/
make
```
Then you need to load the module into the linux kernel.

```shell
sudo insmod AESHookMod.ko
```

If you want to remove the kernel module:

```shell
sudo rmmod AESHookMod
```

By the way, you can modify the local IP address and remote IP address at AESHook.h.

### Userspace Module
Just compile and run it after you insert the AESHoookMod.

```shell
cd UserSpaceProgram/
gcc UserSpace.c
./a.out
```