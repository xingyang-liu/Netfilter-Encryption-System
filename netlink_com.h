#ifndef __NETLINK_COM_H__
#define __NETLINK_COM_H__

#include <linux/timer.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/init.h>
#include <net/sock.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>


#define NETLINK_TEST 25/* customized netlink */

struct packet_info
{
  __u32 src;
  __u32 dest;
};

extern int pid; // user process pid
extern struct sock *nl_sk;

int netlink_init(void);
void netlink_fini(void);
void sendnlmsg(char *message);

#endif