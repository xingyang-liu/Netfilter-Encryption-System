
#include "netlink_com.h"

static int err;
static int flag = 0;
int pid = 101;
struct sock *nl_sk = NULL;

#define MAX_MSGSIZE 1024

/**
  * @brief  Send message to User Space process
  * @param  message
  * @retval null
  */
void sendnlmsg(char *message)
{
    struct sk_buff *skb_1;
    struct nlmsghdr *nlh;
    int len = NLMSG_SPACE(MAX_MSGSIZE);
    int slen = 0;
    if(pid == 101) return;
    if(!message || !nl_sk)
    {
        return ;
    }

    skb_1 = nlmsg_new(len,GFP_ATOMIC);

    if(!skb_1)
    {
        printk(KERN_ERR "my_net_link:alloc_skb_1 error\n");
    }

    slen = strlen(message);
    nlh = nlmsg_put(skb_1,0,0,0,MAX_MSGSIZE,0);

    printk(KERN_INFO "pid: %d\n", pid);
    memcpy(nlmsg_data(nlh),message,slen+1);
    printk(KERN_INFO "pid: \n", pid);

    netlink_unicast(nl_sk, skb_1, pid, MSG_DONTWAIT);
}

/**
  * @brief  Recieve message from User Space process and respond to it
  * @param  message
  * @retval null
  */
void crypto_netlink_rcv(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    char str[100];
    struct completion cmpl;

    skb = skb_get (__skb);
    char msg[20] = "I am from kernel!\0";

    if(skb->len >= NLMSG_SPACE(0))
    {
        nlh = nlmsg_hdr(skb);

        memcpy(str, NLMSG_DATA(nlh), sizeof(str));
        printk("Message received:%s\n",str);
        pid = nlh->nlmsg_pid;
        flag = 1;
    }
}

/**
  * @brief  Initialize netlink
  * @param  null
  * @retval success or fail
  */
int netlink_init(void)
{
  	struct netlink_kernel_cfg cfg = {
		.input = crypto_netlink_rcv,
	};

    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);

    if(!nl_sk){//create netlink socket error
        printk(KERN_INFO "NETLINK socket error.\n");
        return -1;
    }

    printk(KERN_INFO "NETLINK socket on.\n");
    return 0;
}  

/**
  * @brief  Unload netlink
  * @param  null
  * @retval success or fail
  */
void netlink_fini(void)
{  
    if(nl_sk != NULL){  
        netlink_kernel_release(nl_sk);  
    }  
    printk(KERN_INFO "NETLINK subsys exited\n");  
}  
