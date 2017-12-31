/*
 * @Author: Xingyang Liu
 * @TimeStamp: 20171231SUN1339
 * @Comment: AES Hook on NF_LOCAL_IN & NF_LOCAL_OUT
 */
/* Includes ------------------------------------------------------------------*/
//Moudle reference
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>
//Network Reference
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/inet.h>
//Get Time
#include <linux/timer.h>
#include <linux/timer.h> 
#include <linux/timex.h> 
#include <linux/rtc.h>
//User Reference
#include "AESHook.h"
#include "AESEncryptor.h"//kernel aes_cbc_256
#include "netlink_com.h"//kernel Connector driver
#include <linux/string.h>
#include <linux/kmod.h>

/* Module Definition ---------------------------------------------------------*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xingyang Liu");

/* Private function prototypes -----------------------------------------------*/
static struct nf_hook_ops nfhk_local_in;
static struct nf_hook_ops nfhk_local_out;
extern int pid;
extern struct sock *nl_sk;;

/*Constant Value*/
#define RECEIVE 0x1
#define SEND 0x0

static void display_packet(char *memory, int start, int len, int is_enc, int is_recv){
	u8 tmp[16];
	//int tmp[4];
	int offset = start;
	int i, k;
	printk(KERN_INFO "%s\t%s\tLength: %d\n", (is_enc?"Encrypted":"UnEncrypted"), (is_recv?"Received":"Sent"), len);
	char* msg;
	struct timex  txc; 
	struct rtc_time tm; 

	do_gettimeofday(&(txc.time)); 
	rtc_time_to_tm(txc.time.tv_sec,&tm); 
	printk(KERN_INFO "UTC time :%d-%d-%d %d:%d:%d", tm.tm_year+1900, tm.tm_mon, tm.tm_mday, tm.tm_hour,tm.tm_min,tm.tm_sec);
	msg = kmalloc(100*sizeof(char), GFP_KERNEL);
	sprintf(msg, "UTC time :%d-%d-%d %d:%d:%d", tm.tm_year+1900, tm.tm_mon, tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec);
	sendnlmsg(msg);
	kfree(msg);

	msg = kmalloc(100*sizeof(char), GFP_KERNEL);
	sprintf(msg, "%s\t%s\tLength: %d\n", (is_enc?"Encrypted":"UnEncrypted"), (is_recv?"Received":"Sent"), len);
	sendnlmsg(msg);
	kfree(msg);
	do {
		msg = kmalloc(100*sizeof(char), GFP_KERNEL);
		if (len < 16) {
			for (i=len; i<16; i++)
				tmp[i] = 0;
		}
		k = (len < 16) ? len : 16;
		memcpy(tmp, memory+offset, k);
		
		printk(KERN_INFO "[+] %02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x\n",
				tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7],
				tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13], tmp[14], tmp[15]);

		sprintf(msg, "[+] %02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x",
				tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7],
				tmp[8], tmp[9], tmp[10], tmp[11], tmp[12], tmp[13], tmp[14], tmp[15]);

		sendnlmsg(msg);
		
		//printk(KERN_INFO "[+] %08x_%08x_%08x_%08x\n", tmp[0], tmp[1], tmp[2], tmp[3]);
		offset += 16;
		len -= 16;
		kfree(msg);
	} while (len > 0);
	sendnlmsg("\n");
}

/**
  * @brief  
  * @param  
  * @retval
  */
char padding_fill(int data_len) {
	char tmp_len = 0;

	tmp_len = data_len % 16;
	tmp_len = (tmp_len==0?0:16-tmp_len);

	return tmp_len;
}

/**
  * @brief  
  * @param  
  * @retval 
  */
char padding_check(char * data, int len)
{
	char ex;
	int flag = 0, i = 0;

	ex = data[len - 1];
	if (ex < 1 || ex > 15)
		return 0;

	for (i = 1; i < ex; i++)
	{
		flag += data[len - i - 1];
	}

	if(flag==0)
		return ex;
	else
		return 0;
}

/**
  * @brief  
  * @param  
  * @retval uint16_t, the length of '*data' pointer(in bit)
  */
unsigned int nf_hookfn_in(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	__u16 data_len;
	char padding_len;
	char* data_origin;
	struct iphdr *iph = NULL;

	if(skb == NULL) {
		printk("%s\n", "*skb is NULL");
		return NF_ACCEPT;
	}

	if (0 != skb_linearize(skb)) {
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if (iph == NULL) {
		printk("%s\n", "*iph is NULL");
		return NF_ACCEPT;
	}

	if((iph->saddr != in_aton(REMOTE_IP)) || iph->daddr != in_aton(LOCAL_IP)) {
		return NF_ACCEPT;
	}

	//Get Original L3 payload, Extract data from payload
	data_len = ntohs(iph->tot_len)  - iph->ihl*4;
	data_origin = skb_network_header(skb) + iph->ihl*4;
	printk(KERN_INFO "This is receiving encrypted package, data length: %d\n", data_len);
	
	/* Decryption function */
	display_packet((char *)skb->data, 0, ntohs(iph->tot_len), ENCRYPTION, RECEIVE);
	aes_crypto_cipher(data_origin, data_len, DECRYPTION);

	printk(KERN_INFO "After Decryption\n");
	display_packet((char *)skb->data, 0, ntohs(iph->tot_len), ENCRYPTION, RECEIVE);

	//re-checksum
	padding_len = padding_check(data_origin, data_len);
	
	iph->tot_len = htons(ntohs(iph->tot_len) - padding_len);//remove padding from length
	skb_trim(skb, ntohs(iph->tot_len));
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);//re-checksum for IP
	printk(KERN_INFO "This is receiving unencrypted package, length: %d\n", ntohs(iph->tot_len));
	display_packet((char *)skb->data, 0, ntohs(iph->tot_len), DECRYPTION, RECEIVE);
	printk(KERN_INFO "\n");

	return NF_ACCEPT;
}

/**
  * @brief  
  * @param  
  * @retval uint16_t, the length of '*data' pointer(in bit)
  */
unsigned int nf_hookfn_out(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	__u16 data_len;
	int nfrags;
	char padding_len;
	char *data = NULL;
	char* data_origin;
	struct iphdr *iph = NULL;
	struct sk_buff *trailer;
	struct tcphdr *tcph;
	struct udphdr *udph;

	if(skb == NULL) {
		printk("%s\n", "*skb is NULL");
		return NF_ACCEPT;
	}

	if (0 != skb_linearize(skb)) {
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if (iph == NULL) {
		printk("%s\n", "*iph is NULL");
		return NF_ACCEPT;
	}

	if((iph->saddr != in_aton(LOCAL_IP)) || iph->daddr != in_aton(REMOTE_IP)) {
		return NF_ACCEPT;
	}

	//pre padding allocate
	data_len = ntohs(iph->tot_len) - iph->ihl*4;
	padding_len = padding_fill(data_len);
	data = kmalloc((data_len+padding_len) * sizeof(char), GFP_KERNEL);
	memset(data, 0, (data_len + padding_len));//padding with 0
	data[data_len + padding_len - 1] = padding_len;//ANSI X.923 format

	// Calculate checksum in TCP/UDP
	if(skb->ip_summed != CHECKSUM_NONE){
		if(iph->protocol == IPPROTO_TCP){
			tcph = tcp_hdr(skb);
            tcph->check = 0;
            skb->csum = csum_partial(tcph, data_len, 0);
            tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, data_len, iph->protocol, 
            								skb->csum);
		}
		if(iph->protocol == IPPROTO_UDP){
			udph = udp_hdr(skb);
            udph->check = 0;
            skb->csum = csum_partial(udph, data_len, 0);
            udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, data_len, iph->protocol, 
            								skb->csum);
		}
	}
	skb->ip_summed = CHECKSUM_NONE;

	//Get Original L3 payload
	data_origin = skb_network_header(skb) + iph->ihl*4;
	printk(KERN_INFO "This is sending unencrypted package, length: %d\n", ntohs(iph->tot_len));
	display_packet((char *)skb->data, 0, ntohs(iph->tot_len), DECRYPTION, SEND);
	memcpy(data, data_origin, data_len);

	printk(KERN_INFO "DATA length: %d\n", data_len+padding_len);
	printk(KERN_INFO "Before Encryption in DATA\n");
	display_packet(data, 0, data_len+padding_len, DECRYPTION, SEND);

	/* Encryption function */
	aes_crypto_cipher(data, (data_len+padding_len), ENCRYPTION);

	printk(KERN_INFO "After Encryption in DATA\n");
	display_packet(data, 0, data_len+padding_len, ENCRYPTION, SEND);

	/* substitute original data */
	printk(KERN_INFO "Before skb_cow_data: data points %p\n",skb->data);
	nfrags = skb_cow_data(skb, padding_len, &trailer);
	if(nfrags < 0){
		printk(KERN_INFO "nfrags allocate fail");
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	data_origin = skb_network_header(skb) + iph->ihl*4;

	skb_put(skb, padding_len);//forward from tail
	printk(KERN_INFO "After skb_cow_data: data points %p\n",skb->data);
	memcpy(data_origin, data, (data_len+padding_len));

	printk(KERN_INFO "After copy & Before rechecksum\n");
	display_packet((char *)skb->data, 0, ntohs(iph->tot_len) + padding_len, ENCRYPTION, SEND);

	//re-checksum
	iph->tot_len = htons(ntohs(iph->tot_len) + padding_len);//'total length' segment in IP
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);//re-checksum for IP

	printk(KERN_INFO "This is sending encrypted package, length: %d\n", ntohs(iph->tot_len));
	display_packet((char *)skb->data, 0, ntohs(iph->tot_len), ENCRYPTION, SEND);

	printk(KERN_INFO "\n");
	kfree(data);

	return NF_ACCEPT;
}

/**
  * @brief  module init function
  */
static int init(void)
{
	unsigned int ret;

	printk("AES kexec start ...\n");
	//NF_LOCAL_IN HOOK struct
	nfhk_local_in.hook = nf_hookfn_in;
	nfhk_local_in.pf = PF_INET;
	nfhk_local_in.hooknum = NF_INET_LOCAL_IN;
	nfhk_local_in.priority = NF_IP_PRI_FIRST;
	//NF_LOCAL_OUT HOOK struct
	nfhk_local_out.hook = nf_hookfn_out;
	nfhk_local_out.pf = PF_INET;
	nfhk_local_out.hooknum = NF_INET_LOCAL_OUT;
	nfhk_local_out.priority = NF_IP_PRI_LAST;

	ret = nf_register_hook(&nfhk_local_in);
	if (ret < 0) {
        printk("LOCAL_IN Register Error\n");
        return ret;
    }

	ret = nf_register_hook(&nfhk_local_out);
	if (ret < 0) {
        printk("LOCAL_OUT Register Error\n");
        return ret;
    }

    ret = netlink_init();
    if (ret < 0) {
    	printk("NETLINK Create Error\n");
        return ret;
    }

	return 0;
}

/**
  * @brief  module exit callback function
  */
static void fini(void)
{
	netlink_fini();
	nf_unregister_hook(&nfhk_local_in);
	nf_unregister_hook(&nfhk_local_out);
	printk("AES kexec exit ...\n");
}

module_init(init);
module_exit(fini);