
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>

#define NETLINK_TEST 25/* general netlink */
#define MAX_PAYLOAD 1024 // maximum payload size

int main(int argc, char* argv[])
{
    int state;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL; //Netlink数据包头
    struct iovec iov;
    struct msghdr msg;
    int sock_fd, retval;
    int state_smg = 0;
    int key_num = -1;
    char text[10];
    // Input key
    while(key_num < 0 || key_num > 32) {
        printf("Please input a key seed (0 <= key <= 32) to generate the key:\n");
        scanf("%d", &key_num);
    }
    sprintf(text, "%d%d", key_num/10, key_num%10);
    // Create a socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
    if(sock_fd == -1){
        printf("error getting socket: %s", strerror(errno));
        return -1;
    }
    // To prepare binding
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid =getpid(); //A：设置源端端口号
    src_addr.nl_groups = 0;
    //Bind
    retval = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if(retval < 0){
        printf("bind failed: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }
    // To orepare create mssage
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if(!nlh){
        printf("malloc nlmsghdr error!\n");
        close(sock_fd);
        return -1;
    }
    memset(&dest_addr,0,sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; //B：设置目的端口号
    dest_addr.nl_groups = 0;
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid(); //C：设置源端口
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh),"Start Transmission!"); //设置消息体
    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);
    //Create mssage
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    //send message
    printf("state_smg\n");
    state_smg = sendmsg(sock_fd,&msg,0);
    if(state_smg == -1)
    {
        printf("get error sendmsg = %s\n",strerror(errno));
    }
    memset(nlh,0,NLMSG_SPACE(MAX_PAYLOAD));
    //receive message
    printf("waiting received!\n");
    FILE *log = fopen("log.txt", "a");
    while(1){
        state = recvmsg(sock_fd, &msg, 0);
        if(state<0)
        {
            printf("state<1");
        }
        printf("%s\n",(char *) NLMSG_DATA(nlh));
        fprintf(log, "%s\n",(char *) NLMSG_DATA(nlh));
    }
    fclose(log);
    close(sock_fd);
    return 0;
}