#ifndef __AES_HOOK_H
#define __AES_HOOK_H

// Set your IP address here
#define LOCAL_IP "192.168.181.128"
#define REMOTE_IP "192.168.181.129"

void printkHex(char *, int, int, char*);
char padding_fill(int);
char padding_check(char *, int);

#endif
