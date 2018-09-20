//
// Created by root on 18-8-26.
//

#ifndef MTR_TCP_H
#define MTR_TCP_H

#include <stdint.h>

extern int init_two_raw_sock();
extern int create_rcv_thread(const struct sockaddr_storage *destaddr);
extern int send_inserted_tcp_packet(    
	int sequence,
    const struct sockaddr_storage *srcaddr,
    const struct sockaddr_storage *destaddr,
    const struct probe_param_t *param);
#endif //MTR_TCP_H
