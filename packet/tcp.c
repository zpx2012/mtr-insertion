//
// Created by root on 18-8-26.
//
#ifndef MTR_TCP_C
#define MTR_TCP_C

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


// extern int sendData(int stream_socket, const char* ipaddr, uint16_t port,
//                     uint8_t ttl, uint8_t* payload, int payload_len, uint16_t ip_id) {

//     struct sockaddr_in src_port_addr;
//     socklen_t len = sizeof(src_port_addr);
//     getsockname(stream_socket, (struct sockaddr *)&src_port_addr, &len);
// 	log_file = fopen("tcp_log.txt","a");
// 	fprintf(log_file,"%d:%s ",ttl, iso_time(time(NULL)));
//     if(seq_1 == 0 || ack_seq_1 == 0){
//         fprintf(log_file,'seq_1 == 0 or ack_seq_1 == 0\n');
// 		fclose(log_file);
//         return -1;
//     }
//     sendIpPacket(raw_sock_tx, src_port_addr.sin_addr.s_addr, ipaddr, port, htons(src_port_addr.sin_port), ttl, seq_1, ack_seq_1, payload, payload_len, ip_id);
// 	fprintf(log_file,"sent successful\n");
// 	fclose(log_file);



//    int sock = initRawSocket();
//    sendIpPacket(sock, "172.16.0.22", "172.16.0.1", 80, rand() * UINT16_MAX, 123, 1);
//    sleep(1);
//    sendIpPacket(sock, "172.16.0.22", "172.16.0.1", 80, rand() * UINT16_MAX, 122, 0);
//    uint8_t recvbuf[3000];
//    sockaddr recvaddr;
//    socklen_t len = sizeof(struct sockaddr);
////    sock = initRawSocket();
//    while (true) {
//        recvfrom(sock, recvbuf, 3000, 0, &recvaddr, &len);
//        if (((iphdr*)recvbuf)->saddr == inet_addr("172.16.0.1")) {
//            tcphdr *ptr = (tcphdr *) (recvbuf + sizeof(struct iphdr));
//            printf("%e", ptr->seq);
//            break;
//        }
//    }

//     return 0;
// }
#endif //MTR_TCP_H