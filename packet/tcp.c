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

uint32_t seq_1 = 0;//network order
uint32_t ack_seq_1 = 0;//network order
uint16_t sport = 0;// network order
int raw_sock_tx = 0;
int raw_sock_rx = 0;
FILE* log_file = NULL;

uint8_t payload[1024] = {0};
int payload_len = 0;	

//Calculate the TCP header checksum of a string (as specified in rfc793)
//Function from http://www.binarytides.com/raw-sockets-c-code-on-linux/
unsigned short csum(unsigned short *ptr,int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    //Debug info
    //hexdump((unsigned char *) ptr, nbytes);
    //printf("csum nbytes: %d\n", nbytes);
    //printf("csum ptr address: %p\n", ptr);

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}


//Pseudo header needed for calculating the TCP header checksum
struct pseudoTCPPacket {
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t TCP_len;
};

int initRawSocket(int protocol) {
    int sock, one = 1;
    //Raw socket without any protocol-header inside
    if((sock = socket(AF_INET, SOCK_RAW, protocol)) < 0) {
        perror("Error while creating socket");
        exit(-1);
    }

    //Set option IP_HDRINCL (headers are included in packet)
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0) {
        perror("Error while setting socket options");
        exit(-1);
    }

    return sock;
}

int send_tcp_packet(int sock, uint32_t srcIP, uint16_t srcPort, 
						 const struct sockaddr_storage *destaddr,
						 uint8_t ttl, 
						 uint32_t seq, 
						 uint32_t ack_seq,
                  		 uint16_t ip_id) {
    int bytes  = 1;
    struct iphdr *ipHdr;
    struct tcphdr *tcpHdr;
    struct sockaddr_in* destaddr4 = (struct sockaddr_in*) destaddr;
    //Initial guess for the SEQ field of the TCP header
//    uint32_t initSeqGuess = rand() * UINT32_MAX;

    //Data to be appended at the end of the tcp header
    char* data;

    //Ethernet header + IP header + TCP header + data
    char packet[1514];

    //Pseudo TCP header to calculate the TCP header's checksum
    struct pseudoTCPPacket pTCPPacket;

    //Pseudo TCP Header + TCP Header + data
    char *pseudo_packet;

    //Allocate mem for ip and tcp headers and zero the allocation
    memset(packet, 0, sizeof(packet));
    ipHdr = (struct iphdr *) packet;
    tcpHdr = (struct tcphdr *) (packet + sizeof(struct iphdr));
    data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
    memcpy(data, payload, payload_len);

    //Populate ipHdr
    ipHdr->ihl = 5; //5 x 32-bit words in the header
    ipHdr->version = 4; // ipv4
    ipHdr->tos = 0;// //tos = [0:5] DSCP + [5:7] Not used, low delay
    ipHdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data); //total lenght of packet. len(data) = 0
    ipHdr->id = htons(ip_id); // 0x00; //16 bit id
    ipHdr->frag_off = 0x40; //16 bit field = [0:2] flags + [3:15] offset = 0x0
    ipHdr->ttl = ttl; //16 bit time to live (or maximal number of hops)
    ipHdr->protocol = IPPROTO_TCP; //TCP protocol
    ipHdr->check = 0; //16 bit checksum of IP header. Can't calculate at this point
    ipHdr->saddr = srcIP; //32 bit format of source address
    ipHdr->daddr = destaddr4->sin_addr.s_addr; //32 bit format of source address
//    memcpy(&ip->saddr, &srcaddr4->sin_addr, sizeof(uint32_t));
//    memcpy(&ip->daddr, &destaddr4->sin_addr, sizeof(uint32_t));

    //Now we can calculate the check sum for the IP header check field
    ipHdr->check = csum((unsigned short *) packet, ipHdr->tot_len);
//    printf("IP header checksum: %d\n\n\n", ipHdr->check);

    //Populate tcpHdr
    tcpHdr->source = srcPort; //16 bit in nbp format of source port
    tcpHdr->dest = destaddr4->sin_port; //16 bit in nbp format of destination port
    tcpHdr->seq = seq;
    tcpHdr->ack_seq = ack_seq;
//    tcpHdr->seq = init_seq + 1; //32 bit sequence number, initially set to zero
//    tcpHdr->ack_seq = init_ack + 1; //32 bit ack sequence number, depends whether ACK is set or not
    tcpHdr->doff = 5; //4 bits: 5 x 32-bit words on tcp header
    tcpHdr->res1 = 0; //4 bits: Not used
    tcpHdr->cwr = 0; //Congestion control mechanism
    tcpHdr->ece = 0; //Congestion control mechanism
    tcpHdr->urg = 0; //Urgent flag
    tcpHdr->ack = 1; //Acknownledge
    tcpHdr->psh = 0; //Push data immediately
    tcpHdr->rst = 0; //RST flag
    tcpHdr->syn = 0; //SYN flag
    tcpHdr->fin = 0; //Terminates the connection
    tcpHdr->window = htons(9638);//0xFFFF; //16 bit max number of databytes
    tcpHdr->check = 0; //16 bit check sum. Can't calculate at this point
    tcpHdr->urg_ptr = 0; //16 bit indicate the urgent data. Only if URG flag is set

    //Now we can calculate the checksum for the TCP header
    pTCPPacket.srcAddr = srcIP; //32 bit format of source address
    pTCPPacket.dstAddr = destaddr4->sin_addr.s_addr; //32 bit format of source address
    pTCPPacket.zero = 0; //8 bit always zero
    pTCPPacket.protocol = IPPROTO_TCP; //8 bit TCP protocol
    pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + strlen(data)); // 16 bit length of TCP header

    //Populate the pseudo packet
    pseudo_packet = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data)));
    memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data));

    //Copy pseudo header
    memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));

    //Send lots of packets
//    while(1) {
//        //Try to gyess TCP seq
//        tcpHdr->seq = htonl(initSeqGuess++);
//
        //Calculate check sum: zero current check, copy TCP header + data to pseudo TCP packet, update check
        tcpHdr->check = 0;
//
        //Copy tcp header + data to fake TCP header for checksum
        memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcpHdr, sizeof(struct tcphdr) + strlen(data));
//
        //Set the TCP header's check field
        tcpHdr->check = (csum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) +
                                                                       sizeof(struct tcphdr) +  strlen(data))));
//
//        printf("TCP Checksum: %d\n", (int) tcpHdr->check);

        //Finally, send packet
        if((bytes = sendto(sock, packet, ipHdr->tot_len, 0, (struct sockaddr *)destaddr4, sizeof(struct sockaddr))) < 0) {
            perror("Error on sendto()");
            return -1;
        }
        else {
//            printf("Success! Sent %d bytes.\n", bytes);
        }
        return 0;
//        printf("SEQ guess: %u\n\n", initSeqGuess);

        //I'll sleep when I'm dead
        //sleep(1);

        //Comment out this break to unleash the beast
//        break;
//    }
}

void * interceptACK(void *pVoid) {
    uint8_t recvbuf[3000];
    struct sockaddr recvaddr;
    socklen_t len0 = sizeof(struct sockaddr);
    struct sockaddr_in* destaddr4 = (struct sockaddr_in*) pVoid;
    while (1) {
        recvfrom(raw_sock_rx, recvbuf, 3000, 0, &recvaddr, &len0);
		struct tcphdr* tcpHeader = (struct tcphdr *) (recvbuf + sizeof(struct iphdr));
		if (((struct iphdr*)recvbuf)->daddr == destaddr4->sin_addr.s_addr && 
			(tcpHeader->dest == destaddr4->sin_port)
			) {
       		if (tcpHeader->ack == 1) {
                ack_seq_1 = tcpHeader->ack_seq;
                seq_1 = htonl((ntohl(tcpHeader->seq) + 1));
				sport = tcpHeader->source;
            }
        }	
    }
}

extern int init_two_raw_sock() {//need to extract raw socket creation
    srand(time(0));
    raw_sock_tx = initRawSocket(IPPROTO_RAW);
    raw_sock_rx = initRawSocket(IPPROTO_TCP);
	return 0;
}

extern int create_rcv_thread(const struct sockaddr_storage *destaddr){

    pthread_t t1;
    pthread_attr_t t2;
    pthread_create(&t1,0,interceptACK,&destaddr);

	int i = 0;
	for (i = 0; i < 1024; i++) {
		payload[i] = rand() % 255;
	}
	payload_len = rand() % 1024;

	return 0;
}


extern int send_inserted_tcp_packet(    
	int sequence,
    const struct sockaddr_storage *srcaddr,
    const struct sockaddr_storage *destaddr,
    const struct probe_param_t *param){

	if (!seq_1 || !ack_seq_1 || !sport){
		return -1;	
	}
	return send_tcp_packet(raw_sock_tx, ((struct sockaddr_in*)srcaddr)->sin_addr.s_addr, sport, destaddr, param->ttl, seq_1, ack_seq_1, sequence);
}

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