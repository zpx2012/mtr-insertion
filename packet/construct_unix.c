/*
    mtr  --  a network diagnostic tool
    Copyright (C) 2016  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "construct_unix.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <time.h>
#include <pthread.h>

#include "protocols.h"


/* For Mac OS X and FreeBSD */
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

//////////////////////////////////
uint32_t seq_1 = 0;//network order
uint32_t ack_seq_1 = 0;//network order
uint16_t sport = 0;// network order
int raw_sock_tx = 0;
int raw_sock_rx = 0;
FILE* log_file = NULL;

uint8_t payload[1400] = {0};
int payload_len = 1400;	

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
//    fprintf(stderr,"send_tcp_packet: %x\n",tcpHdr->dest);
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
            //fprintf(stderr,"Success! Sent %d bytes.\n", bytes);
        }
        return 0;
//        printf("SEQ guess: %u\n\n", initSeqGuess);

        //I'll sleep when I'm dead
        //sleep(1);

        //Comment out this break to unleash the beast
//        break;
//    }
}

// void * intercept_existing_conn(void *pVoid) {
//     uint8_t recvbuf[3000];
//     struct sockaddr recvaddr;
//     socklen_t len0 = sizeof(struct sockaddr);
//     struct sockaddr_in* destaddr4 = (struct sockaddr_in*) pVoid;
//     while (1) {
//         recvfrom(raw_sock_rx, recvbuf, 3000, 0, &recvaddr, &len0);
// 		struct tcphdr* tcpHeader = (struct tcphdr *) (recvbuf + sizeof(struct iphdr));
//         fprintf(stderr,"%x %x %x %x\n",((struct iphdr*)recvbuf)->saddr,destaddr4->sin_addr,tcpHeader->source, destaddr4->sin_port);
// 		if (((struct iphdr*)recvbuf)->saddr == destaddr4->sin_addr.s_addr && 
// 			(tcpHeader->source == destaddr4->sin_port)
// 			) {
//        		if (tcpHeader->ack == 1) {
//                 seq_1 = tcpHeader->ack_seq;
//                 ack_seq_1 = htonl((ntohl(tcpHeader->seq) + 1));
// 				sport = tcpHeader->source;
//                 fprintf(stderr,"...%x %x %x\n", seq_1, ack_seq_1, sport);
//             }
//         }	
//     }
// }

extern int init_two_raw_sock() {//need to extract raw socket creation
    srand(time(0));
    raw_sock_tx = initRawSocket(IPPROTO_RAW);
    raw_sock_rx = initRawSocket(IPPROTO_TCP);

	int i = 0;
	for (i = 0; i < payload_len; i++) {
		payload[i] = 15;
	}
	return 0;
}

int get_intercept_info(struct sockaddr_storage *destaddr){
	
    uint8_t recvbuf[3000];
    struct sockaddr recvaddr;
    socklen_t len0 = sizeof(struct sockaddr);
    struct sockaddr_in* destaddr4 = (struct sockaddr_in*) destaddr;
    struct timeval lasttime, thistime, intervaltime;
    int dt = 2.0 * 1000000;
    int data_len = 0;

    intervaltime.tv_sec = dt / 1000000;
    intervaltime.tv_usec = dt % 1000000;
    gettimeofday(&lasttime, NULL);
    gettimeofday(&thistime, NULL);
    while( thistime.tv_sec < lasttime.tv_sec + intervaltime.tv_sec
            || (thistime.tv_sec == lasttime.tv_sec + intervaltime.tv_sec
                && thistime.tv_usec <= lasttime.tv_usec + intervaltime.tv_usec)
    ){
        recvfrom(raw_sock_rx, recvbuf, 3000, 0, &recvaddr, &len0);
        struct iphdr* ipHeader = (struct iphdr*) recvbuf;
        struct tcphdr* tcpHeader = (struct tcphdr *) (recvbuf + sizeof(struct iphdr));
//        fprintf(stderr,"%x %x %x\n",ipHeader->saddr,ipHeader->daddr,destaddr4->sin_addr.s_addr);
		//data receiver side
        if(ipHeader->saddr == destaddr4->sin_addr.s_addr) {

            data_len = ntohs(ipHeader->tot_len) - ipHeader->ihl*4 - tcpHeader->doff*4;//use data_len to distingush
            //fprintf(stderr,"data_len: %d %d %d %d\n", data_len,ntohs(ipHeader->tot_len),ntohs(ipHeader->ihl),ntohs(tcpHeader->doff));
            if(data_len && tcpHeader->source != destaddr4->sin_port){//data receiver side check
                fprintf(stderr,"get_intercept_info:wrong port %x %x\n",tcpHeader->source,destaddr4->sin_port);
                continue;
            }
            if (tcpHeader->ack == 1) {
                seq_1 = tcpHeader->ack_seq;
                ack_seq_1 = htonl(ntohl(tcpHeader->seq) + data_len + 1);
                sport = tcpHeader->dest;
                if(!data_len){
                    ((struct sockaddr_in*)destaddr)->sin_port = tcpHeader->source;
                    fprintf(stderr,"override dport %d\n", ((struct sockaddr_in*)destaddr)->sin_port);
                }
                fprintf(stderr,"%x %x %x\n", seq_1, ack_seq_1, sport);
                return 0;
            }
        } 
        gettimeofday(&thistime, NULL);
		
    }
    fprintf(stderr,"get_intercept_info:time out\n");
    return -1;
    // error(EXIT_FAILURE, errno, "get_intercept_info:time out");
    // _exit(EXIT_FAILURE);
}

// extern int create_intercept_thread(const struct sockaddr_storage *destaddr){

//     pthread_t t1;
//     // pthread_attr_t t2;
//     pthread_create(&t1,0,intercept_existing_conn,destaddr);

// 	int i = 0;
// 	for (i = 0; i < 1024; i++) {
// 		payload[i] = rand() % 255;
// 	}
// 	payload_len = rand() % 1024;

// 	return 0;
// }


extern int send_inserted_tcp_packet(    
	int sequence,
    const struct sockaddr_storage *srcaddr,
    const struct sockaddr_storage *destaddr,
    const struct probe_param_t *param){

	return send_tcp_packet(raw_sock_tx, ((struct sockaddr_in*)srcaddr)->sin_addr.s_addr, sport, destaddr, param->ttl, seq_1, ack_seq_1, sequence);
}
////////////////////////////////////////////////////////////

/*  A source of data for computing a checksum  */
struct checksum_source_t {
    const void *data;
    size_t size;
};

/*  Compute the IP checksum (or ICMP checksum) of a packet.  */
static
uint16_t compute_checksum(
    const void *packet,
    int size)
{
    const uint8_t *packet_bytes = (uint8_t *) packet;
    uint32_t sum = 0;
    int i;

    for (i = 0; i < size; i++) {
        if ((i & 1) == 0) {
            sum += packet_bytes[i] << 8;
        } else {
            sum += packet_bytes[i];
        }
    }

    /*
       Sums which overflow a 16-bit value have the high bits
       added back into the low 16 bits.
     */
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    /*
       The value stored is the one's complement of the
       mathematical sum.
     */
    return (~sum & 0xffff);
}

/*  Encode the IP header length field in the order required by the OS.  */
static
uint16_t length_byte_swap(
    const struct net_state_t *net_state,
    uint16_t length)
{
    if (net_state->platform.ip_length_host_order) {
        return length;
    } else {
        return htons(length);
    }
}

/*  Construct a combined sockaddr from a source address and source port  */
static
void construct_addr_port(
    struct sockaddr_storage *addr_with_port,
    const struct sockaddr_storage *addr,
    int port)
{
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;

    memcpy(addr_with_port, addr, sizeof(struct sockaddr_storage));

    if (addr->ss_family == AF_INET6) {
        addr6 = (struct sockaddr_in6 *) addr_with_port;
        addr6->sin6_port = htons(port);
    } else {
        addr4 = (struct sockaddr_in *) addr_with_port;
        addr4->sin_port = htons(port);
    }
}

/*  Construct a header for IP version 4  */
static
void construct_ip4_header(
    const struct net_state_t *net_state,
    char *packet_buffer,
    int packet_size,
    const struct sockaddr_storage *srcaddr,
    const struct sockaddr_storage *destaddr,
    const struct probe_param_t *param)
{
    struct IPHeader *ip;
    struct sockaddr_in *srcaddr4 = (struct sockaddr_in *) srcaddr;
    struct sockaddr_in *destaddr4 = (struct sockaddr_in *) destaddr;

    ip = (struct IPHeader *) &packet_buffer[0];

    memset(ip, 0, sizeof(struct IPHeader));

    ip->version = 0x45;
    ip->tos = param->type_of_service;
    ip->len = length_byte_swap(net_state, packet_size);
    ip->ttl = param->ttl;
    ip->protocol = param->protocol;
    memcpy(&ip->saddr, &srcaddr4->sin_addr, sizeof(uint32_t));
    memcpy(&ip->daddr, &destaddr4->sin_addr, sizeof(uint32_t));
}

/*  Construct an ICMP header for IPv4  */
static
void construct_icmp4_header(
    const struct net_state_t *net_state,
    int sequence,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct ICMPHeader *icmp;
    int icmp_size;

    if (net_state->platform.ip4_socket_raw) {
        icmp = (struct ICMPHeader *) &packet_buffer[sizeof(struct IPHeader)];
        icmp_size = packet_size - sizeof(struct IPHeader);
    } else {
        icmp = (struct ICMPHeader *) &packet_buffer[0];
        icmp_size = packet_size;
    }

    memset(icmp, 0, sizeof(struct ICMPHeader));

    icmp->type = ICMP_ECHO;
    icmp->id = htons(getpid());
    icmp->sequence = htons(sequence);
    icmp->checksum = htons(compute_checksum(icmp, icmp_size));
}

/*  Construct an ICMP header for IPv6  */
static
int construct_icmp6_packet(
    const struct net_state_t *net_state,
    int sequence,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct ICMPHeader *icmp;

    icmp = (struct ICMPHeader *) packet_buffer;

    memset(icmp, 0, sizeof(struct ICMPHeader));

    icmp->type = ICMP6_ECHO;
    icmp->id = htons(getpid());
    icmp->sequence = htons(sequence);

    return 0;
}

/*
    Set the port numbers for an outgoing UDP probe.
    There is limited space in the header for a sequence number
    to identify the probe upon return.

    We store the sequence number in the destination port, the local
    port, or the checksum.  The location chosen depends upon which
    probe parameters have been requested.
*/
static
void set_udp_ports(
    struct UDPHeader *udp,
    int sequence,
    const struct probe_param_t *param)
{
    if (param->dest_port) {
        udp->dstport = htons(param->dest_port);

        if (param->local_port) {
            udp->srcport = htons(param->local_port);
            udp->checksum = htons(sequence);
        } else {
            udp->srcport = htons(sequence);
            udp->checksum = 0;
        }
    } else {
        udp->dstport = htons(sequence);

        if (param->local_port) {
            udp->srcport = htons(param->local_port);
        } else {
            udp->srcport = htons(getpid());
        }

        udp->checksum = 0;
    }
}

/*
    Construct a header for UDP probes, using the port number associated
    with the probe.
*/
static
void construct_udp4_header(
    const struct net_state_t *net_state,
    int sequence,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    struct UDPHeader *udp;
    int udp_size;

    if (net_state->platform.ip4_socket_raw) {
        udp = (struct UDPHeader *) &packet_buffer[sizeof(struct IPHeader)];
        udp_size = packet_size - sizeof(struct IPHeader);
    } else {
        udp = (struct UDPHeader *) &packet_buffer[0];
        udp_size = packet_size;
    }

    memset(udp, 0, sizeof(struct UDPHeader));

    set_udp_ports(udp, sequence, param);
    udp->length = htons(udp_size);
}

/*  Construct a header for UDPv6 probes  */
static
int construct_udp6_packet(
    const struct net_state_t *net_state,
    int sequence,
    char *packet_buffer,
    int packet_size,
    const struct probe_param_t *param)
{
    int udp_socket = net_state->platform.udp6_send_socket;
    struct UDPHeader *udp;
    int udp_size;

    udp = (struct UDPHeader *) packet_buffer;
    udp_size = packet_size;

    memset(udp, 0, sizeof(struct UDPHeader));

    set_udp_ports(udp, sequence, param);
    udp->length = htons(udp_size);

    if (net_state->platform.ip6_socket_raw) {
        /*
           Instruct the kernel to put the pseudoheader checksum into the
           UDP header, this is only needed when using RAW socket.
         */
        int chksum_offset = (char *) &udp->checksum - (char *) udp;
        if (setsockopt(udp_socket, IPPROTO_IPV6,
                       IPV6_CHECKSUM, &chksum_offset, sizeof(int))) {
            return -1;
        }
    }

    return 0;
}

/*
    Set the socket options for an outgoing stream protocol socket based on
    the packet parameters.
*/
static
int set_stream_socket_options(
    int stream_socket,
    const struct probe_param_t *param)
{
    int level;
    int opt;
    int reuse = 1;

    /*  Allow binding to a local port previously in use  */
#ifdef SO_REUSEPORT
    /*
       FreeBSD wants SO_REUSEPORT in addition to SO_REUSEADDR to
       bind to the same port
     */
    if (setsockopt(stream_socket, SOL_SOCKET, SO_REUSEPORT,
                   &reuse, sizeof(int)) == -1) {

        return -1;
    }
#endif

    if (setsockopt(stream_socket, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(int)) == -1) {

        return -1;
    }

    /*  Set the number of hops the probe will transit across  */
    if (param->ip_version == 6) {
        level = IPPROTO_IPV6;
        opt = IPV6_UNICAST_HOPS;
    } else {
        level = IPPROTO_IP;
        opt = IP_TTL;
    }

    if (setsockopt(stream_socket, level, opt, &param->ttl, sizeof(int)) ==
        -1) {

        return -1;
    }

    /*  Set the "type of service" field of the IP header  */
    if (param->ip_version == 6) {
        level = IPPROTO_IPV6;
        opt = IPV6_TCLASS;
    } else {
        level = IPPROTO_IP;
        opt = IP_TOS;
    }

    if (setsockopt(stream_socket, level, opt,
                   &param->type_of_service, sizeof(int)) == -1) {

        return -1;
    }
#ifdef SO_MARK
    if (param->routing_mark) {
        if (setsockopt(stream_socket, SOL_SOCKET,
                       SO_MARK, &param->routing_mark, sizeof(int))) {
            return -1;
        }
    }
#endif

    return 0;
}

/*
    Open a TCP or SCTP socket, respecting the probe paramters as much as
    we can, and use it as an outgoing probe.
*/
static
int open_stream_socket(
    const struct net_state_t *net_state,
    int protocol,
    int port,
    const struct sockaddr_storage *src_sockaddr,
    const struct sockaddr_storage *dest_sockaddr,
    const struct probe_param_t *param)
{
    int stream_socket;
    int addr_len;
    int dest_port;
    struct sockaddr_storage dest_port_addr;
    struct sockaddr_storage src_port_addr;

    if (param->ip_version == 6) {
        stream_socket = socket(AF_INET6, SOCK_STREAM, protocol);
        addr_len = sizeof(struct sockaddr_in6);
    } else if (param->ip_version == 4) {
        stream_socket = socket(AF_INET, SOCK_STREAM, protocol);
        addr_len = sizeof(struct sockaddr_in);
    } else {
        errno = EINVAL;
        return -1;
    }

    if (stream_socket == -1) {
        return -1;
    }

    set_socket_nonblocking(stream_socket);

    if (set_stream_socket_options(stream_socket, param)) {
        close(stream_socket);
        return -1;
    }

    /*
       Bind to a known local port so we can identify which probe
       causes a TTL expiration.
     */
    construct_addr_port(&src_port_addr, src_sockaddr, port);
    if (bind(stream_socket, (struct sockaddr *) &src_port_addr, addr_len)) {
        close(stream_socket);
        return -1;
    }

    if (param->dest_port) {
        dest_port = param->dest_port;
    } else {
        /*  Use http if no port is specified  */
        dest_port = HTTP_PORT;
    }

    /*  Attempt a connection  */
    construct_addr_port(&dest_port_addr, dest_sockaddr, dest_port);
    if (connect
        (stream_socket, (struct sockaddr *) &dest_port_addr, addr_len)) {

        /*  EINPROGRESS simply means the connection is in progress  */
        if (errno != EINPROGRESS) {
            close(stream_socket);
            return -1;
        }
    }

    return stream_socket;
}

/*
    Determine the size of the constructed packet based on the packet
    parameters.  This is the amount of space the packet *we* construct
    uses, and doesn't include any headers the operating system tacks
    onto the packet.  (Such as the IPv6 header on non-Linux operating
    systems.)
*/
static
int compute_packet_size(
    const struct net_state_t *net_state,
    const struct probe_param_t *param)
{
    int packet_size = 0;

    if (param->protocol == IPPROTO_TCP) {
        return 0;
    }
#ifdef IPPROTO_SCTP
    if (param->protocol == IPPROTO_SCTP) {
        return 0;
    }
#endif

    /*  Start by determining the full size, including omitted headers  */
    if (param->ip_version == 6) {
        if (net_state->platform.ip6_socket_raw) {
            packet_size += sizeof(struct IP6Header);
        }
    } else if (param->ip_version == 4) {
        if (net_state->platform.ip4_socket_raw) {
            packet_size += sizeof(struct IPHeader);
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    if (param->protocol == IPPROTO_ICMP) {
        packet_size += sizeof(struct ICMPHeader);
    } else if (param->protocol == IPPROTO_UDP) {
        packet_size += sizeof(struct UDPHeader);

        /*  We may need to put the sequence number in the payload  */
        packet_size += sizeof(int);
    } else {
        errno = EINVAL;
        return -1;
    }

    /*
       If the requested size from send-probe is greater, extend the
       packet size.
     */
    if (param->packet_size > packet_size) {
        packet_size = param->packet_size;
    }

    /*
       Since we don't explicitly construct the IPv6 header, we
       need to account for it in our transmitted size.
     */
    if (param->ip_version == 6 && net_state->platform.ip6_socket_raw) {
        packet_size -= sizeof(struct IP6Header);
    }

    return packet_size;
}

/*  Construct a packet for an IPv4 probe  */
static
int construct_ip4_packet(
    const struct net_state_t *net_state,
    int *packet_socket,
    int sequence,
    char *packet_buffer,
    int packet_size,
    const struct sockaddr_storage *src_sockaddr,
    const struct sockaddr_storage *dest_sockaddr,
    const struct probe_param_t *param)
{
    int send_socket = net_state->platform.ip4_send_socket;
    bool is_stream_protocol = false;
    int tos, ttl, socket_0;
    bool bind_send_socket = false;
    struct sockaddr_storage current_sockaddr;
    int current_sockaddr_len;

    if (param->protocol == IPPROTO_TCP) {
        is_stream_protocol = true;
#ifdef IPPROTO_SCTP
    } else if (param->protocol == IPPROTO_SCTP) {
        is_stream_protocol = true;
#endif
    } else {
        if (net_state->platform.ip4_socket_raw) {
            construct_ip4_header(net_state, packet_buffer, packet_size,
                                 src_sockaddr, dest_sockaddr, param);
        }
        if (param->protocol == IPPROTO_ICMP) {
            construct_icmp4_header(net_state, sequence, packet_buffer,
                                   packet_size, param);
        } else if (param->protocol == IPPROTO_UDP) {
            construct_udp4_header(net_state, sequence, packet_buffer,
                                  packet_size, param);
        } else {
            errno = EINVAL;
            return -1;
        }
    }

    static int init_flag = 0;
    if (is_stream_protocol) {
        if(!init_flag){
            init_two_raw_sock();
            //create_intercept_thread(dest_sockaddr);
            init_flag = 1;
        }
        if(!get_intercept_info(dest_sockaddr))
    		send_inserted_tcp_packet(sequence, src_sockaddr, dest_sockaddr, param);

        int fake_socket = socket(AF_INET, SOCK_STREAM, 0);
//        if (param->ttl > max_ttl) {
//            max_ttl = param->ttl;
//            struct sockaddr_in dest_port_addr;
//            dest_port_addr.sin_addr.s_addr = htonl(inet_network(param->remote_address));
//            dest_port_addr.sin_family = AF_INET;
//            dest_port_addr.sin_port = htons(param->dest_port);
//            set_socket_nonblocking(fake_socket);
//            setsockopt(fake_socket, IPPROTO_IP, IP_TTL, &param->ttl, sizeof(int));
//            connect(fake_socket, (struct sockaddr *) &dest_port_addr, sizeof(struct sockaddr_in));
//        }
        *packet_socket = 0;
        return 0;
    }

    /*
       The routing mark requires CAP_NET_ADMIN, as opposed to the
       CAP_NET_RAW which we are sometimes explicitly given.
       If we don't have CAP_NET_ADMIN, this will fail, so we'll 
       only set the mark if the user has explicitly requested it.

       Unfortunately, this means that once the mark is set, it won't
       be set on the socket_0 again until a new mark is explicitly
       specified.
     */
#ifdef SO_MARK
    if (param->routing_mark) {
        if (setsockopt(send_socket, SOL_SOCKET,
                       SO_MARK, &param->routing_mark, sizeof(int))) {
            return -1;
        }
    }
#endif

    /*
       Bind src port when not using raw socket_0 to pass in ICMP id, kernel
       get ICMP id from src_port when using DGRAM socket_0.
     */
    if (!net_state->platform.ip4_socket_raw &&
            param->protocol == IPPROTO_ICMP &&
            !param->is_probing_byte_order) {
        current_sockaddr_len = sizeof(struct sockaddr_in);
        bind_send_socket = true;
        socket_0 = net_state->platform.ip4_txrx_icmp_socket;
        if (getsockname(socket_0, (struct sockaddr *) &current_sockaddr,
                        &current_sockaddr_len)) {
            return -1;
        }
        struct sockaddr_in *sin_cur =
            (struct sockaddr_in *) &current_sockaddr;

        /* avoid double bind */
        if (sin_cur->sin_port) {
            bind_send_socket = false;
        }
    }

    /*  Bind to our local address  */
    if (bind_send_socket && bind(socket_0, (struct sockaddr *)src_sockaddr,
                sizeof(struct sockaddr_in))) {
        return -1;
    }

    /* set TOS and TTL for non-raw socket_0 */
    if (!net_state->platform.ip4_socket_raw && !param->is_probing_byte_order) {
        if (param->protocol == IPPROTO_ICMP) {
            socket_0 = net_state->platform.ip4_txrx_icmp_socket;
        } else if (param->protocol == IPPROTO_UDP) {
            socket_0 = net_state->platform.ip4_txrx_udp_socket;
        } else {
            return 0;
        }
        tos = param->type_of_service;
        if (setsockopt(socket_0, SOL_IP, IP_TOS, &tos, sizeof(int))) {
            return -1;
        }
        ttl = param->ttl;
        if (setsockopt(socket_0, SOL_IP, IP_TTL,
                       &ttl, sizeof(int)) == -1) {
            return -1;
        }
    }

    return 0;
}

/*  Construct a packet for an IPv6 probe  */
static
int construct_ip6_packet(
    const struct net_state_t *net_state,
    int *packet_socket,
    int sequence,
    char *packet_buffer,
    int packet_size,
    const struct sockaddr_storage *src_sockaddr,
    const struct sockaddr_storage *dest_sockaddr,
    const struct probe_param_t *param)
{
    int send_socket;
    bool is_stream_protocol = false;
    bool bind_send_socket = true;
    struct sockaddr_storage current_sockaddr;
    int current_sockaddr_len;

    if (param->protocol == IPPROTO_TCP) {
        is_stream_protocol = true;
#ifdef IPPROTO_SCTP
    } else if (param->protocol == IPPROTO_SCTP) {
        is_stream_protocol = true;
#endif
    } else if (param->protocol == IPPROTO_ICMP) {
        if (net_state->platform.ip6_socket_raw) {
            send_socket = net_state->platform.icmp6_send_socket;
        } else {
            send_socket = net_state->platform.ip6_txrx_icmp_socket;
        }

        if (construct_icmp6_packet
            (net_state, sequence, packet_buffer, packet_size, param)) {
            return -1;
        }
    } else if (param->protocol == IPPROTO_UDP) {
        if (net_state->platform.ip6_socket_raw) {
            send_socket = net_state->platform.udp6_send_socket;
        } else {
            send_socket = net_state->platform.ip6_txrx_udp_socket;
        }

        if (construct_udp6_packet
            (net_state, sequence, packet_buffer, packet_size, param)) {
            return -1;
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    if (is_stream_protocol) {
        send_socket =
            open_stream_socket(net_state, param->protocol, sequence,
                               src_sockaddr, dest_sockaddr, param);

        if (send_socket == -1) {
            return -1;
        }

        *packet_socket = send_socket;
        return 0;
    }

    /*
       Check the current socket address, and if it is the same
       as the source address we intend, we will skip the bind.
       This is to accomodate Solaris, which, as of Solaris 11.3,
       will return an EINVAL error on bind if the socket is already
       bound, even if the same address is used.
     */
    current_sockaddr_len = sizeof(struct sockaddr_in6);
    if (getsockname(send_socket, (struct sockaddr *) &current_sockaddr,
                    &current_sockaddr_len) == 0) {
        struct sockaddr_in6 *sin6_cur = (struct sockaddr_in6 *) &current_sockaddr;

        if (net_state->platform.ip6_socket_raw) {
            if (memcmp(&current_sockaddr,
                       src_sockaddr, sizeof(struct sockaddr_in6)) == 0) {
                bind_send_socket = false;
            }
        } else {
            /* avoid double bind for DGRAM socket */
            if (sin6_cur->sin6_port) {
                bind_send_socket = false;
            }
        }
    }

    /*  Bind to our local address  */
    if (bind_send_socket) {
        if (bind(send_socket, (struct sockaddr *) src_sockaddr,
                 sizeof(struct sockaddr_in6))) {
            return -1;
        }
    }

    /*  The traffic class in IPv6 is analagous to ToS in IPv4  */
    if (setsockopt(send_socket, IPPROTO_IPV6,
                   IPV6_TCLASS, &param->type_of_service, sizeof(int))) {
        return -1;
    }

    /*  Set the time-to-live  */
    if (setsockopt(send_socket, IPPROTO_IPV6,
                   IPV6_UNICAST_HOPS, &param->ttl, sizeof(int))) {
        return -1;
    }
#ifdef SO_MARK
    if (param->routing_mark) {
        if (setsockopt(send_socket,
                       SOL_SOCKET, SO_MARK, &param->routing_mark,
                       sizeof(int))) {
            return -1;
        }
    }
#endif

    return 0;
}

/*  Construct a probe packet based on the probe parameters  */
int construct_packet(
    const struct net_state_t *net_state,
    int *packet_socket,
    int sequence,
    char *packet_buffer,
    int packet_buffer_size,
    const struct sockaddr_storage *dest_sockaddr,
    const struct sockaddr_storage *src_sockaddr,
    const struct probe_param_t *param)
{
    int packet_size;

    packet_size = compute_packet_size(net_state, param);
    if (packet_size < 0) {
        return -1;
    }

    if (packet_buffer_size < packet_size) {
        errno = EINVAL;
        return -1;
    }

    memset(packet_buffer, param->bit_pattern, packet_size);

    if (param->ip_version == 6) {
        if (construct_ip6_packet(net_state, packet_socket, sequence,
                                 packet_buffer, packet_size,
                                 src_sockaddr, dest_sockaddr, param)) {
            return -1;
        }
    } else if (param->ip_version == 4) {
        if (construct_ip4_packet(net_state, packet_socket, sequence,
                                 packet_buffer, packet_size,
                                 src_sockaddr, dest_sockaddr, param)) {
            return -1;
        }
    } else {
        errno = EINVAL;
        return -1;
    }

    return packet_size;
}

