#include<netinet/in.h>
#include<stdio.h>
#include<netinet/ip_icmp.h>
#include<netinet/if_ether.h>
#include<net/ethernet.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>

#include<stdlib.h>
#include<string.h>
#include<unistd.h>

#include<locale.h>
#include<time.h>

#define PACKET_LENGTH 65536
#define TRUE 1
#define FALSE 0

#define TIME_UTC 1

typedef struct sockaddr* t_sap;
unsigned long long packet_cnt;

char* PROTOCOL_NAME[18];
struct opt_arg{
	char time[100];
	struct timespec ts;
	int is_tcp;  // -t
	int is_udp;  // -u
	int is_icmp; // -i
	int is_more; // -vi
	int is_write;
	int is_port;
	int is_list;
	int is_src;
	int is_dst;
	int is_all_protocol;
	unsigned short port; // -p 3389
	int s,e; // list = start, end
	char src_addr[20]; // -s 192.168.1.32
	char dst_addr[20]; // -d 192.168.1.33
	char filename[50]; // -w dump.dat
	char list[40];	    // -c 50,100
};

struct opt_arg option;
struct packet_info{
	char* src_addr;
	char* dst_addr;
	char* src_port;
	char* dst_port;
};

struct packet_info pi;
FILE* fp;

void init();
void PrintUSAGE();
void PrintPacket(unsigned char*, int);
void PrintTime();
void PrintIP(unsigned char*, int);
void PrintICMP(unsigned char*, int);
void PrintTCP(unsigned char*, int);
void PrintUDP(unsigned char*, int);
void PrintData(unsigned char*, int);
void PrintTCPHeaderToFile(unsigned char* buf, int size, struct iphdr* iph, struct tcphdr* tcph);
void PrintTCPHeaderToScreen(unsigned char* buf, int size, struct tcphdr* tcph);
void PrintUDPHeaderToFile(unsigned char* buf, int size, struct iphdr* iph, struct udphdr* udph);
void PrintUDPHeaderToScreen(unsigned char* buf, int size, struct udphdr* udph);
void PrintICMPHeaderToFile(unsigned char* buf, int size, struct iphdr* iph, struct icmp* rp);
void PrintICMPHeaderToScreen(unsigned char* buf, int size, struct icmp* rp);
		
int main(int argc, char** argv){
	int readn, opt;
	socklen_t addrlen;
	int sock_raw;
	struct sockaddr_in saddr;

	init();
	unsigned char* buffer = (unsigned char*)malloc(PACKET_LENGTH);
	sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sock_raw < 0){
		perror("error: ");
		return 1;
	}
	 	
	while((opt = getopt(argc, argv, "tuihs:d:p:m:w:c:r:")) != -1){
		if(opt == 'h'){
			PrintUSAGE();
			return 1;
		}

		switch(opt){
	      case 't':
			option.is_tcp = TRUE;
			break;
	      case 'u':
			option.is_udp = 1;
			break;
	      case 'i':
			option.is_icmp = 1;
			break;
	      case 's':
			option.is_src = 1;
			memcpy(option.src_addr, optarg, 20);
			break;
	      case 'd':
			option.is_dst = 1;
			memcpy(option.dst_addr, optarg, 20);
			break;
	      case 'p':
			option.is_port = 1;
			option.port = atoi(optarg);
			break;
	      case 'w':
			option.is_write = 1;
			memcpy(option.filename, optarg, 50);
			if((fp = fopen(option.filename, "w+")) == NULL){
				perror("file error: ");
				exit(1);
			}	
			break;
	      case 'c':
			option.is_list = 1;
			memcpy(option.list, optarg, 40);
			option.s = atoi(strtok(option.list, ","));
			option.e = atoi(strtok(NULL, ","));
			break;
	      default :
			printf("There isn`t this option!!!\n");
			break;
	     }
    }

	if(option.is_tcp == 0 && option.is_udp == 0 && option.is_icmp == 0){
		option.is_tcp = option.is_udp = option.is_icmp = 1;
		option.is_all_protocol = 1;
	}	

	while(1){
		addrlen = sizeof(saddr);
		memset(buffer, 0x00, PACKET_LENGTH);
		readn = recvfrom(sock_raw, buffer, PACKET_LENGTH, 0, (t_sap)&saddr, &addrlen); 
	
		if(readn < 0)
			return 1;
		
		PrintPacket(buffer, readn);
	}

	close(sock_raw);
	return 0;
}

void init(){
	setbuf(stdout, NULL);
	memset(&option, 0, sizeof(option));
	PROTOCOL_NAME[1] = "ICMP";
	PROTOCOL_NAME[6] = "TCP";
	PROTOCOL_NAME[17] = "UDP";
}

void PrintUSAGE(){
	printf("yhdump version 0.0.1\n");
	printf("Usage: yhdump [tuims:d:p:w:c:]\n");
	printf("[ -t|-u|-i, Show only tcp/udp/icmp packet]\n");
	printf("[ -d|-s IP, Show only the packets corresponding to the IP ]\n");
	printf("[ -p PORT, Show only the packets correspoding to the port ]\n");
	printf("[ -w FILE, Write the packets to the file ]\n");
	printf("[ -c RANGE, Show the packets in that range ]\n");
}

void PrintPacket(unsigned char* buffer, int size){
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	
	packet_cnt++;
	switch(iph->protocol){
		case 1:
			PrintICMP(buffer, size);
			break;
		case 6:
			PrintTCP(buffer, size);
			break;
		case 17:
			PrintUDP(buffer, size);
			break;
		default:
			break;
	}
}

void PrintTime(){
	struct timespec ts;
	timespec_get(&ts, TIME_UTC);
	char buff[100];
	strftime(buff, sizeof buff, "%D %T", gmtime(&ts.tv_sec));
	
	if(option.is_write){
		strcpy(option.time, buff);
		option.ts = ts;
	}else{
		printf("%llu. %s.%09ld ", packet_cnt, buff, ts.tv_nsec);
	}
}

void PrintIP(unsigned char* buf, int size){
	unsigned short iphdrlen;
	char protocol_name[10];

	struct sockaddr_in src, dst;
	struct iphdr* iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;

	memset(&src, 0x00, sizeof(src));
	src.sin_addr.s_addr = iph->saddr;
	
	memset(&dst, 0x00, sizeof(dst));
	dst.sin_addr.s_addr = iph->daddr;

	pi.src_addr = inet_ntoa(src.sin_addr);
	pi.dst_addr = inet_ntoa(dst.sin_addr);

	PrintTime();
	if(!option.is_write)
		printf("%s ", PROTOCOL_NAME[iph->protocol]);	
}

void PrintTCPHeaderToFile(unsigned char* buf, int size, struct iphdr* iph, struct tcphdr* tcph){
	char flag[50];
	PrintIP(buf, size);
	
	memset(flag, 0x00, sizeof(flag));
	if((unsigned int)tcph->urg)
		strcat(flag, "URG, ");
	if((unsigned int)tcph->ack)
		strcat(flag, "ACK, ");
	if((unsigned int)tcph->psh)
		strcat(flag, "PSH, ");
	if((unsigned int)tcph->rst)
		strcat(flag, "RST, ");
	if((unsigned int)tcph->syn)
		strcat(flag, "SYN, ");
	if((unsigned int)tcph->fin)
		strcat(flag, "FIN, ");

	flag[strlen(flag)-2] = 0;
	dprintf(fileno(fp), "%llu. %s.%09ld %s %s(%u) > %s(%u) [%s] Seq=%u, Ack=%u, Win=%d\n", packet_cnt, option.time, option.ts.tv_nsec, PROTOCOL_NAME[iph->protocol], pi.src_addr, ntohs(tcph->source), pi.dst_addr, ntohs(tcph->dest), flag, ntohl(tcph->seq), ntohl(tcph->ack_seq), ntohs(tcph->window));
}

void PrintTCPHeaderToScreen(unsigned char* buf, int size, struct tcphdr* tcph){
	char flag[50];
	PrintIP(buf, size);

	memset(flag, 0x00, sizeof(flag));
	if((unsigned int)tcph->urg)
		strcat(flag, "URG, ");
	if((unsigned int)tcph->ack)
		strcat(flag, "ACK, ");
	if((unsigned int)tcph->psh)
		strcat(flag, "PSH, ");
	if((unsigned int)tcph->rst)
		strcat(flag, "RST, ");
	if((unsigned int)tcph->syn)
		strcat(flag, "SYN, ");
	if((unsigned int)tcph->fin)
		strcat(flag, "FIN, ");

	flag[strlen(flag)-2] = 0;
	printf("%s(%u) > %s(%u) [%s] Seq=%u, Ack=%u, Win=%d\n", pi.src_addr, ntohs(tcph->source), pi.dst_addr, ntohs(tcph->dest), flag, ntohl(tcph->seq), ntohl(tcph->ack_seq), ntohs(tcph->window));
}

void PrintTCP(unsigned char* buf, int size){
	if(!option.is_tcp) return ;
	 
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct sockaddr_in src, dst;

	memset(&src, 0x00, sizeof(src));
	src.sin_addr.s_addr = iph->saddr;
	
	memset(&dst, 0x00, sizeof(dst));
	dst.sin_addr.s_addr = iph->daddr;

	char *src_addr = inet_ntoa(src.sin_addr);
	char *dst_addr = inet_ntoa(dst.sin_addr);

	struct tcphdr *tcph = (struct tcphdr*)(buf + iphdrlen + sizeof(struct ethhdr));

	// option.is_write가 있는 경우
	if(option.is_write){
		// list옵션만 있는 경우 => ./ypt -c 1,100
		if(option.is_write && option.is_list == 0 && option.is_more == 0 && option.is_port == 0 && option.is_src == 0 && option.is_dst == 0)
			PrintTCPHeaderToFile(buf, size, iph, tcph);

		if(option.is_list && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_dst == 0)
		{
			if(packet_cnt > option.e)
				exit(0);		
				
			if(option.s <= packet_cnt && packet_cnt <= option.e)	
				PrintTCPHeaderToFile(buf, size, iph, tcph);
		}

		// option.is_list가 옵션인 경우
		else if(option.is_list)
		{
			// 리스트 종료 구문 => 반드시 맨 앞 둬야 한다.
			if(packet_cnt > option.e)
				exit(0);		

			// 리스트와 근원지 => ./ypt -c 1,100 -s 192.168.3.123
			else if(option.is_src && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.src_addr, src_addr) == 0)
				PrintTCPHeaderToFile(buf, size, iph, tcph);
			
			// 리스트와 목적지 => ./ypt -c 1,100 -d 192.168.2.125
			else if(option.is_dst && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.dst_addr, dst_addr) == 0)
				PrintTCPHeaderToFile(buf, size, iph, tcph);

			// 리스트와 포트 => => ./ypt -c 1,100 -p 7563	
			else if(option.is_port && (option.port == ntohs(tcph->source) || option.port == ntohs(tcph->dest)) && (option.s <= packet_cnt && packet_cnt <= option.e))
				PrintTCPHeaderToFile(buf, size, iph, tcph);
		}	

		// option.is_port가 옵션인 경우
		else if(option.is_port && option.is_list == 0)
		{
			// 포트만 있는 경우 => ./ypt -p 7563
			if((option.port == ntohs(tcph->source) || option.port == ntohs(tcph->dest)) &&  option.is_more == 0 && option.is_src == 0 && option.is_dst == 0)
				PrintTCPHeaderToFile(buf, size, iph, tcph);
		
			// 포트랑 근원지 => ./ypt -p 7563 -s 192.168.2.1 ( 근원지 포트 7563과 근원지 주소 192.168.2.1 )		
			else if(option.is_src && option.port == ntohs(tcph->source) && strcmp(option.src_addr, src_addr) == 0)
				PrintTCPHeaderToFile(buf, size, iph, tcph);

			// 포트랑 목적지 => ./ypt -p 7563 -d 192.168.2.1 ( 목적지 포트 7563과 목적지 주소 192.168.2.1 )
			else if(option.is_dst && option.port == ntohs(tcph->dest) && strcmp(option.dst_addr, dst_addr) == 0)
				PrintTCPHeaderToFile(buf, size, iph, tcph);
			
		}

		// option.is_src가 있는 경우
		else if(option.is_src && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 근원지 옵션만 있는 경우 => ./ypt -s 192.168.3.125
			// printf("option.src_addr: %s, src_addr: %s\n", option.src_addr, src_addr);
			if(strcmp(option.src_addr, src_addr) == 0)
				PrintTCPHeaderToFile(buf, size, iph, tcph);

			// 목적지와 근원지가 있는 경우 => ./ypt -s 192.168.2.1 -d 192.168.4.2
			else if(option.is_dst && strcmp(option.dst_addr, dst_addr) == 0 && strcmp(option.src_addr, src_addr) == 0)
				PrintTCPHeaderToFile(buf, size, iph, tcph);
		}

		// option.is_dst만 있는 경우
		else if(option.is_dst && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 목적지 옵션만 있는 경우 => ./ypt -d 192.168.3.125
			if(strcmp(option.dst_addr, dst_addr) == 0)
				PrintTCPHeaderToFile(buf, size, iph, tcph);
		}

		else if(option.is_all_protocol)
			PrintTCPHeaderToFile(buf, size, iph, tcph);

		else if(option.is_tcp)
			PrintTCPHeaderToFile(buf, size, iph, tcph);

	// option.is_write가 없는 경우	
	}else if(!option.is_write){ 
		// option.is_list가 옵션인 경우
		if(option.is_list && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_dst == 0)
		{
			if(packet_cnt > option.e)
				exit(0);		
				
			if(option.s <= packet_cnt && packet_cnt <= option.e)	
				PrintTCPHeaderToScreen(buf, size, tcph);	
		}
		
		else if(option.is_list)
		{
			// 리스트 종료 구문 => 반드시 맨 앞 둬야 한다.
			if(packet_cnt > option.e)
				exit(0);		

			// 리스트와 근원지 => ./ypt -c 1,100 -s 192.168.3.123
			else if(option.is_src && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.src_addr, src_addr) == 0)
				PrintTCPHeaderToScreen(buf, size, tcph);
			
			// 리스트와 목적지 => ./ypt -c 1,100 -d 192.168.2.125
			else if(option.is_dst && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.dst_addr, dst_addr) == 0)
				PrintTCPHeaderToScreen(buf, size, tcph);

			// 리스트와 포트 => => ./ypt -c 1,100 -p 7563	
			else if(option.is_port && (option.port == ntohs(tcph->source) || option.port == ntohs(tcph->dest)) && (option.s <= packet_cnt && packet_cnt <= option.e))
				PrintTCPHeaderToScreen(buf, size, tcph);
		}	

		// option.is_port가 옵션인 경우
		else if(option.is_port && option.is_list == 0)
		{
			// 포트만 있는 경우 => ./ypt -p 7563
			if((option.port == ntohs(tcph->source) || option.port == ntohs(tcph->dest)) &&  option.is_more == 0 && option.is_src == 0 && option.is_dst == 0)
				PrintTCPHeaderToScreen(buf, size, tcph);
			
			// 포트랑 근원지 => ./ypt -p 7563 -s 192.168.2.1 ( 근원지 포트 7563과 근원지 주소 192.168.2.1 )		
			if(option.is_src && option.port == ntohs(tcph->source) && strcmp(option.src_addr, src_addr) == 0)
				PrintTCPHeaderToScreen(buf, size, tcph);

			// 포트랑 목적지 => ./ypt -p 7563 -d 192.168.2.1 ( 목적지 포트 7563과 목적지 주소 192.168.2.1 )
			else if(option.is_dst && option.port == ntohs(tcph->dest) && strcmp(option.dst_addr, dst_addr) == 0)
				PrintTCPHeaderToScreen(buf, size, tcph);
		}

		// option.is_src가 있는 경우
		else if(option.is_src && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 근원지 옵션만 있는 경우 => ./ypt -s 192.168.3.125
			// printf("option.src_addr: %s, src_addr: %s, strcmp(option.src_addr, src_addr): %d\n", option.src_addr, src_addr, strcmp(option.src_addr, src_addr));
			if(strcmp(option.src_addr, src_addr) == 0)
				PrintTCPHeaderToScreen(buf, size, tcph);

			// 목적지와 근원지가 있는 경우 => ./ypt -s 192.168.2.1 -d 192.168.4.2
			else if(option.is_dst && strcmp(option.dst_addr, dst_addr) == 0 && strcmp(option.src_addr, src_addr) == 0)
				PrintTCPHeaderToScreen(buf, size, tcph);
		}

		// option.is_dst만 있는 경우
		else if(option.is_dst && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 목적지 옵션만 있는 경우 => ./ypt -d 192.168.3.125
			if(strcmp(option.dst_addr, dst_addr) == 0)
				PrintTCPHeaderToScreen(buf, size, tcph);
		}

		else if(option.is_all_protocol)
			PrintTCPHeaderToScreen(buf, size, tcph);
		
		else if(option.is_tcp)
			PrintTCPHeaderToScreen(buf, size, tcph);
		
	}
}	

void PrintICMPHeaderToFile(unsigned char* buf, int size, struct iphdr* iph, struct icmp* rp){
	PrintIP(buf, size);
	dprintf(fileno(fp), "%llu. %s.%09ld %s %s > %s [TYPE=%d, CODE=%d, CHECKSUM=%d, ID=%d, SEQ=%d]\n", packet_cnt, option.time, option.ts.tv_nsec, PROTOCOL_NAME[iph->protocol], pi.src_addr, pi.dst_addr, rp->icmp_type, rp->icmp_code, rp->icmp_cksum, rp->icmp_id, rp->icmp_seq);
}

void PrintICMPHeaderToScreen(unsigned char* buf, int size, struct icmp* rp){
	PrintIP(buf, size);
	printf("%s > %s [TYPE=%d, CODE=%d, CHECKSUM=%d, ID=%d, SEQ=%d]\n", pi.src_addr, pi.dst_addr, rp->icmp_type, rp->icmp_code, rp->icmp_cksum, rp->icmp_id, rp->icmp_seq);
}

void PrintICMP(unsigned char* buf, int size){
	if(!option.is_icmp) return ;

	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
	struct ip *ip = (struct ip*)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	
	struct icmp *rp = (struct icmp*)(buf + iphdrlen + sizeof(struct ethhdr));
	
	struct sockaddr_in src, dst;

	memset(&src, 0x00, sizeof(src));
	src.sin_addr.s_addr = iph->saddr;
	
	memset(&dst, 0x00, sizeof(dst));
	dst.sin_addr.s_addr = iph->daddr;

	char *src_addr = inet_ntoa(src.sin_addr);
	char *dst_addr = inet_ntoa(dst.sin_addr);

	// option.is_write가 있는 경우
	if(option.is_write){
		// list옵션만 있는 경우 => ./ypt -c 1,100
		if(option.is_write && option.is_list == 0 && option.is_more == 0 && option.is_port == 0 && option.is_src == 0 && option.is_dst == 0)
			PrintICMPHeaderToFile(buf, size, iph, rp);

		if(option.is_list && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_dst == 0)
		{
			if(packet_cnt > option.e)
				exit(0);		
			
			if(option.s <= packet_cnt && packet_cnt <= option.e)	
				PrintICMPHeaderToFile(buf, size, iph, rp);
		}

		// option.is_list가 옵션인 경우
		else if(option.is_list)
		{
			// 리스트 종료 구문 => 반드시 맨 앞 둬야 한다.
			if(packet_cnt > option.e)
				exit(0);		
				

			// 리스트와 근원지 => ./ypt -c 1,100 -s 192.168.3.123
			else if(option.is_src && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.src_addr, src_addr) == 0)
				PrintICMPHeaderToFile(buf, size, iph, rp);
			
			// 리스트와 목적지 => ./ypt -c 1,100 -d 192.168.2.125
			else if(option.is_dst && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.dst_addr, dst_addr) == 0)
				PrintICMPHeaderToFile(buf, size, iph, rp);
		}	

		// option.is_src가 있는 경우
		else if(option.is_src && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 근원지 옵션만 있는 경우 => ./ypt -s 192.168.3.125
			// printf("option.src_addr: %s, src_addr: %s\n", option.src_addr, src_addr);
			if(strcmp(option.src_addr, src_addr) == 0)
				PrintICMPHeaderToFile(buf, size, iph, rp);

			// 목적지와 근원지가 있는 경우 => ./ypt -s 192.168.2.1 -d 192.168.4.2
			else if(option.is_dst && strcmp(option.dst_addr, dst_addr) == 0 && strcmp(option.src_addr, src_addr) == 0)
				PrintICMPHeaderToFile(buf, size, iph, rp);
		}

		// option.is_dst만 있는 경우
		else if(option.is_dst && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 목적지 옵션만 있는 경우 => ./ypt -d 192.168.3.125
			if(strcmp(option.dst_addr, dst_addr) == 0)
				PrintICMPHeaderToFile(buf, size, iph, rp);
		}

		else if(option.is_all_protocol)
			PrintICMPHeaderToFile(buf, size, iph, rp);

		// else if(option.is_icmp)
		// 	PrintICMPHeaderToFile(buf, size, iph, rp);

	// option.is_write가 없는 경우	
	}else if(!option.is_write){ 
		// option.is_list가 옵션인 경우
		if(option.is_list && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_dst == 0)
		{
			if(packet_cnt > option.e)
				exit(0);		
				
			if(option.s <= packet_cnt && packet_cnt <= option.e)	
				PrintICMPHeaderToScreen(buf, size, rp);	
		}
		
		else if(option.is_list)
		{
			// 리스트 종료 구문 => 반드시 맨 앞 둬야 한다.
			if(packet_cnt > option.e)
				exit(0);		
			
			// 리스트와 근원지 => ./ypt -c 1,100 -s 192.168.3.123
			else if(option.is_src && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.src_addr, src_addr) == 0)
				PrintICMPHeaderToScreen(buf, size, rp);
			
			// 리스트와 목적지 => ./ypt -c 1,100 -d 192.168.2.125
			else if(option.is_dst && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.dst_addr, dst_addr) == 0)
				PrintICMPHeaderToScreen(buf, size, rp);
		}	

		// option.is_src가 있는 경우
		else if(option.is_src && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 근원지 옵션만 있는 경우 => ./ypt -s 192.168.3.125
			// printf("option.src_addr: %s, src_addr: %s, strcmp(option.src_addr, src_addr): %d\n", option.src_addr, src_addr, strcmp(option.src_addr, src_addr));
			if(strcmp(option.src_addr, src_addr) == 0)
				PrintICMPHeaderToScreen(buf, size, rp);

			// 목적지와 근원지가 있는 경우 => ./ypt -s 192.168.2.1 -d 192.168.4.2
			else if(option.is_dst && strcmp(option.dst_addr, dst_addr) == 0 && strcmp(option.src_addr, src_addr) == 0)
				PrintICMPHeaderToScreen(buf, size, rp);
		}

		// option.is_dst만 있는 경우
		else if(option.is_dst && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 목적지 옵션만 있는 경우 => ./ypt -d 192.168.3.125
			if(strcmp(option.dst_addr, dst_addr) == 0)
				PrintICMPHeaderToScreen(buf, size, rp);
		}

		else if(option.is_all_protocol){
			PrintICMPHeaderToScreen(buf, size, rp);
		}
		
		else if(option.is_icmp){
			PrintICMPHeaderToScreen(buf, size, rp);
		}
	}
}

void PrintUDPHeaderToFile(unsigned char* buf, int size, struct iphdr* iph, struct udphdr* udph){
	PrintIP(buf, size);
	dprintf(fileno(fp), "%llu. %s.%09ld %s %s(%u) > %s(%u) Len=%d, Chk=%d\n", packet_cnt, option.time, option.ts.tv_nsec, PROTOCOL_NAME[iph->protocol], pi.src_addr, ntohs(udph->source), pi.dst_addr, ntohs(udph->dest), ntohs(udph->len), ntohs(udph->check));
}

void PrintUDPHeaderToScreen(unsigned char* buf, int size, struct udphdr* udph){
	PrintIP(buf, size);
	printf("%s(%u) > %s(%u) Len=%d, Chk=%d\n", pi.src_addr, ntohs(udph->source), pi.dst_addr, ntohs(udph->dest), ntohs(udph->len), ntohs(udph->check));
}

void PrintUDP(unsigned char* buf, int size){
	if(!option.is_udp) return ;
	 
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr*)(buf + sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct sockaddr_in src, dst;

	memset(&src, 0x00, sizeof(src));
	src.sin_addr.s_addr = iph->saddr;
	
	memset(&dst, 0x00, sizeof(dst));
	dst.sin_addr.s_addr = iph->daddr;

	char *src_addr = inet_ntoa(src.sin_addr);
	char *dst_addr = inet_ntoa(dst.sin_addr);

	struct udphdr *udph = (struct udphdr*)(buf + iphdrlen + sizeof(struct ethhdr));

	// option.is_write가 있는 경우
	if(option.is_write){
		// list옵션만 있는 경우 => ./ypt -c 1,100
		if(option.is_write && option.is_list == 0 && option.is_more == 0 && option.is_port == 0 && option.is_src == 0 && option.is_dst == 0)
			PrintUDPHeaderToFile(buf, size, iph, udph);

		if(option.is_list && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_dst == 0)
		{
			if(packet_cnt > option.e)
				exit(0);		
				
			if(option.s <= packet_cnt && packet_cnt <= option.e)	
				PrintUDPHeaderToFile(buf, size, iph, udph);
		}

		// option.is_list가 옵션인 경우
		else if(option.is_list)
		{
			// 리스트 종료 구문 => 반드시 맨 앞 둬야 한다.
			if(packet_cnt > option.e)
				exit(0);		

			// 리스트와 근원지 => ./ypt -c 1,100 -s 192.168.3.123
			else if(option.is_src && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.src_addr, src_addr) == 0)
				PrintUDPHeaderToFile(buf, size, iph, udph);
			
			// 리스트와 목적지 => ./ypt -c 1,100 -d 192.168.2.125
			else if(option.is_dst && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.dst_addr, dst_addr) == 0)
				PrintUDPHeaderToFile(buf, size, iph, udph);

			// 리스트와 포트 => => ./ypt -c 1,100 -p 7563	
			else if(option.is_port && (option.port == ntohs(udph->source) || option.port == ntohs(udph->dest)) && (option.s <= packet_cnt && packet_cnt <= option.e))
				PrintUDPHeaderToFile(buf, size, iph, udph);
		}	

		// option.is_port가 옵션인 경우
		else if(option.is_port && option.is_list == 0)
		{
			// 포트만 있는 경우 => ./ypt -p 7563
			if((option.port == ntohs(udph->source) || option.port == ntohs(udph->dest)) &&  option.is_more == 0 && option.is_src == 0 && option.is_dst == 0)
				PrintUDPHeaderToFile(buf, size, iph, udph);
		
			// 포트랑 근원지 => ./ypt -p 7563 -s 192.168.2.1 ( 근원지 포트 7563과 근원지 주소 192.168.2.1 )		
			else if(option.is_src && (option.port == ntohs(udph->source) || option.port == ntohs(udph->dest)) && strcmp(option.src_addr, src_addr) == 0)
				PrintUDPHeaderToFile(buf, size, iph, udph);

			// 포트랑 목적지 => ./ypt -p 7563 -d 192.168.2.1 ( 목적지 포트 7563과 목적지 주소 192.168.2.1 )
			else if(option.is_dst && (option.port == ntohs(udph->source) || option.port == ntohs(udph->dest)) && strcmp(option.dst_addr, dst_addr) == 0)
				PrintUDPHeaderToFile(buf, size, iph, udph);
		}

		// option.is_src가 있는 경우
		else if(option.is_src && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 근원지 옵션만 있는 경우 => ./ypt -s 192.168.3.125
			if(strcmp(option.src_addr, src_addr) == 0)
				PrintUDPHeaderToFile(buf, size, iph, udph);

			// 목적지와 근원지가 있는 경우 => ./ypt -s 192.168.2.1 -d 192.168.4.2
			else if(option.is_dst && strcmp(option.dst_addr, dst_addr) == 0 && strcmp(option.src_addr, src_addr) == 0)
				PrintUDPHeaderToFile(buf, size, iph, udph);
		}

		// option.is_dst만 있는 경우
		else if(option.is_dst && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 목적지 옵션만 있는 경우 => ./ypt -d 192.168.3.125
			if(strcmp(option.dst_addr, dst_addr) == 0)
				PrintUDPHeaderToFile(buf, size, iph, udph);
		}

		else if(option.is_all_protocol)
			PrintUDPHeaderToFile(buf, size, iph, udph);

		else if(option.is_udp)
			PrintUDPHeaderToFile(buf, size, iph, udph);

	// option.is_write가 없는 경우	
	}else if(!option.is_write){ 
		// option.is_list가 옵션인 경우
		if(option.is_list && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_dst == 0)
		{
			if(packet_cnt > option.e)
				exit(0);		
				
			if(option.s <= packet_cnt && packet_cnt <= option.e)	
				PrintUDPHeaderToScreen(buf, size, udph);	
		}
			
		if(option.is_list)
		{
			// 리스트 종료 구문 => 반드시 맨 앞 둬야 한다.
			if(packet_cnt > option.e)
				exit(0);		

			// 리스트와 근원지 => ./ypt -c 1,100 -s 192.168.3.123
			else if(option.is_src && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.src_addr, src_addr) == 0)
				PrintUDPHeaderToScreen(buf, size, udph);
			
			// 리스트와 목적지 => ./ypt -c 1,100 -d 192.168.2.125
			else if(option.is_dst && (option.s <= packet_cnt && packet_cnt <= option.e) && strcmp(option.dst_addr, dst_addr) == 0)
				PrintUDPHeaderToScreen(buf, size, udph);

			// 리스트와 포트 => => ./ypt -c 1,100 -p 7563	
			else if(option.is_port && (option.port == ntohs(udph->source) || option.port == ntohs(udph->dest)) && (option.s <= packet_cnt && packet_cnt <= option.e))
				PrintUDPHeaderToScreen(buf, size, udph);
		}	

		// option.is_port가 옵션인 경우
		else if(option.is_port && option.is_list == 0)
		{
			// 포트만 있는 경우 => ./ypt -p 7563
			if((option.port == ntohs(udph->source) || option.port == ntohs(udph->dest)) &&  option.is_more == 0 && option.is_src == 0 && option.is_dst == 0)
				PrintUDPHeaderToScreen(buf, size, udph);
		
			// 포트랑 근원지 => ./ypt -p 7563 -s 192.168.2.1 ( 근원지 포트 7563과 근원지 주소 192.168.2.1 )		
			else if(option.is_src && (option.port == ntohs(udph->source) || option.port == ntohs(udph->dest)) && strcmp(option.src_addr, src_addr) == 0)
				PrintUDPHeaderToScreen(buf, size, udph);

			// 포트랑 목적지 => ./ypt -p 7563 -d 192.168.2.1 ( 목적지 포트 7563과 목적지 주소 192.168.2.1 )
			else if(option.is_dst && (option.port == ntohs(udph->source) || option.port == ntohs(udph->dest)) && strcmp(option.dst_addr, dst_addr) == 0)
				PrintUDPHeaderToScreen(buf, size, udph);
		}

		// option.is_src가 있는 경우
		else if(option.is_src && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 근원지 옵션만 있는 경우 => ./ypt -s 192.168.3.125
			// printf("option: %s, pi: %s\n", option.src_addr, src_addr);
			if(strcmp(option.src_addr, src_addr) == 0)
				PrintUDPHeaderToScreen(buf, size, udph);

			// 목적지와 근원지가 있는 경우 => ./ypt -s 192.168.2.1 -d 192.168.4.2
			else if(option.is_dst && strcmp(option.dst_addr, dst_addr) == 0 && strcmp(option.src_addr, src_addr) == 0)
				PrintUDPHeaderToScreen(buf, size, udph);
		}

		// option.is_dst만 있는 경우
		else if(option.is_dst && option.is_src == 0 && option.is_port == 0 && option.is_more == 0 && option.is_list == 0)
		{
			// 목적지 옵션만 있는 경우 => ./ypt -d 192.168.3.125
			if(strcmp(option.dst_addr, dst_addr) == 0)
				PrintUDPHeaderToScreen(buf, size, udph);
		}

		else if(option.is_all_protocol)
			PrintUDPHeaderToScreen(buf, size, udph);
		
		else if(option.is_udp)
			PrintUDPHeaderToScreen(buf, size, udph);
		
	}	
	
}
