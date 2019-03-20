#include <pcap.h>
#include <stdio.h>

// typedef struct Ipv4
// {
//     char version_headlength;
//     char type_of_service;
//     short total_length;
//     short identification;
//     short fragment_offset;
//     char time_to_live;
//     char protocol;
//     short checksum;
//     unsigned int source_address;
//     unsigned int destination_address;
// }IP;

typedef struct //IP头结构
{
    int header_len:4;
    int version:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char proto:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}IPHEAD;

typedef struct{      //TCP头结构
    short srcPort;        // 源端口号16bit
    short dstPort;        // 目的端口号16bit
    unsigned int uiSequNum;       // 序列号32bit
    unsigned int uiAcknowledgeNum;  // 确认号32bit
    short sHeaderLenAndFlag;      // 前4位：TCP头长度；中6位：保留；后6位：标志位
    short sWindowSize;       // 窗口大小16bit
    short sCheckSum;         // 检验和16bit
    short surgentPointer;       // 紧急数据偏移量16bit
}TCPHEAD;

typedef struct{          //UDP头结构
    unsigned short srcPort;    // 源端口号16bit
    unsigned short dstPort;    // 目的端口号16bit
    unsigned short usLength;    // 数据包长度16bit
    unsigned short usCheckSum;    // 校验和16bit
}UDPHEAD;


void callback(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data);

int main(int argc, char *argv[])
{
	pcap_t *enth; /* Session enth */
	char *dev; /* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
	struct bpf_program fp; /* The compiled filter */
	char filter_exp[] = "port 80"; /* The filter expression */
	bpf_u_int32 mask; /* Our netmask */
	bpf_u_int32 net; /* Our IP */
	struct pcap_pkthdr header; /* The header that pcap gives us */
	const u_char *packet; /* The actual packet */


	/* Define the device */
	dev = pcap_lookupdev(errbuf);  //查看设备，返回句柄
	if (dev == NULL) {             //如果返回空则报错
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {   //获取设备详细信息，如IP、掩码等等
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	enth = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);   //开始混杂模式监听
	if (enth == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(enth, &fp, filter_exp, 0, net) == -1) {    //编译规则
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(enth));
		return(2);
	}
	if (pcap_setfilter(enth, &fp) == -1) {                   //设置过滤器
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(enth));
		return(2);
	}
	/* Grab a packet */
	pcap_loop(enth, -1, callback, NULL);                    //开始循环补包

	/* And close the session */
	pcap_close(enth);
	return(0);
}

void callback(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    printf("\n\t\tOne packet captured.\t\t\n");
    printf("-------------------------------------------------\n");
    //解析数据包IP头部
    if(header->len>=14){    //数据帧头14字节尾6字节
        FILE *fp;
	    fp = fopen("pcap_record.txt", "a+");   //打开文件，准备记录捕包信息
        fprintf(fp,"\n\t\tOne packet captured.\t\t\n");
        fprintf(fp,"-------------------------------------------------\n");
        IPHEAD *ip_header=(IPHEAD*)(pkt_data+14);
        // //解析协议类型
        // cout<<"|版本 "<<ip_header->version<<"|首部长度"<<ip_header->header_len*4<<"字节|\t\t|"
        //     "总长度"<<ip_header->total_len<<"字节|"<<endl;
        // printf("-------------------------------------------------\n");
        // cout<<"|\t\t\t|\t|\t\t|"<<endl;
        // printf("-------------------------------------------------\n");
        // cout<<"|ttl "<<int(ip_header->ttl)<<"\t|协议 ";
        // switch(ip_header->proto)
        // {
        //   case 1:
        //     cout<<"ICMP";
        //     break;
        //   case 2:
        //     cout<<"IGMP";
        //     break;
        //   case 6:
        //     cout<<"TCP ";
        //     break;
        //   case 17:
        //     cout<<"UDP ";
        //     break;
        //   case 41:
        //     cout<<"IPv6";
        //     break;
        //   default:
        //     cout<<"IPv4";
        // }
        // cout<<"\t|首部校验和 "<<ip_header->checksum<<"\t|"<<endl;
        // printf("-------------------------------------------------\n");
        printf("\t\t源地址 : %d.%d.%d.%d\t\t\n",ip_header->sourceIP[0],ip_header->sourceIP[1],ip_header->sourceIP[2],ip_header->sourceIP[3]);  //打印源IP
        printf("-------------------------------------------------\n");
        printf("\t\t目的地址 : %d.%d.%d.%d\t\t\n",ip_header->destIP[0],ip_header->destIP[1],ip_header->destIP[2],ip_header->destIP[3]);
        printf("-------------------------------------------------\n");

        fprintf(fp,"\t\t源地址 : %d.%d.%d.%d\t\t\n",ip_header->sourceIP[0],ip_header->sourceIP[1],ip_header->sourceIP[2],ip_header->sourceIP[3]);  //写入到文件
        fprintf(fp,"-------------------------------------------------\n");
        fprintf(fp,"\t\t目的地址 : %d.%d.%d.%d\t\t\n",ip_header->destIP[0],ip_header->destIP[1],ip_header->destIP[2],ip_header->destIP[3]);
        fprintf(fp,"-------------------------------------------------\n");

        if(ip_header->proto==6){
            printf("\t\tTCP\t\t\n");
            printf("-------------------------------------------------\n");
            fprintf(fp,"\t\tTCP\t\t\n");
            fprintf(fp,"-------------------------------------------------\n");
            TCPHEAD *tcp_header=(TCPHEAD*)(pkt_data+14+4*ip_header->header_len);  //加上IP头长度，略过IP头
            printf("\t\t源端口号 : %d\t\t\n",tcp_header->srcPort);             //打印TCP端口号
            printf("-------------------------------------------------\n");
            printf("\t\t源端口号 : %d\t\t\n",tcp_header->dstPort);
            printf("-------------------------------------------------\n");
            fprintf(fp,"\t\t源端口号 : %d\t\t\n",tcp_header->srcPort);   //写入端口号到文件
            fprintf(fp,"-------------------------------------------------\n");
            fprintf(fp,"\t\t源端口号 : %d\t\t\n",tcp_header->dstPort);
            fprintf(fp,"-------------------------------------------------\n");
        }else if(ip_header->proto==17){
            printf("\t\tUDP\t\t\n");
            printf("-------------------------------------------------\n");
            fprintf(fp,"\t\tUDP\t\t\n");
            fprintf(fp,"-------------------------------------------------\n");
            UDPHEAD *udp_header=(UDPHEAD*)(pkt_data+14+4*ip_header->header_len);
            printf("\t\t源端口号 : %d\t\t\n",udp_header->srcPort);              //打印UDP端口号
            printf("-------------------------------------------------\n");
            printf("\t\t源端口号 : %d\t\t\n",udp_header->dstPort);
            printf("-------------------------------------------------\n");
            fprintf(fp,"\t\t源端口号 : %d\t\t\n",udp_header->srcPort);          //写入端口号到文件
            fprintf(fp,"-------------------------------------------------\n");
            fprintf(fp,"\t\t源端口号 : %d\t\t\n",udp_header->dstPort);
            fprintf(fp,"-------------------------------------------------\n");
        }else{
            printf("暂未实现的协议类型，不处理\n");
            fprintf(fp,"暂未实现的协议类型，不处理\n");
        }
        fclose(fp);
    }
}
