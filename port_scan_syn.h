#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
//#include <ws2tcpip.h>
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <linux/tcp.h>
#endif
#define SWAP_8(x) (((x)>>4)|(((x)&0x0f)<<4))                                    //0x31 --> 0x13
#define SWAP_16(x) (((x)>>8)|(((x)&0x00ff)<<8))                                 //0x1122 --> 0x2211
#define SWAP_32_1(x) (((x)>>16)|(((x)&0x0000ffff)<<16))                         //0x11223344 --> 0x33441122
//#define SWAP_32_2(x) SWAP_32_1((((x)&0xff00ffff)>>8)|(((x)&0xffff00ff)<<8))     //0x11223344 --> 0x44332211
#define SWAP_32_2(x) (((x)>>24)|(((x)&0x00ff0000)>>8)|(((x)&0x0000ff00)<<8)|(((x)&0x000000ff)<<24))     //0x11223344 --> 0x44332211
#define SWAP_32 SWAP_32_2

#define SIO_RCVALL (0x80000000|(0x18000000)|(1))
#define SOCKET_CLOSE closesocket
#define SEQ 633678900
#define PORTL 10416

#ifdef _WIN32
	#define lock_inc(x) InterlockedIncrement(&(x))
	#define lock_dec(x) InterlockedDecrement(&(x))
#else
	#define lock_inc(x) __sync_add_and_fetch(&(x),1)
	#define lock_dec(x) __sync_sub_and_fetch(&(x),1)
#endif

typedef struct _iphdr{
	uint8_t h_lenver; //4λIP�汾��+4λ�ײ�����
	uint8_t tos; //8λ��������TOS
	//000=��ͨ��001=���ȣ�010=�������ͣ�011=����ʽ
	//100=���죬101=CRI/TIC/ECP��110=������ƣ�111=�������
	uint16_t total_len; //16λ�ܳ��ȣ��ֽڣ������FFFF=65535
	uint16_t ident; //16λ��ʶ
	uint16_t frag_and_flags; //3λ��־λ+13λƬ��ƫ��
	//1λ�����ã�2λΪ1��ʾ·�������ܶ��ϲ����ݰ��ֶΣ�3λΪ1��ʾ�Ѿ��ֶ�
	uint8_t ttl; //8λ����ʱ�� TTL
	uint8_t proto; //8λЭ�� (TCP, UDP ������)
	//1=ICMP,2=IGMP,6=TCP,17=UDP,88=IGRP,89=OSPF
	uint16_t checksum; //16λIP�ײ�У���
	//��IPͷ������ȷ�Լ�⣬�����������ݲ��֣�ÿ��·����Ҫ�ı�TTL��ֵ,����·������Ϊÿ��ͨ�������ݰ����¼������ֵ
	uint32_t sourceIP; //32λԴIP��ַ
	uint32_t destIP; //32λĿ��IP��ַ
} IP_HEADER;//��20�ֽڣ����������ICMP��TCP��UDP�ȣ�����ԴIP��Ŀ��IP

//TCP head
typedef struct _tcphdr{
	uint16_t th_sport; //16λԴ�˿�
	uint16_t th_dport; //16λĿ�Ķ˿�
	uint32_t th_seq; //32λ���к�
	uint32_t th_ack; //32λACKȷ�Ϻ�
	uint8_t th_lenres; //4λ�ײ�����(���ݶ�ƫ����)+6λ��������0,TCP���Ⱥͱ�����
	uint8_t th_flag; //6λ���Ʊ�־�����ܻ�ͬʱ���ֶ��λ��Ϊ1
	//0x20  0x00100000 URG Я���������ϵķ��
	//0x10  0x00010000 ACK ��Ӧ���
	//0x08  0x00001000 PSH (PushFunction) �˷����Я�������ݻ�ֱ���ϴ����ϲ�Ӧ�ó�������辭��TCP����
	//0x04  0x00000100 RST �ش�
	//0x02  0x00000010 SYN ���ر�־
	//0x01  0x00000001 End Of Data
	uint16_t th_win; //16λ���ڴ�С
	uint16_t th_sum; //16λУ���
	uint16_t th_urp; //16λ��������ƫ����
} TCP_HEADER;

//TCP xhead
typedef struct _psd_header{
	unsigned long saddr; //Դ��ַ
	unsigned long daddr; //Ŀ�ĵ�ַ
	char mbz;
	char ptcl; //Э������
	unsigned short tcpl; //TCP����
}PSD_HEADER;

uint32_t mm_rand(uint32_t min,uint32_t max){
    static uint32_t flag;
    if(flag==0){
        srand((uint32_t)time(NULL));
        flag=1;
    }
    return min+(uint32_t)(rand()*(max-min+1.0)/(1.0+RAND_MAX));
}

void mm_bin2hex(char*in,int len,char*out){
	char table[]="0123456789abcdef";
	unsigned value,i=0;
	for(;i<len;in++){
		if(len>0 && ++i>len)break;
		value=( (*in) & 255 );
		*(++out)=table[value%16];
		value/=16;
		*(--out)=table[value%16];
		out+=2;
	}
	*out=0;
}

uint32_t mm_server_time_get_s(){
#ifdef _WIN32
	return GetTickCount();
#else
    struct timespec ts;
    clock_gettime(1,&ts);
    return ts.tv_sec;
#endif
}
//1С�ˣ�0���
int check_cpu_1small_0big(){
	uint32_t a=1;
	return (*((uint8_t*)(&a))==1);
}
unsigned mm_server_itoa(uint32_t value, char*out,int not_write_end_0){
    char tmp[11];
    char*P_save=9+(char*)&tmp;
    char*P=P_save;
	if(value==0){
		*out='0';
		if(not_write_end_0!=1)*(out+1)=0;
		return 1;
	}
    while(value){
        *(P--)='0'+(value%10);
        value/=10;
    }
    register unsigned n=(P_save-P);
    memcpy(out,P+1,n);
    if(not_write_end_0!=1)*(out+n)=0;
    return(n);
}
unsigned mm_server_ip_uint32_to_ipv4_string(uint32_t ipv4,char*out){
    unsigned char*p=(unsigned char*)&ipv4;
    char*out_save=out;
    int n=mm_server_itoa(*p,out,1);
    out+=mm_server_itoa(*p,out,1);
    *(out++)='.';
    out+=mm_server_itoa(*(p+1),out,1);
    *(out++)='.';
    out+=mm_server_itoa(*(p+2),out,1);
    *(out++)='.';
    out+=mm_server_itoa(*(p+3),out,0);
    return(out-out_save);
}
uint32_t ip2int(char*ip,int little_end){
	uint32_t tmp;
	unsigned char*p=(unsigned char*)&tmp;
	char*ip_save=ip;
	ip+=strlen(ip);
	int i=3;
	for(;ip>ip_save;ip--){
		if(*ip=='.'){
			*ip=0;
			*(p+i)=atoi(ip+1);
			--i;
		}
	}
	if(i!=0)return 0;
	*p=atoi(ip);
	return (little_end==1)?(SWAP_32(tmp)):tmp;
}
//mm_time_get_formatstring(0,8,out,"%Y%m%d %H:%M:%S")
void mm_time_get_formatstring(time_t in_utc_time,uint32_t in_time_zone,char*back_format_string,char*format_ruler){
	if(in_utc_time==0)in_utc_time=time(NULL);
	if(in_time_zone!=0)in_utc_time+=(in_time_zone*3600);
	strftime(back_format_string,64,format_ruler,localtime(&in_utc_time));
}
long mm_file_readall(char*filename,char**out,long out_size){
	FILE*f=fopen(filename,"r");
	if(f==NULL)return -1;
	fseek(f,0,SEEK_END);
	long fsize=ftell(f);
	fseek(f,0,SEEK_SET);
	if(fsize>0 && out_size<=fsize){
		++fsize;
		*out=(char*)realloc(*out,fsize);
		memset(*out,0,sizeof(char)*fsize);
	}
	long read_size=fread(*out,fsize,1,f);
	fclose(f);
	return read_size;
}
int mm_string_explode(char*in,char*key,void*function){
	char*P=in;
	char*P_end=P+strlen(in);
	char*buf=(char*)strstr(P,key);
	int len_key=strlen(key);
	char x;
	unsigned times=0;
	int(*f)(char*,int);
	f=function;
	while(buf!=NULL){
			++times;
			x=*buf;
			*buf=0;
	    if(1==f(P,times))return times;
	    *buf=x;
			P=buf+len_key;
	    buf=strstr(P,key);
	}
	if(times>0 && P<P_end){
		++times;
		f(P,times);
	}
	return times;
}
#define IS_SPACE(ch) (ch == ' ' || ch == '\n' || ch == '\t' || ch == '\r' || ch == '\b' || ch == '\f' || ch == '��')
#define NOT_SPACE(ch) (ch!= ' ' && ch != '\n' && ch != '\t' && ch != '\r' && ch != '\b' && ch != '\f' && ch != '��')
int mm_string_trim(char*str,char*out,int with_0){
	char*p=str;
	char*p1;
	int backn=0;
	if(p){
		p1 = p+strlen(str)-1;
		while(*p && IS_SPACE(*p)) p++;
		for(;p1>p;p1--){
			if(NOT_SPACE(*p1)){
				*(++p1)='\0';
				break;
			}
		}
		backn=p1-p;
		if(backn<0)backn=0;
		while( ( *(out++) = *(p++) ) != '\0' );
		if(with_0==1)*out='\0';
	}
	return backn;
}
int mm_string_strstr(char*big,char*key,int where_start){
    char*p=big;
    unsigned len=strlen(key);
    for(;(p=(char*)strchr(p,*key))!=0;p++){
			if((p-big)<where_start)continue;
			if(strncmp(p,key,len)==0)return (p-big);//return (char*)p;
    }
    return -1;
}
uint16_t checksum(uint16_t*buffer,int size){
	unsigned long cksum=0;
	while(size>1){
		cksum += *(buffer++);
		size -= sizeof(uint16_t);
	}
	if(size){
		cksum += *(uint8_t*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >>16);
	return (uint16_t)(~cksum);
}
uint32_t get_local_ip(){
	uint32_t ip=0;
	struct hostent*pp=gethostbyname(0);
	int i=0;
	#ifdef _WIN32
	for(;pp!=0 && pp->h_addr_list[i]!=0;i++){
	#else
	for(;pp!=0 && (pp->h_addr_list+i)!=0;i++){
	#endif
		#ifdef _WIN32
		if( (pp->h_addr_list[i][0]&0x00ff)==169 )continue;
		#else
		if( ((uint8_t)(pp->h_addr_list+i)&0x00ff)==169 )continue;
		#endif
		#ifdef _WIN32
		unsigned char*p=(unsigned char*)&ip;
		*(p+3)=(pp->h_addr_list[i][3]&0x00ff);
		*(p+2)=(pp->h_addr_list[i][2]&0x00ff);
		*(p+1)=(pp->h_addr_list[i][1]&0x00ff);
		*(p)=(pp->h_addr_list[i][0]&0x00ff);
		#else
		ip=SWAP_32(pp->h_addr_list+i);
		#endif
		return ip;
	}
	return 0;
}