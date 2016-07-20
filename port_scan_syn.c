#include "port_scan_syn.h"

//校验盒子，每个ip占用一个，若同时扫描1000个ip则占用8MB内存
typedef struct tag_checkbox{
	uint32_t send_end_time;//该ip全端口syn包发送完毕的本地时间戳，初始为0
	uint32_t server_ip;
	uint32_t recv_num;//单位检查时间(10秒)内收到的包数，当该值<20时重置盒子
	uint8_t ports[8192];//65535位，对应端口号
}CHECKBOX;

//发射器
typedef struct tag_sender{
	int socket_send;//发送socket
	IP_HEADER ip_header;
	TCP_HEADER tcp_header;
	PSD_HEADER psd_header;
	uint8_t sendbuf[64];//发送缓冲区
}SENDERX;

//待扫描ip结构
typedef struct tag_ip_obj{
	//uint8_t type_all_65535;//扫描方式
	//uint32_t server_ip;//待扫描的ip
	unsigned char bit_5[5];
}IPx;

//全局变量
uint32_t local_ip;//本地ip
int socket_recv;//接收socket
CHECKBOX*boxs;//校验盒子池指针，堆，需要free
uint32_t boxs_num;//盒子总数
uint32_t boxs_num_busy;//被占用的盒子总数
int all_ip_num;//需要探测的ip总数
SENDERX sends[2];//主发射器 + 重试发射器
//#define TIME_WITE 30000   //未返回封包等待时长
int TIME_WITE;
static const uint8_t b_list_to_1[8]={0b10000000,0b01000000,0b00100000,0b00010000,0b00001000,0b00000100,0b00000010,0b00000001};
static const uint8_t b_list_to_0[8]={0b01111111,0b10111111,0b11011111,0b11101111,0b11110111,0b11111011,0b11111101,0b11111110};
#define b_list_get b_list_to_1  //取某一位的码表
//常见代理端口
//static const uint32_t proxy_port_list[]={10000,10030,10034,10052,10080,10240,11095,11650,11736,11825,1209,123,1234,12345,1237,12483,12638,12640,12944,12945,12946,13063,13243,1337,13389,13669,13789,14432,14826,14856,15238,15275,15692,16107,16158,16385,16515,17130,17183,17403,17449,17657,17945,18000,18080,18088,18186,18204,18253,18256,18350,18378,18392,18888,18899,18943,19279,193,19305,19327,19328,19329,19988,20093,20771,20912,2096,21320,21571,21724,21725,23245,23251,23684,23685,2429,24379,24524,24599,24809,25085,254,26384,2659,27,28361,29037,29786,29832,309,3121,3127,3128,3130,3198,32844,33389,33719,3389,33919,33925,33942,33944,33948,33965,33976,33987,34015,34032,34034,34043,34061,34484,35010,35098,37564,4048,443,4444,4593,5992,628,63000,6609,734,7808,80,800,808,8000,8001,8003,8008,8019,8021,8029,8030,8032,8035,8039,8043,8047,8050,8059,8060,8061,8065,8076,808,8080,8081,8082,8083,8084,8085,8086,8088,8089,8090,8092,8094,8099,81,8100,8103,8106,8108,811,8110,8111,8112,8115,8117,8118,8123,8124,8125,8127,8131,8139,8150,8160,8161,8162,8172,8188,8199,82,8202,8207,8214,8219,8225,8252,8254,8265,8274,8281,83,8310,8337,8343,84,8408,8429,85,8518,8542,86,867,87,8765,88,888,8888,8899,8948,90,9000,9003,9009,9018,9080,9090,9092,9364,9426,9561,965,9789,9797,9851,9876,9888,9989,9999};//21,22,
static const uint32_t proxy_port_list[]={10001,10034,10052,12345,13621,18000,18186,2345,23456,3128,3129,3130,3333,3456,34567,37564,4444,5555,4567,45678,5678,56789,63000,64321,6666,7003,8008,808,8080,8088,8090,81,8118,8123,8128,82,84,843,85,87,8888,90,9000,9090,9797,9999};//22,80
#define IP_LIST_MAX 100000000
IPx ip_list[IP_LIST_MAX];//一次扫描100w个ip占4.7MB内存。1亿占内存470MB
FILE*f_out;//扫描结果文件句柄
char logstring[1024]={0};//日志缓冲字符

//发射执行函数，仅用于单线程，发送syn包，成功返回1，失败返回负数
//该ip使用盒子指针、发射器指针、服务器端口、是否为重发(1则不重写端口所在位)
int send_syn(CHECKBOX*box,SENDERX*sender,uint16_t server_port,int is_resend){
	struct sockaddr_in dest;
	//(sender->ip_header).checksum=0; //16位IP首部校验和【需要填充】
	(sender->ip_header).destIP=(box->server_ip); //32位目的IP地址【需要填充】
	(sender->tcp_header).th_dport=htons(server_port); //服务器端口号，htons(port)【需要填充】
	//(sender->tcp_header).th_sum=0; //校验和【需要填充】
	(sender->psd_header).daddr=(box->server_ip);//32位目的IP地址【需要填充】
	//变量：远端端口、远端ip
	memset(&dest,0,sizeof(dest));
	dest.sin_family=AF_INET;
	dest.sin_addr.s_addr=(box->server_ip);//32位目的IP地址【需要填充】
	dest.sin_port=htons(server_port);//服务器端口号，htons(port)【需要填充】
	
	//本地ip，解决ADSL换ip问题
	(sender->ip_header).sourceIP=local_ip; //32位源IP地址
	(sender->psd_header).saddr=local_ip;
	//随机TTL
	(sender->ip_header).ttl=mm_rand(66,251); //8位生存时间TTL  64
	
	//随机本地ip，攻击效果
		/*开源时已删除*/
	
	//计算TCP校验和
	memcpy((sender->sendbuf),&(sender->psd_header),sizeof(PSD_HEADER));
	memcpy((sender->sendbuf)+sizeof(PSD_HEADER),&(sender->tcp_header),sizeof(TCP_HEADER));
	memset((sender->sendbuf)+27,0,8);
	(sender->tcp_header).th_sum=checksum((uint16_t*)(sender->sendbuf),sizeof(PSD_HEADER)+sizeof(TCP_HEADER));
	//计算IP校验和
	memcpy((sender->sendbuf),&(sender->ip_header),sizeof(IP_HEADER));
	memcpy((sender->sendbuf)+sizeof(IP_HEADER),&(sender->tcp_header),sizeof(TCP_HEADER));
	memset((sender->sendbuf)+sizeof(IP_HEADER)+sizeof(TCP_HEADER),0,4);
	int datasize=sizeof(IP_HEADER)+sizeof(TCP_HEADER);
	(sender->ip_header).checksum=checksum((uint16_t*)(sender->sendbuf),datasize);
	//填充发送缓冲区
	memcpy((sender->sendbuf),&(sender->ip_header),sizeof(IP_HEADER));
	//发送
	int n=sendto((sender->socket_send),(sender->sendbuf),datasize,0,(struct sockaddr*)&dest,sizeof(dest));
	if(n<1)return -1;
	
	//设置 CHECKBOX 中对应位为 1
	if(is_resend==0)((box->ports)[(server_port-1)>>3])|=(b_list_to_1[(server_port-1)&7]);
	//printf("发送完毕,置对应位为1的结果:%d\n",(((box->ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7])));
	return 1;
}

//type_all_65535=1向ip发送1~65535端口的syn包
//type_all_65535=0向ip发送 proxy_port_list 端口的syn包
//单线程，返回发送成功的次数，失败返回负数
int send_syn_all(uint32_t server_ip,uint8_t type_all_65535){
	CHECKBOX*box;
	int i;
	uint16_t server_port;
	//通过ip找到对应盒子
	for(i=0;i<boxs_num;i++){
		if((boxs[i].server_ip)==server_ip){
			box=&(boxs[i]);
			goto goto_send_ing;
		}
	}
	//新分配box
	for(i=0;i<boxs_num;i++){
		if((boxs[i].server_ip)==0){
			boxs[i].server_ip=server_ip;
			box=&(boxs[i]);
			lock_inc(boxs_num_busy);//原子
			goto goto_send_ing;
		}
	}
	//盒子池已满
	//printf("box full :(\n");
	return -1;
	//发送封包
	goto_send_ing:
	if(type_all_65535==0){
		(box->recv_num)=server_port=sizeof(proxy_port_list)/4;//记录空格子数
		//printf("proxy_port_list:%d\n",server_port);
		while(server_port--){
			//if(proxy_port_list[server_port]==0)continue;
			//printf("%d:%d\n",server_port,proxy_port_list[server_port]);
			send_syn(box,&sends[0],proxy_port_list[server_port],0);
			//system("pause");
		}
	}else{
		(box->recv_num)=server_port=65536;//记录空格子数
		while(--server_port){
			send_syn(box,&sends[0],server_port,0);
		}
	}
	//设置发送完毕时间戳
	(box->send_end_time)=(TIME_WITE+mm_server_time_get_s());//等待10秒接收数据包
	//(box->recv_num)=65535;//记录空格子数
	return 1;
}

//设置发射器socket属性
void socket_send_setsockopt(int socket_send,uint32_t sentbuf_num){
	//socket头部可编辑
	int bOpt=1;
	setsockopt(socket_send,IPPROTO_IP,2,(char*)&bOpt,sizeof(bOpt));//IP_HDRINCL==2
	//关闭延迟发送
	int on_nagle=1;
	setsockopt(socket_send,IPPROTO_TCP,TCP_NODELAY,(void*)&on_nagle,sizeof(int));
	//设置非阻塞
	//int ul=1;
	//ioctlsocket(socket_send,FIONBIO,(unsigned long*)&ul);
	//设置发送缓冲区大小，默认为8688
	int nSentBuf=sentbuf_num;//400000  1310700  2621400
	setsockopt(socket_send,SOL_SOCKET,SO_SNDBUF,(char*)&nSentBuf,sizeof(int));
    //禁用keepalive检测
    int keepalive_tag=0;
    setsockopt(socket_send,SOL_SOCKET,SO_KEEPALIVE,(void*)&keepalive_tag,sizeof(int));
}

//监听线程
int thread_listen(int thread_id){
	//接收数据
	char ip_string[16];
	char buff[80];
	int i,open=0;
	IP_HEADER*pIPHdr;
	TCP_HEADER*ptcp;
	uint32_t server_port;
	char write_buf[24];//写出ip:端口缓冲区
	char write_port[6];//端口字符串
	while(1){
		do{
			goto_head:
			while(recv(socket_recv,buff,80,0)<1);
			pIPHdr=(IP_HEADER*)buff;
			if(pIPHdr->proto!=6)goto goto_head;//TCP封包==6
			ptcp=(TCP_HEADER*)(buff+sizeof(IP_HEADER));
		}while(ptcp->th_dport!=SWAP_16(PORTL) || ntohl(ptcp->th_ack)!=(SEQ+1));
		
		//SYN Cookie 防护会回复随机 th_seq ，回复ack=seq+1破解
		//SYN Reset  防护会回复随机 th_ack ，回复携带ack的rst将自己列入白名单
		
		//自动对抗防火墙
			/*开源时已删除*/
		
		server_port=SWAP_16(ptcp->th_sport);//if(server_port>35535 || server_port<1)continue;//取出端口号
		if(((ptcp->th_flag)&0x04)==0x04){//RST 端口未开放
			for(i=0;i<boxs_num;i++){
				if((boxs[i].server_ip)==(pIPHdr->sourceIP)){//通过ip找到对应盒子
					//printf("Log>>>置对应盒子中端口位置为0.  ip=%u  port=%u\n",(boxs[i].server_ip),server_port);
					(boxs[i].ports)[(server_port-1)>>3]&=b_list_to_0[(server_port-1)&7];//置对应盒子中端口位置为0
					//printf("syn置对应位为0的结果:%d\n",(((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7])));
					goto goto_head;
				}
			}
		}else if(((ptcp->th_flag)&0x02)==0x02){//SYN 端口开放
			//发送 RST 包
			for(i=0;i<boxs_num;i++){
				if((boxs[i].server_ip)==(pIPHdr->sourceIP)){//通过ip找到对应盒子
					if((((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7]))>0){//若所在位为1则记录开放的ip和端口信息
						mm_server_ip_uint32_to_ipv4_string((uint32_t)(pIPHdr->sourceIP),ip_string);
						
						memset(write_buf,0,24);
						strcat(write_buf,ip_string);
						strcat(write_buf,":");
						mm_server_itoa(server_port,write_port,0);
						strcat(write_buf,write_port);
						strcat(write_buf,"\n");
						fwrite(write_buf,strlen(write_buf),1,f_out);
						fflush(f_out);
						printf(">>>>>%s",write_buf);
						
						//printf("%d■■■■■■ %s:%d\n",thread_id,ip_string,server_port);
						//printf("Log>>>置对应盒子中端口位置为0.  ip=%u  port=%u\n",(boxs[i].server_ip),server_port);
						(boxs[i].ports)[(server_port-1)>>3]&=b_list_to_0[(server_port-1)&7];//置对应盒子中端口位置为0
						//printf("rst置对应位为0的结果:%d\n",(((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7])));
						goto goto_head;
					}
				}
			}
		}
	}
}

//1秒扫描一次完全发送完毕的盒子，对位值为1的端口执行重发封包
int thread_recheck(int var){
	uint32_t i;
	uint32_t timenow;
	uint32_t server_port;
	char ip_string[16];
	uint32_t resend_num;//本次重发端口数
	while(1){
		//刷新本地ip
		local_ip=get_local_ip();
		//扫描
		Sleep(2000);
		timenow=mm_server_time_get_s();
		for(i=0;i<boxs_num;i++){
			if((boxs[i].send_end_time)==0 || (boxs[i].send_end_time)>timenow)continue;
			//判断1~65535端口为1的位
			server_port=65536;
			resend_num=0;
			//计算需要重发的端口数
			while(--server_port){
				if((((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7]))>0)++resend_num;
			}
			//验证是否重置盒子
			if(resend_num>0){
				//printf("需要重发 %d 个端口 [%d]\n",resend_num,((boxs[i].recv_num)-resend_num));
				(boxs[i].send_end_time)=(TIME_WITE+timenow);//更新时间戳
				//if((boxs[i].recv_num)==0)goto set_the_recv_num;
				if((boxs[i].recv_num)-resend_num<1)goto reset_the_box;//单位时间内最少回应1个有效包，否则放弃任务
				//set_the_recv_num:
				(boxs[i].recv_num)=resend_num;//记录当前的空格子数
			}else{
				reset_the_box:
				memset(&(boxs[i]),0,sizeof(CHECKBOX));//重置盒子
				//printf("重置盒子:%d\n",i);
				//--boxs_num_busy;
				lock_dec(boxs_num_busy);//原子自减
				continue;
			}
			//重发
			server_port=65536;
			while(--server_port){
				if((((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7]))>0){
					//重发syn包
					//mm_server_ip_uint32_to_ipv4_string(boxs[i].server_ip,ip_string);
					//printf("%d >> ",(((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7])));
					//printf("重发端口 %s:%d\n",ip_string,server_port);
					send_syn(&(boxs[i]),&sends[1],server_port,1);
				}
			}
			timenow=mm_server_time_get_s();
		}
	}
}

//初始化：本地ip、盒子池、发送/接收socket、创建监听线程池
// box_num 同时扫描的ip数(校验盒子数,1~65535),建议1000(8MB内存占用)的倍数
//若 box_num=65025 可同时扫描 192.168.x.x 网段,内存消耗 255*255*8/1024=508MB
//若 box_num=255   可同时扫描 192.168.1.x 网段,内存消耗 255*8/1024=2MB
// sentbuf_num 为发送缓冲区字节数，根据上行网速设置，1Mb带宽上行为128KB则设置此值为(128/2)=64KB=65536，1MB上传则为1024/2=512KB=524288
// thread_listen_num 为监听线程数量，为0时指(cpu核数*2+2)
// ip_string_in 强制指定来源ip，0为自动获取，型如 192.168.1.1 的字符串，-1为随机(产生攻击效果)
//失败返回负数，成功返回1
int port_scan_syn_init(uint16_t box_num,uint32_t sentbuf_num,uint16_t thread_listen_num,char*ip_string_in){
	#ifdef _WIN32
	WSADATA wsdata;
	WSAStartup(0x0101,&wsdata);//WSAStartup(0x0202,&wsdata);
	#endif
	uint32_t ip=0;
	if(ip_string_in==0){
		//获取本地ip
		ip=get_local_ip();
		if(ip==0){
			printf("获取本地ip失败.\n");
			return -1;
		}
		char*outss[16]={0};
		mm_server_ip_uint32_to_ipv4_string(ip,outss);
		printf("ip:%s\t%x\n",outss,ip);
	}else{
		//ADSL的ip获取错误
		ip=ip2int(ip_string_in,0);
	}
	local_ip=ip;
	//初始化box池
	boxs=(CHECKBOX*)malloc(sizeof(CHECKBOX)*box_num);
	if(boxs<1){printf("err malloc boxs\n");return -2;}
	memset(boxs,0,sizeof(CHECKBOX)*box_num);
	boxs_num=box_num;
	boxs_num_busy=0;
	
	//初始化接收socket
	socket_recv=socket(AF_INET,SOCK_RAW,IPPROTO_IP);
	if(socket_recv<1){printf("err socket_recv\n");free(boxs);return -3;}
	//设置接收缓冲区
	int nRecvBuf=2097152;//2MB
	setsockopt(socket_recv,SOL_SOCKET,SO_RCVBUF,(char*)&nRecvBuf,sizeof(int));
	
	//初始化主发射器 sends[0] 和 sends[1]
	memset(sends,0,sizeof(SENDERX)*2);
	//填充数据
	(sends[0].ip_header).h_lenver=(4<<4 | sizeof(IP_HEADER)/sizeof(unsigned long));
	(sends[0].ip_header).total_len=htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER));
	(sends[0].ip_header).ident=1;//16位标识 htons(17393);
	(sends[0].ip_header).frag_and_flags=0x40; //3位标志位,Do not fragment
	(sends[0].ip_header).ttl=64; //8位生存时间TTL
	(sends[0].ip_header).proto=IPPROTO_TCP; //8位协议(TCP,UDP…)
	(sends[0].ip_header).checksum=0; //16位IP首部校验和
	(sends[0].ip_header).sourceIP=ip; //32位源IP地址
	(sends[0].ip_header).destIP=0; //32位目的IP地址【需要填充】
    //填充TCP首部
	(sends[0].tcp_header).th_sport=htons(PORTL);//源端口号
	(sends[0].tcp_header).th_dport=0; //服务器端口号，htons(port)【需要填充】
	(sends[0].tcp_header).th_lenres=(sizeof(TCP_HEADER)/4<<4|0); //TCP长度和保留位
	(sends[0].tcp_header).th_win=htons(16384);//滑动窗口尺寸
	(sends[0].tcp_header).th_seq=htonl(SEQ); //SYN序列号
	(sends[0].tcp_header).th_ack=0; //ACK序列号置为0
	(sends[0].tcp_header).th_flag=2; //SYN 标志
	(sends[0].tcp_header).th_urp=0; //偏移
	(sends[0].tcp_header).th_sum=0; //校验和
    //填充TCP伪首部（用于计算校验和，并不真正发送）
	(sends[0].psd_header).saddr=ip;
	(sends[0].psd_header).daddr=0;//32位目的IP地址【需要填充】
	(sends[0].psd_header).mbz=0;
	(sends[0].psd_header).ptcl=IPPROTO_TCP;
	(sends[0].psd_header).tcpl=htons(sizeof(TCP_HEADER));
	//拷贝
	memcpy(&sends[1],&sends[0],sizeof(SENDERX));
	//填充独立数据
	(sends[0].socket_send)=socket(AF_INET,SOCK_RAW,IPPROTO_IP);
	(sends[1].socket_send)=socket(AF_INET,SOCK_RAW,IPPROTO_IP);
	if((sends[0].socket_send)<1||(sends[1].socket_send)<1){printf("err socket_send\n");free(boxs);return -4;}
	socket_send_setsockopt((sends[0].socket_send),sentbuf_num);
	socket_send_setsockopt((sends[1].socket_send),sentbuf_num);
	//绑定监听socket
	struct sockaddr_in addr_in;
	addr_in.sin_family=AF_INET;// AF_PACKET==17 则不会添加ip。 AF_INET 会添加
	addr_in.sin_port=htons(PORTL);//htons(0);

	#ifdef _WIN32
	addr_in.sin_addr.S_un.S_addr=ip;//inet_addr("192.168.0.1");   htonl(INADDR_ANY);
	#else
	addr_in.sin_addr.s_addr=ip;//SWAP_32(add.sin_addr.s_addr)
	#endif

	//addr_in.sin_addr.S_un.S_addr=htonl(INADDR_ANY);
	int zz=bind(socket_recv,(struct sockaddr*)&addr_in,sizeof(addr_in));
	if(zz<0){printf("err bind:%d]\n",WSAGetLastError());free(boxs);return -5;}
	//设置接收全部封包
	int dwValue=1;
	zz=ioctlsocket(socket_recv,SIO_RCVALL,&dwValue);//-1744830463
	if(zz<0)printf("err SIO_RCVALL:%d\n",WSAGetLastError());//10022
	//创建监听线程池
	int n=thread_listen_num;
	if(thread_listen_num==0){n=atoi(getenv("NUMBER_OF_PROCESSORS"));if(n<1)n=1;n=n*2+2;}//cpu数量
	printf("监听线程数:%d\n",n);
	int z;
	for(;n--;){
		z=_beginthreadex(0,0,(void*)&thread_listen,n,0,0);
		#ifdef _WIN32
		if(z>0)CloseHandle((HANDLE)z);
		#endif
	}
	//创建机器人线程
	z=_beginthreadex(0,0,(void*)&thread_recheck,0,0,0);
	#ifdef _WIN32
	if(z>0)CloseHandle((HANDLE)z);
	#endif
	return 1;
}

//将ip加入待测试链表
void add_ip_to_list(uint32_t ip,uint8_t type_all_65535){
	//节约内存
	(ip_list[all_ip_num].bit_5)[0]=type_all_65535;
	*(uint32_t*)((ip_list[all_ip_num].bit_5)+1)=SWAP_32(ip);
	
	++all_ip_num;
	if(all_ip_num>IP_LIST_MAX){
		printf("待处理ip数溢出.即将退出.最大值为:%u\n",IP_LIST_MAX);
		system("pause");
		exit(0);
	}
}

//分割字符串回调函数，单线程
int do_f(char*s,int times){
	const char out[1024]={0};
	mm_string_trim(s,out,1);
	if(strlen(out)==0 || (out[0]=='/'&&out[1]=='/'))return 0;//过滤：空行、注释
	int where_dh=mm_string_strstr(out,",",7);//逗号位置
	if(where_dh==-1)return 0;//过滤：无逗号
	//printf("%d:%s\n",times,out);
	//printf("1:%s\n",out);
	//42.123.91.1-42.123.91.255,0
	//106.187.89.210,65535
	//42.123.0.1-42.123.90.255,0
	//解析扫描模式 type_all_65535
	char*type_p=out+where_dh+1;
	*(type_p-1)=0;
	uint8_t type_all_65535;
	if(strcmp(type_p,"0")==0){//简单扫描
		type_all_65535=0;
	}else if(strcmp(type_p,"65535")==0){//完全扫描
		type_all_65535=1;
	}else{
		return 0;
	}
	//解析ip
	int where_jh=mm_string_strstr(out,"-",7);//减号"-"的位置
	char*ip_end;
	if(where_jh==-1){//单ip
		//printf("ip:%s|\n\n",out);
		add_ip_to_list(ip2int(out,1),type_all_65535);
	}else{//ip段
		ip_end=out+where_jh+1;
		*(ip_end-1)=0;
		uint32_t ip_start_int=ip2int(out,1);
		uint32_t ip_end_int=ip2int(ip_end,1);
		//printf("ip1:%s|\nip2:%s|\n%u-%u\n\n",out,ip_end,ip_start_int,ip_end_int);
		for(;ip_end_int>=ip_start_int;ip_end_int--){
			//printf(">>ip:%u\n",ip_end_int);
			add_ip_to_list(ip_end_int,type_all_65535);
		}
	}
	return 0;
}

int main(int argc, char const *argv[]){
	//portscan -IN 北京ip列表.txt -OUT 北京端口.txt -SOCKET_CACHE 524288 -BOX_NUM 255
	//
	//输入:
	//ip或ip段,0=常见代理端口/65535=全端口
	//42.123.91.1-42.123.91.255,0
	//106.187.89.210,65535
	//
	//结果:
	//20140518 12:01:53 //开始时间
	//20140518 13:22:05 //结束时间
	//42.123.91.1:80
	//42.123.91.1:8080
	//42.123.91.10:3389
	
	//printf("参数量:%d\n",argc);
	if(argc<9){
		//printf("用法:\nportscan -IN 北京ip列表.txt -OUT 北京端口.txt -SOCKET_CACHE 524288 -BOX_NUM 255\n");
		return 1;
	}
	
	//输出开始时间
	char time_string_start[18]={0};
	mm_time_get_formatstring(0,0,time_string_start,"%Y%m%d %H:%M:%S");
	printf("\n------------------------------------------------------------\n%s\n",time_string_start);
	
	//录入参数
	char*file_in;
	char*file_out;
	uint32_t sentbuf_n;
	uint16_t box_n;
	int i=0;
	char*in_ip_string=0;
	TIME_WITE=30000;
	for(;i<argc;i++){
		//printf("%d\t%s\n",strcmp("-IN",argv[i]),argv[i]);
		if(0==strcmp("-IN",argv[i])){
			file_in=argv[i+1];
		}else if(0==strcmp("-OUT",argv[i])){
			file_out=argv[i+1];
		}else if(0==strcmp("-SOCKET_CACHE",argv[i])){
			sentbuf_n=atoi(argv[i+1]);
		}else if(0==strcmp("-BOX_NUM",argv[i])){
			box_n=atoi(argv[i+1]);
		}else if(0==strcmp("-IP",argv[i])){
			if(strcmp(argv[i+1],"x")==0){
				in_ip_string=-1;
				printf("随机发送端ip开启.\n");
			}else if(strcmp(argv[i+1],"0")==0){
				in_ip_string=0;
				printf("自动获取发送端ip.\n");
			}else{
				in_ip_string=argv[i+1];
				printf("固定发送端ip:%s\n",in_ip_string);
			}
		}else if(0==strcmp("-TIMEOUT",argv[i])){
			TIME_WITE=atoi(argv[i+1]);
		}
	}
	printf("\n输入 = %s\n",file_in);
	printf("输出 = %s\n",file_out);
	printf("缓存 = %u\n",sentbuf_n);
	printf("超时 = %d\n",TIME_WITE);
	printf("盒子 = %u\n\n",box_n);
	//将结果写入文件
	char wtype[]="ab+";//追加
	f_out=fopen(file_out,wtype);
	if(f_out==0){
		printf("打开写出结果文件出错!\n");
		return -1;
	}
	fwrite(time_string_start,strlen(time_string_start),1,f_out);//写入开始时间
	fwrite("\n\n",2,1,f_out);
	
	memset(logstring,0,sizeof(logstring));
	strcat(logstring,"输入 = ");strcat(logstring,file_in);
	strcat(logstring,"\n输出 = ");strcat(logstring,file_out);
	char itoa_c[11]={0};
	strcat(logstring,"\n缓存 = ");mm_server_itoa(sentbuf_n,itoa_c,0);strcat(logstring,itoa_c);
	strcat(logstring,"\n超时 = ");mm_server_itoa(TIME_WITE,itoa_c,0);strcat(logstring,itoa_c);
	strcat(logstring,"\n盒子 = ");mm_server_itoa(box_n,itoa_c,0);strcat(logstring,itoa_c);
	fwrite(logstring,strlen(logstring),1,f_out);
	
	//初始化，监听线程数=cpu核数*2+2
	port_scan_syn_init(box_n,sentbuf_n,0,in_ip_string);
	memset(&ip_list,0,sizeof(ip_list));
	printf("初始化完毕!ip_list:%u\n\n",sizeof(ip_list));
	
	//读入输入文件
	char*tmp=malloc(1024);
	mm_file_readall(file_in,&tmp,1024);
	//printf("%s\n",tmp);
	//换行符分割
	all_ip_num=0;
	mm_string_explode(tmp,"\n",&do_f);
	printf("总需要探测的ip数:%u\n",all_ip_num);
	free(tmp);
	
	memset(logstring,0,sizeof(logstring));
	strcat(logstring,"\n总需要探测的ip数:");mm_server_itoa(all_ip_num,itoa_c,0);strcat(logstring,itoa_c);strcat(logstring,"\n");
	fwrite(logstring,strlen(logstring),1,f_out);
	//fwrite("\n",1,1,f_out);
	fflush(f_out);
	
	if(--all_ip_num<0)return 1;
	
	//将待测试ip链表内容压入发射器，队列空退出，盒子满等待3秒
	while(all_ip_num>=0){//待测试ip数量>0
		//printf(">>>>ip:%u\n",ip_list[all_ip_num].server_ip);
		//if(send_syn_all(ip_list[all_ip_num].server_ip,ip_list[all_ip_num].type_all_65535)<0){//盒子满
		if(send_syn_all(*(uint32_t*)((ip_list[all_ip_num].bit_5)+1),(ip_list[all_ip_num].bit_5)[0])<0){//盒子满
			Sleep(3000);
		}else{
			char ip_string[16];
			mm_server_ip_uint32_to_ipv4_string(*(uint32_t*)((ip_list[all_ip_num].bit_5)+1),ip_string);
			//printf("投递成功: %s\t%u\n",ip_string,all_ip_num);
			--all_ip_num;
		}
	}
	//等待盒子全空
	printf("当前使用盒子数:%u\n最后等待盒子全空...\n",boxs_num_busy);
	while(boxs_num_busy>0)Sleep(3000);
	
	//写结束时间
	mm_time_get_formatstring(0,0,time_string_start,"%Y%m%d %H:%M:%S");
	fwrite(time_string_start,strlen(time_string_start),1,f_out);//结束时间
	fwrite("\n\n",2,1,f_out);
	fclose(f_out);
	return 1;
}

