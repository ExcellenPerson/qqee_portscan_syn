#include "port_scan_syn.h"

//У����ӣ�ÿ��ipռ��һ������ͬʱɨ��1000��ip��ռ��8MB�ڴ�
typedef struct tag_checkbox{
	uint32_t send_end_time;//��ipȫ�˿�syn��������ϵı���ʱ�������ʼΪ0
	uint32_t server_ip;
	uint32_t recv_num;//��λ���ʱ��(10��)���յ��İ���������ֵ<20ʱ���ú���
	uint8_t ports[8192];//65535λ����Ӧ�˿ں�
}CHECKBOX;

//������
typedef struct tag_sender{
	int socket_send;//����socket
	IP_HEADER ip_header;
	TCP_HEADER tcp_header;
	PSD_HEADER psd_header;
	uint8_t sendbuf[64];//���ͻ�����
}SENDERX;

//��ɨ��ip�ṹ
typedef struct tag_ip_obj{
	//uint8_t type_all_65535;//ɨ�跽ʽ
	//uint32_t server_ip;//��ɨ���ip
	unsigned char bit_5[5];
}IPx;

//ȫ�ֱ���
uint32_t local_ip;//����ip
int socket_recv;//����socket
CHECKBOX*boxs;//У����ӳ�ָ�룬�ѣ���Ҫfree
uint32_t boxs_num;//��������
uint32_t boxs_num_busy;//��ռ�õĺ�������
int all_ip_num;//��Ҫ̽���ip����
SENDERX sends[2];//�������� + ���Է�����
//#define TIME_WITE 30000   //δ���ط���ȴ�ʱ��
int TIME_WITE;
static const uint8_t b_list_to_1[8]={0b10000000,0b01000000,0b00100000,0b00010000,0b00001000,0b00000100,0b00000010,0b00000001};
static const uint8_t b_list_to_0[8]={0b01111111,0b10111111,0b11011111,0b11101111,0b11110111,0b11111011,0b11111101,0b11111110};
#define b_list_get b_list_to_1  //ȡĳһλ�����
//��������˿�
//static const uint32_t proxy_port_list[]={10000,10030,10034,10052,10080,10240,11095,11650,11736,11825,1209,123,1234,12345,1237,12483,12638,12640,12944,12945,12946,13063,13243,1337,13389,13669,13789,14432,14826,14856,15238,15275,15692,16107,16158,16385,16515,17130,17183,17403,17449,17657,17945,18000,18080,18088,18186,18204,18253,18256,18350,18378,18392,18888,18899,18943,19279,193,19305,19327,19328,19329,19988,20093,20771,20912,2096,21320,21571,21724,21725,23245,23251,23684,23685,2429,24379,24524,24599,24809,25085,254,26384,2659,27,28361,29037,29786,29832,309,3121,3127,3128,3130,3198,32844,33389,33719,3389,33919,33925,33942,33944,33948,33965,33976,33987,34015,34032,34034,34043,34061,34484,35010,35098,37564,4048,443,4444,4593,5992,628,63000,6609,734,7808,80,800,808,8000,8001,8003,8008,8019,8021,8029,8030,8032,8035,8039,8043,8047,8050,8059,8060,8061,8065,8076,808,8080,8081,8082,8083,8084,8085,8086,8088,8089,8090,8092,8094,8099,81,8100,8103,8106,8108,811,8110,8111,8112,8115,8117,8118,8123,8124,8125,8127,8131,8139,8150,8160,8161,8162,8172,8188,8199,82,8202,8207,8214,8219,8225,8252,8254,8265,8274,8281,83,8310,8337,8343,84,8408,8429,85,8518,8542,86,867,87,8765,88,888,8888,8899,8948,90,9000,9003,9009,9018,9080,9090,9092,9364,9426,9561,965,9789,9797,9851,9876,9888,9989,9999};//21,22,
static const uint32_t proxy_port_list[]={10001,10034,10052,12345,13621,18000,18186,2345,23456,3128,3129,3130,3333,3456,34567,37564,4444,5555,4567,45678,5678,56789,63000,64321,6666,7003,8008,808,8080,8088,8090,81,8118,8123,8128,82,84,843,85,87,8888,90,9000,9090,9797,9999};//22,80
#define IP_LIST_MAX 100000000
IPx ip_list[IP_LIST_MAX];//һ��ɨ��100w��ipռ4.7MB�ڴ档1��ռ�ڴ�470MB
FILE*f_out;//ɨ�����ļ����
char logstring[1024]={0};//��־�����ַ�

//����ִ�к����������ڵ��̣߳�����syn�����ɹ�����1��ʧ�ܷ��ظ���
//��ipʹ�ú���ָ�롢������ָ�롢�������˿ڡ��Ƿ�Ϊ�ط�(1����д�˿�����λ)
int send_syn(CHECKBOX*box,SENDERX*sender,uint16_t server_port,int is_resend){
	struct sockaddr_in dest;
	//(sender->ip_header).checksum=0; //16λIP�ײ�У��͡���Ҫ��䡿
	(sender->ip_header).destIP=(box->server_ip); //32λĿ��IP��ַ����Ҫ��䡿
	(sender->tcp_header).th_dport=htons(server_port); //�������˿ںţ�htons(port)����Ҫ��䡿
	//(sender->tcp_header).th_sum=0; //У��͡���Ҫ��䡿
	(sender->psd_header).daddr=(box->server_ip);//32λĿ��IP��ַ����Ҫ��䡿
	//������Զ�˶˿ڡ�Զ��ip
	memset(&dest,0,sizeof(dest));
	dest.sin_family=AF_INET;
	dest.sin_addr.s_addr=(box->server_ip);//32λĿ��IP��ַ����Ҫ��䡿
	dest.sin_port=htons(server_port);//�������˿ںţ�htons(port)����Ҫ��䡿
	
	//����ip�����ADSL��ip����
	(sender->ip_header).sourceIP=local_ip; //32λԴIP��ַ
	(sender->psd_header).saddr=local_ip;
	//���TTL
	(sender->ip_header).ttl=mm_rand(66,251); //8λ����ʱ��TTL  64
	
	//�������ip������Ч��
		/*��Դʱ��ɾ��*/
	
	//����TCPУ���
	memcpy((sender->sendbuf),&(sender->psd_header),sizeof(PSD_HEADER));
	memcpy((sender->sendbuf)+sizeof(PSD_HEADER),&(sender->tcp_header),sizeof(TCP_HEADER));
	memset((sender->sendbuf)+27,0,8);
	(sender->tcp_header).th_sum=checksum((uint16_t*)(sender->sendbuf),sizeof(PSD_HEADER)+sizeof(TCP_HEADER));
	//����IPУ���
	memcpy((sender->sendbuf),&(sender->ip_header),sizeof(IP_HEADER));
	memcpy((sender->sendbuf)+sizeof(IP_HEADER),&(sender->tcp_header),sizeof(TCP_HEADER));
	memset((sender->sendbuf)+sizeof(IP_HEADER)+sizeof(TCP_HEADER),0,4);
	int datasize=sizeof(IP_HEADER)+sizeof(TCP_HEADER);
	(sender->ip_header).checksum=checksum((uint16_t*)(sender->sendbuf),datasize);
	//��䷢�ͻ�����
	memcpy((sender->sendbuf),&(sender->ip_header),sizeof(IP_HEADER));
	//����
	int n=sendto((sender->socket_send),(sender->sendbuf),datasize,0,(struct sockaddr*)&dest,sizeof(dest));
	if(n<1)return -1;
	
	//���� CHECKBOX �ж�ӦλΪ 1
	if(is_resend==0)((box->ports)[(server_port-1)>>3])|=(b_list_to_1[(server_port-1)&7]);
	//printf("�������,�ö�ӦλΪ1�Ľ��:%d\n",(((box->ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7])));
	return 1;
}

//type_all_65535=1��ip����1~65535�˿ڵ�syn��
//type_all_65535=0��ip���� proxy_port_list �˿ڵ�syn��
//���̣߳����ط��ͳɹ��Ĵ�����ʧ�ܷ��ظ���
int send_syn_all(uint32_t server_ip,uint8_t type_all_65535){
	CHECKBOX*box;
	int i;
	uint16_t server_port;
	//ͨ��ip�ҵ���Ӧ����
	for(i=0;i<boxs_num;i++){
		if((boxs[i].server_ip)==server_ip){
			box=&(boxs[i]);
			goto goto_send_ing;
		}
	}
	//�·���box
	for(i=0;i<boxs_num;i++){
		if((boxs[i].server_ip)==0){
			boxs[i].server_ip=server_ip;
			box=&(boxs[i]);
			lock_inc(boxs_num_busy);//ԭ��
			goto goto_send_ing;
		}
	}
	//���ӳ�����
	//printf("box full :(\n");
	return -1;
	//���ͷ��
	goto_send_ing:
	if(type_all_65535==0){
		(box->recv_num)=server_port=sizeof(proxy_port_list)/4;//��¼�ո�����
		//printf("proxy_port_list:%d\n",server_port);
		while(server_port--){
			//if(proxy_port_list[server_port]==0)continue;
			//printf("%d:%d\n",server_port,proxy_port_list[server_port]);
			send_syn(box,&sends[0],proxy_port_list[server_port],0);
			//system("pause");
		}
	}else{
		(box->recv_num)=server_port=65536;//��¼�ո�����
		while(--server_port){
			send_syn(box,&sends[0],server_port,0);
		}
	}
	//���÷������ʱ���
	(box->send_end_time)=(TIME_WITE+mm_server_time_get_s());//�ȴ�10��������ݰ�
	//(box->recv_num)=65535;//��¼�ո�����
	return 1;
}

//���÷�����socket����
void socket_send_setsockopt(int socket_send,uint32_t sentbuf_num){
	//socketͷ���ɱ༭
	int bOpt=1;
	setsockopt(socket_send,IPPROTO_IP,2,(char*)&bOpt,sizeof(bOpt));//IP_HDRINCL==2
	//�ر��ӳٷ���
	int on_nagle=1;
	setsockopt(socket_send,IPPROTO_TCP,TCP_NODELAY,(void*)&on_nagle,sizeof(int));
	//���÷�����
	//int ul=1;
	//ioctlsocket(socket_send,FIONBIO,(unsigned long*)&ul);
	//���÷��ͻ�������С��Ĭ��Ϊ8688
	int nSentBuf=sentbuf_num;//400000  1310700  2621400
	setsockopt(socket_send,SOL_SOCKET,SO_SNDBUF,(char*)&nSentBuf,sizeof(int));
    //����keepalive���
    int keepalive_tag=0;
    setsockopt(socket_send,SOL_SOCKET,SO_KEEPALIVE,(void*)&keepalive_tag,sizeof(int));
}

//�����߳�
int thread_listen(int thread_id){
	//��������
	char ip_string[16];
	char buff[80];
	int i,open=0;
	IP_HEADER*pIPHdr;
	TCP_HEADER*ptcp;
	uint32_t server_port;
	char write_buf[24];//д��ip:�˿ڻ�����
	char write_port[6];//�˿��ַ���
	while(1){
		do{
			goto_head:
			while(recv(socket_recv,buff,80,0)<1);
			pIPHdr=(IP_HEADER*)buff;
			if(pIPHdr->proto!=6)goto goto_head;//TCP���==6
			ptcp=(TCP_HEADER*)(buff+sizeof(IP_HEADER));
		}while(ptcp->th_dport!=SWAP_16(PORTL) || ntohl(ptcp->th_ack)!=(SEQ+1));
		
		//SYN Cookie ������ظ���� th_seq ���ظ�ack=seq+1�ƽ�
		//SYN Reset  ������ظ���� th_ack ���ظ�Я��ack��rst���Լ����������
		
		//�Զ��Կ�����ǽ
			/*��Դʱ��ɾ��*/
		
		server_port=SWAP_16(ptcp->th_sport);//if(server_port>35535 || server_port<1)continue;//ȡ���˿ں�
		if(((ptcp->th_flag)&0x04)==0x04){//RST �˿�δ����
			for(i=0;i<boxs_num;i++){
				if((boxs[i].server_ip)==(pIPHdr->sourceIP)){//ͨ��ip�ҵ���Ӧ����
					//printf("Log>>>�ö�Ӧ�����ж˿�λ��Ϊ0.  ip=%u  port=%u\n",(boxs[i].server_ip),server_port);
					(boxs[i].ports)[(server_port-1)>>3]&=b_list_to_0[(server_port-1)&7];//�ö�Ӧ�����ж˿�λ��Ϊ0
					//printf("syn�ö�ӦλΪ0�Ľ��:%d\n",(((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7])));
					goto goto_head;
				}
			}
		}else if(((ptcp->th_flag)&0x02)==0x02){//SYN �˿ڿ���
			//���� RST ��
			for(i=0;i<boxs_num;i++){
				if((boxs[i].server_ip)==(pIPHdr->sourceIP)){//ͨ��ip�ҵ���Ӧ����
					if((((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7]))>0){//������λΪ1���¼���ŵ�ip�Ͷ˿���Ϣ
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
						
						//printf("%d������������ %s:%d\n",thread_id,ip_string,server_port);
						//printf("Log>>>�ö�Ӧ�����ж˿�λ��Ϊ0.  ip=%u  port=%u\n",(boxs[i].server_ip),server_port);
						(boxs[i].ports)[(server_port-1)>>3]&=b_list_to_0[(server_port-1)&7];//�ö�Ӧ�����ж˿�λ��Ϊ0
						//printf("rst�ö�ӦλΪ0�Ľ��:%d\n",(((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7])));
						goto goto_head;
					}
				}
			}
		}
	}
}

//1��ɨ��һ����ȫ������ϵĺ��ӣ���λֵΪ1�Ķ˿�ִ���ط����
int thread_recheck(int var){
	uint32_t i;
	uint32_t timenow;
	uint32_t server_port;
	char ip_string[16];
	uint32_t resend_num;//�����ط��˿���
	while(1){
		//ˢ�±���ip
		local_ip=get_local_ip();
		//ɨ��
		Sleep(2000);
		timenow=mm_server_time_get_s();
		for(i=0;i<boxs_num;i++){
			if((boxs[i].send_end_time)==0 || (boxs[i].send_end_time)>timenow)continue;
			//�ж�1~65535�˿�Ϊ1��λ
			server_port=65536;
			resend_num=0;
			//������Ҫ�ط��Ķ˿���
			while(--server_port){
				if((((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7]))>0)++resend_num;
			}
			//��֤�Ƿ����ú���
			if(resend_num>0){
				//printf("��Ҫ�ط� %d ���˿� [%d]\n",resend_num,((boxs[i].recv_num)-resend_num));
				(boxs[i].send_end_time)=(TIME_WITE+timenow);//����ʱ���
				//if((boxs[i].recv_num)==0)goto set_the_recv_num;
				if((boxs[i].recv_num)-resend_num<1)goto reset_the_box;//��λʱ�������ٻ�Ӧ1����Ч���������������
				//set_the_recv_num:
				(boxs[i].recv_num)=resend_num;//��¼��ǰ�Ŀո�����
			}else{
				reset_the_box:
				memset(&(boxs[i]),0,sizeof(CHECKBOX));//���ú���
				//printf("���ú���:%d\n",i);
				//--boxs_num_busy;
				lock_dec(boxs_num_busy);//ԭ���Լ�
				continue;
			}
			//�ط�
			server_port=65536;
			while(--server_port){
				if((((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7]))>0){
					//�ط�syn��
					//mm_server_ip_uint32_to_ipv4_string(boxs[i].server_ip,ip_string);
					//printf("%d >> ",(((boxs[i].ports)[(server_port-1)>>3])&(b_list_get[(server_port-1)&7])));
					//printf("�ط��˿� %s:%d\n",ip_string,server_port);
					send_syn(&(boxs[i]),&sends[1],server_port,1);
				}
			}
			timenow=mm_server_time_get_s();
		}
	}
}

//��ʼ��������ip�����ӳء�����/����socket�����������̳߳�
// box_num ͬʱɨ���ip��(У�������,1~65535),����1000(8MB�ڴ�ռ��)�ı���
//�� box_num=65025 ��ͬʱɨ�� 192.168.x.x ����,�ڴ����� 255*255*8/1024=508MB
//�� box_num=255   ��ͬʱɨ�� 192.168.1.x ����,�ڴ����� 255*8/1024=2MB
// sentbuf_num Ϊ���ͻ������ֽ��������������������ã�1Mb��������Ϊ128KB�����ô�ֵΪ(128/2)=64KB=65536��1MB�ϴ���Ϊ1024/2=512KB=524288
// thread_listen_num Ϊ�����߳�������Ϊ0ʱָ(cpu����*2+2)
// ip_string_in ǿ��ָ����Դip��0Ϊ�Զ���ȡ������ 192.168.1.1 ���ַ�����-1Ϊ���(��������Ч��)
//ʧ�ܷ��ظ������ɹ�����1
int port_scan_syn_init(uint16_t box_num,uint32_t sentbuf_num,uint16_t thread_listen_num,char*ip_string_in){
	#ifdef _WIN32
	WSADATA wsdata;
	WSAStartup(0x0101,&wsdata);//WSAStartup(0x0202,&wsdata);
	#endif
	uint32_t ip=0;
	if(ip_string_in==0){
		//��ȡ����ip
		ip=get_local_ip();
		if(ip==0){
			printf("��ȡ����ipʧ��.\n");
			return -1;
		}
		char*outss[16]={0};
		mm_server_ip_uint32_to_ipv4_string(ip,outss);
		printf("ip:%s\t%x\n",outss,ip);
	}else{
		//ADSL��ip��ȡ����
		ip=ip2int(ip_string_in,0);
	}
	local_ip=ip;
	//��ʼ��box��
	boxs=(CHECKBOX*)malloc(sizeof(CHECKBOX)*box_num);
	if(boxs<1){printf("err malloc boxs\n");return -2;}
	memset(boxs,0,sizeof(CHECKBOX)*box_num);
	boxs_num=box_num;
	boxs_num_busy=0;
	
	//��ʼ������socket
	socket_recv=socket(AF_INET,SOCK_RAW,IPPROTO_IP);
	if(socket_recv<1){printf("err socket_recv\n");free(boxs);return -3;}
	//���ý��ջ�����
	int nRecvBuf=2097152;//2MB
	setsockopt(socket_recv,SOL_SOCKET,SO_RCVBUF,(char*)&nRecvBuf,sizeof(int));
	
	//��ʼ���������� sends[0] �� sends[1]
	memset(sends,0,sizeof(SENDERX)*2);
	//�������
	(sends[0].ip_header).h_lenver=(4<<4 | sizeof(IP_HEADER)/sizeof(unsigned long));
	(sends[0].ip_header).total_len=htons(sizeof(IP_HEADER)+sizeof(TCP_HEADER));
	(sends[0].ip_header).ident=1;//16λ��ʶ htons(17393);
	(sends[0].ip_header).frag_and_flags=0x40; //3λ��־λ,Do not fragment
	(sends[0].ip_header).ttl=64; //8λ����ʱ��TTL
	(sends[0].ip_header).proto=IPPROTO_TCP; //8λЭ��(TCP,UDP��)
	(sends[0].ip_header).checksum=0; //16λIP�ײ�У���
	(sends[0].ip_header).sourceIP=ip; //32λԴIP��ַ
	(sends[0].ip_header).destIP=0; //32λĿ��IP��ַ����Ҫ��䡿
    //���TCP�ײ�
	(sends[0].tcp_header).th_sport=htons(PORTL);//Դ�˿ں�
	(sends[0].tcp_header).th_dport=0; //�������˿ںţ�htons(port)����Ҫ��䡿
	(sends[0].tcp_header).th_lenres=(sizeof(TCP_HEADER)/4<<4|0); //TCP���Ⱥͱ���λ
	(sends[0].tcp_header).th_win=htons(16384);//�������ڳߴ�
	(sends[0].tcp_header).th_seq=htonl(SEQ); //SYN���к�
	(sends[0].tcp_header).th_ack=0; //ACK���к���Ϊ0
	(sends[0].tcp_header).th_flag=2; //SYN ��־
	(sends[0].tcp_header).th_urp=0; //ƫ��
	(sends[0].tcp_header).th_sum=0; //У���
    //���TCPα�ײ������ڼ���У��ͣ������������ͣ�
	(sends[0].psd_header).saddr=ip;
	(sends[0].psd_header).daddr=0;//32λĿ��IP��ַ����Ҫ��䡿
	(sends[0].psd_header).mbz=0;
	(sends[0].psd_header).ptcl=IPPROTO_TCP;
	(sends[0].psd_header).tcpl=htons(sizeof(TCP_HEADER));
	//����
	memcpy(&sends[1],&sends[0],sizeof(SENDERX));
	//����������
	(sends[0].socket_send)=socket(AF_INET,SOCK_RAW,IPPROTO_IP);
	(sends[1].socket_send)=socket(AF_INET,SOCK_RAW,IPPROTO_IP);
	if((sends[0].socket_send)<1||(sends[1].socket_send)<1){printf("err socket_send\n");free(boxs);return -4;}
	socket_send_setsockopt((sends[0].socket_send),sentbuf_num);
	socket_send_setsockopt((sends[1].socket_send),sentbuf_num);
	//�󶨼���socket
	struct sockaddr_in addr_in;
	addr_in.sin_family=AF_INET;// AF_PACKET==17 �򲻻����ip�� AF_INET �����
	addr_in.sin_port=htons(PORTL);//htons(0);

	#ifdef _WIN32
	addr_in.sin_addr.S_un.S_addr=ip;//inet_addr("192.168.0.1");   htonl(INADDR_ANY);
	#else
	addr_in.sin_addr.s_addr=ip;//SWAP_32(add.sin_addr.s_addr)
	#endif

	//addr_in.sin_addr.S_un.S_addr=htonl(INADDR_ANY);
	int zz=bind(socket_recv,(struct sockaddr*)&addr_in,sizeof(addr_in));
	if(zz<0){printf("err bind:%d]\n",WSAGetLastError());free(boxs);return -5;}
	//���ý���ȫ�����
	int dwValue=1;
	zz=ioctlsocket(socket_recv,SIO_RCVALL,&dwValue);//-1744830463
	if(zz<0)printf("err SIO_RCVALL:%d\n",WSAGetLastError());//10022
	//���������̳߳�
	int n=thread_listen_num;
	if(thread_listen_num==0){n=atoi(getenv("NUMBER_OF_PROCESSORS"));if(n<1)n=1;n=n*2+2;}//cpu����
	printf("�����߳���:%d\n",n);
	int z;
	for(;n--;){
		z=_beginthreadex(0,0,(void*)&thread_listen,n,0,0);
		#ifdef _WIN32
		if(z>0)CloseHandle((HANDLE)z);
		#endif
	}
	//�����������߳�
	z=_beginthreadex(0,0,(void*)&thread_recheck,0,0,0);
	#ifdef _WIN32
	if(z>0)CloseHandle((HANDLE)z);
	#endif
	return 1;
}

//��ip�������������
void add_ip_to_list(uint32_t ip,uint8_t type_all_65535){
	//��Լ�ڴ�
	(ip_list[all_ip_num].bit_5)[0]=type_all_65535;
	*(uint32_t*)((ip_list[all_ip_num].bit_5)+1)=SWAP_32(ip);
	
	++all_ip_num;
	if(all_ip_num>IP_LIST_MAX){
		printf("������ip�����.�����˳�.���ֵΪ:%u\n",IP_LIST_MAX);
		system("pause");
		exit(0);
	}
}

//�ָ��ַ����ص����������߳�
int do_f(char*s,int times){
	const char out[1024]={0};
	mm_string_trim(s,out,1);
	if(strlen(out)==0 || (out[0]=='/'&&out[1]=='/'))return 0;//���ˣ����С�ע��
	int where_dh=mm_string_strstr(out,",",7);//����λ��
	if(where_dh==-1)return 0;//���ˣ��޶���
	//printf("%d:%s\n",times,out);
	//printf("1:%s\n",out);
	//42.123.91.1-42.123.91.255,0
	//106.187.89.210,65535
	//42.123.0.1-42.123.90.255,0
	//����ɨ��ģʽ type_all_65535
	char*type_p=out+where_dh+1;
	*(type_p-1)=0;
	uint8_t type_all_65535;
	if(strcmp(type_p,"0")==0){//��ɨ��
		type_all_65535=0;
	}else if(strcmp(type_p,"65535")==0){//��ȫɨ��
		type_all_65535=1;
	}else{
		return 0;
	}
	//����ip
	int where_jh=mm_string_strstr(out,"-",7);//����"-"��λ��
	char*ip_end;
	if(where_jh==-1){//��ip
		//printf("ip:%s|\n\n",out);
		add_ip_to_list(ip2int(out,1),type_all_65535);
	}else{//ip��
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
	//portscan -IN ����ip�б�.txt -OUT �����˿�.txt -SOCKET_CACHE 524288 -BOX_NUM 255
	//
	//����:
	//ip��ip��,0=��������˿�/65535=ȫ�˿�
	//42.123.91.1-42.123.91.255,0
	//106.187.89.210,65535
	//
	//���:
	//20140518 12:01:53 //��ʼʱ��
	//20140518 13:22:05 //����ʱ��
	//42.123.91.1:80
	//42.123.91.1:8080
	//42.123.91.10:3389
	
	//printf("������:%d\n",argc);
	if(argc<9){
		//printf("�÷�:\nportscan -IN ����ip�б�.txt -OUT �����˿�.txt -SOCKET_CACHE 524288 -BOX_NUM 255\n");
		return 1;
	}
	
	//�����ʼʱ��
	char time_string_start[18]={0};
	mm_time_get_formatstring(0,0,time_string_start,"%Y%m%d %H:%M:%S");
	printf("\n------------------------------------------------------------\n%s\n",time_string_start);
	
	//¼�����
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
				printf("������Ͷ�ip����.\n");
			}else if(strcmp(argv[i+1],"0")==0){
				in_ip_string=0;
				printf("�Զ���ȡ���Ͷ�ip.\n");
			}else{
				in_ip_string=argv[i+1];
				printf("�̶����Ͷ�ip:%s\n",in_ip_string);
			}
		}else if(0==strcmp("-TIMEOUT",argv[i])){
			TIME_WITE=atoi(argv[i+1]);
		}
	}
	printf("\n���� = %s\n",file_in);
	printf("��� = %s\n",file_out);
	printf("���� = %u\n",sentbuf_n);
	printf("��ʱ = %d\n",TIME_WITE);
	printf("���� = %u\n\n",box_n);
	//�����д���ļ�
	char wtype[]="ab+";//׷��
	f_out=fopen(file_out,wtype);
	if(f_out==0){
		printf("��д������ļ�����!\n");
		return -1;
	}
	fwrite(time_string_start,strlen(time_string_start),1,f_out);//д�뿪ʼʱ��
	fwrite("\n\n",2,1,f_out);
	
	memset(logstring,0,sizeof(logstring));
	strcat(logstring,"���� = ");strcat(logstring,file_in);
	strcat(logstring,"\n��� = ");strcat(logstring,file_out);
	char itoa_c[11]={0};
	strcat(logstring,"\n���� = ");mm_server_itoa(sentbuf_n,itoa_c,0);strcat(logstring,itoa_c);
	strcat(logstring,"\n��ʱ = ");mm_server_itoa(TIME_WITE,itoa_c,0);strcat(logstring,itoa_c);
	strcat(logstring,"\n���� = ");mm_server_itoa(box_n,itoa_c,0);strcat(logstring,itoa_c);
	fwrite(logstring,strlen(logstring),1,f_out);
	
	//��ʼ���������߳���=cpu����*2+2
	port_scan_syn_init(box_n,sentbuf_n,0,in_ip_string);
	memset(&ip_list,0,sizeof(ip_list));
	printf("��ʼ�����!ip_list:%u\n\n",sizeof(ip_list));
	
	//���������ļ�
	char*tmp=malloc(1024);
	mm_file_readall(file_in,&tmp,1024);
	//printf("%s\n",tmp);
	//���з��ָ�
	all_ip_num=0;
	mm_string_explode(tmp,"\n",&do_f);
	printf("����Ҫ̽���ip��:%u\n",all_ip_num);
	free(tmp);
	
	memset(logstring,0,sizeof(logstring));
	strcat(logstring,"\n����Ҫ̽���ip��:");mm_server_itoa(all_ip_num,itoa_c,0);strcat(logstring,itoa_c);strcat(logstring,"\n");
	fwrite(logstring,strlen(logstring),1,f_out);
	//fwrite("\n",1,1,f_out);
	fflush(f_out);
	
	if(--all_ip_num<0)return 1;
	
	//��������ip��������ѹ�뷢���������п��˳����������ȴ�3��
	while(all_ip_num>=0){//������ip����>0
		//printf(">>>>ip:%u\n",ip_list[all_ip_num].server_ip);
		//if(send_syn_all(ip_list[all_ip_num].server_ip,ip_list[all_ip_num].type_all_65535)<0){//������
		if(send_syn_all(*(uint32_t*)((ip_list[all_ip_num].bit_5)+1),(ip_list[all_ip_num].bit_5)[0])<0){//������
			Sleep(3000);
		}else{
			char ip_string[16];
			mm_server_ip_uint32_to_ipv4_string(*(uint32_t*)((ip_list[all_ip_num].bit_5)+1),ip_string);
			//printf("Ͷ�ݳɹ�: %s\t%u\n",ip_string,all_ip_num);
			--all_ip_num;
		}
	}
	//�ȴ�����ȫ��
	printf("��ǰʹ�ú�����:%u\n���ȴ�����ȫ��...\n",boxs_num_busy);
	while(boxs_num_busy>0)Sleep(3000);
	
	//д����ʱ��
	mm_time_get_formatstring(0,0,time_string_start,"%Y%m%d %H:%M:%S");
	fwrite(time_string_start,strlen(time_string_start),1,f_out);//����ʱ��
	fwrite("\n\n",2,1,f_out);
	fclose(f_out);
	return 1;
}

