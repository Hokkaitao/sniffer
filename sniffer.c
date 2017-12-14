#define APP_NAME                "sniffer"
#define APP_DESC                "SQL sniffer  using libpcap"
#define APP_COPYRIGHT        "Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER        "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>
#include <time.h>
#include <unistd.h>

#include <inttypes.h>

/* 默认捕获长度 (每个包捕获的最大长度)
   default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* 以太网头部14个字节
   ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* 以太网地址6个字节
   Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN        6

#define MAX_FILTER_EXP 128

#define MAX_SERVER_VERSION_LEN 128
/* type of package */
#define PACKAGE_TYPE_UNKNOWN -1
#define PACKAGE_TYPE_HANDSHAKE -2
#define PACKAGE_TYPE_AUTH -3
#define PACKAGE_TYPE_AUTH_OK -4
#define PACKAGE_TYPE_AUTH_ERR -5
#define PACKAGE_TYPE_COMMAND -6
#define PACKAGE_TYPE_RESULT -7
#define PACKAGE_TYPE_RESULT_FINAL -8
#define PACKAGE_TYPE_QUIT -8

/* parse number in packet  */
#define uint2korr(A)    (unsigned int) (((unsigned int) ((unsigned char) (A)[0])) +\
    ((unsigned int) ((unsigned char) (A)[1]) << 8))

#define uint3korr(A)    (unsigned int) (((unsigned int) ((unsigned char) (A)[0])) +\
    (((unsigned int) ((unsigned char) (A)[1])) << 8) +\
    (((unsigned int) ((unsigned char) (A)[2])) << 16))

#define uint4korr(A)    (unsigned int) (((unsigned int) ((unsigned char) (A)[0])) +\
    (((unsigned int) ((unsigned char) (A)[1])) << 8) +\
    (((unsigned int) ((unsigned char) (A)[2])) << 16) +\
    (((unsigned int) ((unsigned char) (A)[3])) << 24))

#define uint8korr(A)    ((unsigned long long)(((uint32) ((unsigned char) (A)[0])) +\
    (((unsigned int) ((unsigned char) (A)[1])) << 8) +\
    (((unsigned int) ((unsigned char) (A)[2])) << 16) +\
    (((unsigned int) ((unsigned char) (A)[3])) << 24)) +\
    (((unsigned long long) (((unsigned int) ((unsigned char) (A)[4])) +\
    (((unsigned int) ((unsigned char) (A)[5])) << 8) +\
    (((unsigned int) ((unsigned char) (A)[6])) << 16) +\
    (((unsigned int) ((unsigned char) (A)[7])) << 24))) <<\
    32))

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* ./include/my_command.h  */
enum enum_server_command
{
  COM_SLEEP,
  COM_QUIT,
  COM_INIT_DB,
  COM_QUERY,
  COM_FIELD_LIST,
  COM_CREATE_DB,
  COM_DROP_DB,
  COM_REFRESH,
  COM_SHUTDOWN,
  COM_STATISTICS,
  COM_PROCESS_INFO,
  COM_CONNECT,
  COM_PROCESS_KILL,
  COM_DEBUG,
  COM_PING,
  COM_TIME,
  COM_DELAYED_INSERT,
  COM_CHANGE_USER,
  COM_BINLOG_DUMP,
  COM_TABLE_DUMP,
  COM_CONNECT_OUT,
  COM_REGISTER_SLAVE,
  COM_STMT_PREPARE,
  COM_STMT_EXECUTE,
  COM_STMT_SEND_LONG_DATA,
  COM_STMT_CLOSE,
  COM_STMT_RESET,
  COM_SET_OPTION,
  COM_STMT_FETCH,
  COM_DAEMON,
  COM_BINLOG_DUMP_GTID,
  COM_RESET_CONNECTION,
  /* don't forget to update const char *command_name[] in sql_parse.cc */

  /* Must be last */
  COM_END
};

char *server_cmd[] = {
    "COM_SLEEP",   
    "COM_QUIT",
    "COM_INIT_DB",
    "COM_QUERY",
    "COM_FIELD_LIST",
    "COM_CREATE_DB",
    "COM_DROP_DB",
    "COM_REFRESH",
    "COM_SHUTDOWN",
    "COM_STATISTICS",
    "COM_PROCESS_INFO",
    "COM_CONNECT",
    "COM_PROCESS_KILL",
    "COM_DEBUG",
    "COM_PING",
    "COM_TIME",
    "COM_DELAYED_INSERT",
    "COM_CHANGE_USER",
    "COM_BINLOG_DUMP",
    "COM_TABLE_DUMP",
    "COM_CONNECT_OUT",
    "COM_REGISTER_SLAVE",
    "COM_STMT_PREPARE",
    "COM_STMT_EXECUTE",
    "COM_STMT_SEND_LONG_DATA",
    "COM_STMT_CLOSE",
    "COM_STMT_RESET",
    "COM_SET_OPTION",
    "COM_STMT_FETCH",
    "COM_DAEMON",
    "COM_BINLOG_DUMP_GTID",
    "COM_RESET_CONNECTION"
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_usage(void);

/*
 * print help text
 */
void
print_app_usage(void)
{

        printf("Usage: %s [interface]\n", APP_NAME);
        printf("\n");
        printf("Options:\n");
        printf("    interface    Listen on <interface> for packets.\n");
        printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

        int i;
        int gap;
        const u_char *ch;

        /* offset */
        printf("%05d   ", offset);
        
        /* hex */
        ch = payload;
        for(i = 0; i < len; i++) {
                printf("%02x ", *ch);
                ch++;
                /* print extra space after 8th byte for visual aid */
                if (i == 7)
                        printf(" ");
        }
        /* print space to handle line less than 8 bytes */
        if (len < 8)
                printf(" ");
        
        /* fill hex gap with spaces if not full line */
        if (len < 16) {
                gap = 16 - len;
                for (i = 0; i < gap; i++) {
                        printf("   ");
                }
        }
        printf("   ");
        
        /* ascii (if printable) */
        ch = payload;
        for(i = 0; i < len; i++) {
                if (isprint(*ch))
                        printf("%c", *ch);
                else
                        printf(".");
                ch++;
        }

        printf("\n");

return;
}

/*
 * 打印包的有效载荷数据（避免打印二进制数据）
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

		if(len > SNAP_LEN) {
			return;
		}
        int len_rem = len;
        int line_width = 16;                        /* 每行的字节数 | number of bytes per line */
        int line_len;
        int offset = 0;                                        /* 从0开始的偏移计数器 | zero-based offset counter */
        const u_char *ch = payload;

        if (len <= 0)
                return;

        /* data fits on one line */
        if (len <= line_width) {
                print_hex_ascii_line(ch, len, offset);
                return;
        }

        /* 数据跨越多行 data spans multiple lines */
        for ( ;; ) {
                /* 计算当前行的长度 | compute current line length */
                line_len = line_width % len_rem;

                /* 显示分割线 | print line */
                print_hex_ascii_line(ch, line_len, offset);

                /* 计算总剩余 | compute total remaining */
                len_rem = len_rem - line_len;

                /* 转移到打印的剩余字节的指针
                   shift pointer to remaining bytes to print */
                ch = ch + line_len;

                /* 添加偏移 | add offset */
                offset = offset + line_width;

                /* 检查是否有线宽字符或更少
                   check if we have line width chars or less */
                if (len_rem <= line_width) {
                        /* print last line and get out */
                        print_hex_ascii_line(ch, len_rem, offset);
                        break;
                }
        }

return;
}

/*
 * 显示TCP标志位信息
 */
void print_flag(const struct sniff_tcp *tcp, int len) {
	//time
	time_t t;
	struct tm *lt;
	time(&t);
	lt = localtime(&t);

	struct timeval tv;
	gettimeofday(&tv, NULL);

	printf ( "%d/%d/%d %d:%d:%d ##%ld(微秒)\n",lt->tm_year+1900, lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min, lt->tm_sec, tv.tv_sec*1000000 + tv.tv_usec);
	
	
	//filter
	/*
	if(!(tcp->th_flags & TH_SYN) && 
		((tcp->th_flags & TH_ACK) && len == 0) &&
		!(tcp->th_flags & TH_FIN)) return;	
	*/

    printf("port:%d => port:%d\n", 
        ntohs(tcp->th_sport), ntohs(tcp->th_dport));
    printf("FIN:%d SYN:%d RST:%d PUSH:%d ACK:%d URG:%d\n", 
        tcp->th_flags & TH_FIN, tcp->th_flags & TH_SYN, 
        tcp->th_flags & TH_RST, tcp->th_flags & TH_PUSH, 
        tcp->th_flags & TH_ACK, tcp->th_flags & TH_URG);
	if(tcp->th_flags & TH_SYN) {
		printf("syn:%u\n", ntohl(tcp->th_seq));
	}
	if(tcp->th_flags & TH_ACK) {
		printf("ack:%u\n", ntohl(tcp->th_ack));
	}
}

long long getTime() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec*1000000 + tv.tv_usec);
}


////////////////////////////////////////////////////////
//                   数据包识别BEGIN                  //
////////////////////////////////////////////////////////

unsigned long net_field_length(const char *packet) {

    unsigned char *pos= (unsigned char *)packet;

    if (*pos < 251) {
        return *pos;
    }
    if (*pos == 251) {
        return -1;
    }
    if (*pos == 252) {
        return (unsigned long) uint2korr(pos+1);
    }
    if (*pos == 253) {
        return (unsigned long) uint3korr(pos+1);
    }
    return (unsigned long) uint4korr(pos+1);
}
unsigned long lcb_length(const char *packet) {

    unsigned char *pos= (unsigned char *)packet;

    if (*pos < 251) {
        return 1;
    }
    if (*pos == 251) {
        return -1;
    }
    if (*pos == 252) {
        return 3;
    }
    if (*pos == 253) {
        return 4;
    }
    return 9;
}

#define CHECK(c_b, c_i, c_s) do{\
	c_b = c_b + c_i;\
	if(c_b > c_s) return PACKAGE_TYPE_UNKNOWN;\
} while(0)

int get_packet_id(const char *payload, int size_payload) {
	if(size_payload < 4) return PACKAGE_TYPE_UNKNOWN;
	return (int)payload[3];
}

int is_handshake(const char *payload, int size_payload) {
	int ret = PACKAGE_TYPE_HANDSHAKE;
	if(size_payload > SNAP_LEN) {
	        ret = PACKAGE_TYPE_UNKNOWN;
                return ret;
	}
	const char *cur = payload;
	long count = 0;
	//app header
	CHECK(count, 4, size_payload);
	cur += 4;
	//first Bytes protocol version always 10
	CHECK(count, 1, size_payload);
	u_char version = *cur;
	if(version != 0x0a) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	cur += 1;
	//server version
	int server_len = strlen(cur);
	CHECK(count, server_len+1, size_payload);
	cur += server_len;
	cur += 1;
	//thread id
	CHECK(count, 4, size_payload);
	cur += 4;
	//screamble
	CHECK(count, 8, size_payload);
	cur += 8;
	//0x00
	if(*cur != '\0') {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	CHECK(count, 1, size_payload);
	cur += 1;
	//server capabilities low
	CHECK(count, 2, size_payload);
	cur += 2;
	//server character set
	CHECK(count, 1, size_payload);
	cur += 1;
	//server status
	CHECK(count, 2, size_payload);
	cur += 2;
	//server capabilities high
	CHECK(count, 2, size_payload);
	cur += 2;
	//scramble total len
	CHECK(count, 1, size_payload);
	if(*cur != '\0') {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	cur += 1;
	//reverse
	CHECK(count, 10, size_payload);
	int loop = 0;
	for(loop=0; loop < 10; loop ++) {
		if(*(cur + loop) != '\0') {
			ret = PACKAGE_TYPE_UNKNOWN;
			return ret;
		}
	}
	cur += 10;
	//scramble left
	int scramble_len = strlen(cur);
	CHECK(count, scramble_len, size_payload);
	return ret;
}

int is_auth(const char *payload, int size_payload) {
	int ret = PACKAGE_TYPE_AUTH;
	if(size_payload > SNAP_LEN) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	const char *cur = payload;
	long count = 0;
	CHECK(count, 4, size_payload);
	cur += 4;
	//client capabilities
	CHECK(count, 4, size_payload);
	cur += 4;
	//max packet size
	CHECK(count, 4, size_payload);
	cur += 4;
	//charset number
	CHECK(count, 1, size_payload);
	cur += 1;
	//reserve
	CHECK(count, 23, size_payload);
	int loop = 0;
	for(loop = 0; loop < 23; loop ++) {
		if(*(cur + loop) != '\0') {
			ret = PACKAGE_TYPE_UNKNOWN;
			return ret;
		}
	}
	cur += 23;
	//user name
	int user_len = strlen(cur);
	cur += user_len;
	cur += 1;
	CHECK(count, user_len+1, size_payload);
	//hash password
	int pwlen =  lcb_length(cur) + net_field_length(cur);
	cur += pwlen;
	CHECK(count, pwlen, size_payload);
	//database name
	
	//client auth plugin name
	
	return ret;
}

int is_auth_OK(const char *payload, int size_payload) {
	int ret = PACKAGE_TYPE_AUTH_OK;
	if(size_payload > SNAP_LEN) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	const char *cur = payload;
	long count = 0;
	//check packet_id
	CHECK(count, 4, size_payload);
	if(*(cur + 3) != '\02') {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	cur += 4;
	//check flag 0x00
	CHECK(count, 1, size_payload);
	if(*cur != '\0') {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	return ret;
}

int is_auth_ERR(const char *payload, int size_payload) {
	int ret = PACKAGE_TYPE_AUTH_ERR;
	if(size_payload > SNAP_LEN) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	const char *cur = payload;
	long count = 0;
	//check packet_id
	CHECK(count, 4, size_payload);
	if(*(cur + 3) != '\02') {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	cur += 4;
	//check flag 0x00
	CHECK(count, 1, size_payload);
	if((cur[0]&0xff) != 0xff) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	return ret;
}

int is_result_final(const char *payload, int size_payload) {
	int ret = PACKAGE_TYPE_RESULT_FINAL;
	if(size_payload > SNAP_LEN) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	const char *cur = payload;
	long count = 0;

	CHECK(count, 4, size_payload);
	//check 1
	int len = uint3korr(payload);
	int packet_id = get_packet_id(payload, size_payload);
	if((size_payload == len + 4) && (packet_id == 1)) {
		return ret;
	}
	//check 2
	int flag = (*(cur + size_payload - 5))&0xff;
	if(flag != 0xfe) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	return ret;
}

int is_quit(const char *payload, int size_payload) {
	int ret = PACKAGE_TYPE_QUIT;
	if(size_payload > SNAP_LEN) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	int len = uint3korr(payload);
	//总长度检查
	if(size_payload != 5) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	//数据长度检查
	if(len != 1) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	//packet_id检查
	int packet_id = get_packet_id(payload, size_payload);		
	if(packet_id != 0) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	//载荷内容检查
	int context = payload[4] & 0xff;
	if(context != 1) {
		ret = PACKAGE_TYPE_UNKNOWN;
		return ret;
	}
	return ret;
}

//////////////////////////////////////////////////////
//                   辅助函数                       //
//////////////////////////////////////////////////////
#define MAX_TIME_LEN 32

void getCurrentTime(char *dst) {
	if(dst == NULL) return;
	struct timeval tv;
	struct timezone tz;
	struct tm *p;
	
	gettimeofday(&tv, &tz);
	p = localtime(&tv.tv_sec);
	sprintf(dst, "%d-%d-%d %d:%d:%d.%ld", 1900+p->tm_year, 1+p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, tv.tv_usec);
}

//////////////////////////////////////////////////////
//                  处理SESSION                     //
//////////////////////////////////////////////////////


typedef enum _session_state {
	InitStage = 1,
	HandShakeStage,
	AuthStage,
	RequestWaitingStage,
	RequestReadingStage,
	ResponseWaitingStage,
	QuitStage,
	ErrorStage
}session_state;

typedef enum packet_direction {
	DirectionUnknown = 1, 
	DirectionToMySQL,
	DirectionFromMySQL
}packet_direction;

typedef struct _session {
	//time
	struct timeval begin;//gettimeofday(&begin, NULL);begin.tv_sec, begin.tv_usec
	//session属性
	int cmd;
	session_state state;
	//SQL
	GString *sql;
	
	long latency;
	int packet_type;
}session, *SESSION;

SESSION newSession() {
	SESSION s = (SESSION)malloc(sizeof(session));
	if(s == NULL) return NULL;
	memset(s, 0, sizeof(session));
	gettimeofday(&(s->begin), NULL);
	
	s->cmd = -1;
	s->state = InitStage;	
	s->sql = g_string_new(NULL);	
	s->latency = -1;
	s->packet_type = 0;
	return s;
}

void freeSession(gpointer sn) {
	SESSION s = (SESSION)sn; 
	if(s) {
		if(s->sql) g_string_free(s->sql, TRUE);
		free(s);
	}
}

/////////////////////////////////////////////////////////
//                       处理连接                      //
/////////////////////////////////////////////////////////

GList *list_connect = NULL;

#define MAX_CONNECT_KEY_LEN 64

void print_mysql_packet_type(const char *payload, int size_payload) {
	if(payload == NULL) return;
	//数据包类型识别
	int handshake = (is_handshake(payload, size_payload) == PACKAGE_TYPE_HANDSHAKE);
	int auth = (is_auth(payload, size_payload) == PACKAGE_TYPE_AUTH);
	int auth_ok = (is_auth_OK(payload, size_payload) == PACKAGE_TYPE_AUTH_OK);
	int auth_err = (is_auth_ERR(payload, size_payload) == PACKAGE_TYPE_AUTH_ERR);
	if(handshake) {
		printf("packet_type: handshake(server -> client)\n");
	} else if(auth) {
		printf("packet_type: auth(client -> server)\n");
	} else if(auth_ok) {
		printf("packet_type: auth ok(server -> client)\n");
	} else if(auth_err) {
		printf("packet_type: auth err(server -> client)\n");
	}
}

void print_tcp_flag(const struct sniff_tcp *tcp) {
	if(tcp == NULL) return;
	u_char th_flags = tcp->th_flags;
	int fin = th_flags & 0x01;
	int syn = th_flags & 0x02;
	int rst = th_flags & 0x04;
	int push = th_flags & 0x08;
	int ack = th_flags & 0x10;
	int urg = th_flags & 0x20;
	int ece = th_flags & 0x40;
	int cwr = th_flags & 0x80;
	printf("====3 TCP Flags====\n");
	char cur_time[64] = {""};
	getCurrentTime(cur_time);
	printf("timestamp: %s\n", cur_time);
	printf("FIN:%d SYN:%d RST:%d PUSH:%d ACK:%d URG:%d\n", 
		fin>0, syn>0, rst>0, push>0, ack>0, urg>0);
	
	//打印seq/ack
	u_int seq_num = ntohl(tcp->th_seq);
	u_int ack_num = ntohl(tcp->th_ack);
	if(syn) {
		printf(" seq_num:%  " PRIu32, seq_num);
	}
	if(ack) {
		printf(" ack_num:%  " PRIu32, ack_num);
	}
	if(syn||ack) {
		printf("\n");
	}
    
}

int filter_tcp_flag(u_char th_flags) {
	int ret = 0;
	int fin = th_flags & 0x01;
	int rst = th_flags & 0x04;
	int push = th_flags & 0x08;
	if(fin>0 || rst>0 || push>0) {
		ret = 1;
	}
	return ret;
}

typedef struct _One_connect{
	//连接属性
	struct  in_addr s_ip;
	struct  in_addr d_ip;
	u_short s_port;
	u_short d_port;

	char key[MAX_CONNECT_KEY_LEN];

	packet_direction direction;
	//会话属性
	SESSION s;
}OneConnect, *ONECONNECT;

ONECONNECT newOneConnect(
	struct  in_addr s_ip, 
	struct  in_addr d_ip, 
	u_short s_port, 
	u_short d_port, 
	packet_direction direction) 
{
	ONECONNECT con = (ONECONNECT)malloc(sizeof(OneConnect));
	if(con == NULL) return NULL;
	memset(con, 0, sizeof(OneConnect));
	if(direction == DirectionToMySQL) {
		con->s_ip = s_ip;
		con->d_ip = d_ip;
		con->s_port = s_port;
		con->d_port = d_port;
		con->direction = direction;
	} else if(direction == DirectionFromMySQL) {
		con->s_ip = d_ip;
		con->d_ip = s_ip;
		con->s_port = d_port;
		con->d_port = s_port;
		con->direction = direction;
	} else {
		return NULL;
	}
	char src_ip[16] = {""};
        char dst_ip[16] = {""};
	sprintf(src_ip, "%s", inet_ntoa(con->s_ip));
	sprintf(dst_ip, "%s", inet_ntoa(con->d_ip));

	sprintf(con->key, "%s:%d=>%s:%d", 
			src_ip, ntohs(con->s_port), 
			dst_ip, ntohs(con->d_port));
	con->s = newSession();
	return con;
}

void freeOneConnect(gpointer con) {
	ONECONNECT c = (ONECONNECT)con;
	if(c) {
		freeSession(c->s);
		free(c);
	}
}

void printOneConnect(ONECONNECT con) {
	if(con == NULL) return;
	printf("##%s\n", con->key);
}

void getConnectKey(
	struct  in_addr s_ip,
	struct  in_addr d_ip,
	u_short s_port,
	u_short d_port,
	packet_direction direction,
	char *dst) 
{
	char src_ip[16] = {""};
	char dst_ip[16] = {""};
	sprintf(src_ip, "%s", inet_ntoa(s_ip));
	sprintf(dst_ip, "%s", inet_ntoa(d_ip));
	if(dst == NULL) return ;
	if(direction == DirectionToMySQL) {
		sprintf(dst, "%s:%d=>%s:%d", 
			src_ip, ntohs(s_port), 
			dst_ip, ntohs(d_port));
	} else if(direction == DirectionFromMySQL){
		sprintf(dst, "%s:%d=>%s:%d",
			dst_ip, ntohs(d_port),
			src_ip, ntohs(s_port));
	} else {
		return ;
	}
}

char *getSQL(const char *payload) {
/*
 * ret = 0 数据完整
 * ret = 1 数据位接收完，待接收数据
 */
	int ret = 0;
	if(payload == NULL) {
		return;
	}
	long len = uint3korr(payload);
	char *sql = (char *)malloc(len);
	memset(sql, 0, len);
	memcpy(sql, (payload + 5), len - 1);
	return sql;
}
int getCMD(const char *payload) {
	char ret = -1;
	ret = payload[4];
	return (int)ret;
}

gint list_compare_connect(gconstpointer a, gconstpointer b) {
	if(a == NULL) return -1;
	return strcmp(((ONECONNECT)a)->key, (char *)b);
}

packet_direction getConnectDirection(u_short s_port, u_short d_port, u_short mysql_port) {
	packet_direction ret = DirectionUnknown;
	if(ntohs(s_port) == mysql_port) {
		ret = DirectionFromMySQL; 
	} else if(ntohs(d_port) == mysql_port) {
		ret = DirectionToMySQL;
	}
	return ret;
}

ONECONNECT process_connect(
	struct  in_addr s_ip, 
	struct  in_addr d_ip,
	u_short s_port, 
	u_short d_port, 
	packet_direction direction,
	u_char th_flags) 
{
	/*
 	 * 1. 检查是否已经存在，存在则返回，不存在则创建
 	 * 2. 返回该连接的指针
 	 */
        /* 显示源IP和目的IP
           print source and destination IP addresses */
        //printf("       From: %s\n", inet_ntoa(s_ip));
        //printf("         To: %s\n", inet_ntoa(d_ip));
        
	ONECONNECT ret = NULL;
	char key[MAX_CONNECT_KEY_LEN] = {""};
	getConnectKey(s_ip, d_ip, s_port, d_port, direction, key);
	GList *p = g_list_find_custom(list_connect, key, list_compare_connect);

	
	//添加tcp flags
	int fin = th_flags & 0x01;
	int rst = th_flags & 0x04;
	if(fin>0 || rst>0) {//说明该数据包是结束连接的，移除连接
		if(p == NULL) {
			//连接不存在，直接返回
			return NULL;
		} else {
			ONECONNECT con = (ONECONNECT)p->data;
			list_connect = g_list_remove_all(list_connect, con);
			if(con) freeOneConnect(con);
			return NULL;
		}
	}

	if(p == NULL) {
		ONECONNECT con = newOneConnect(s_ip, d_ip, s_port, d_port, direction);
		list_connect = g_list_append(list_connect, con);	
		ret = con;
	} else {
		//update direction
		((ONECONNECT)(p->data))->direction = direction;
		ret = (ONECONNECT)(p->data);
	}
	return ret;
}

void close_connect(ONECONNECT con) {
	if(con && con->s) {
		//断开连接
		GList *p = g_list_find_custom(list_connect, con->key, list_compare_connect);
		if(p) {
			ONECONNECT con = (ONECONNECT)(p->data);
			list_connect = g_list_remove_all(list_connect, con); 
			if(con) freeOneConnect(con);
		}
	}
}

ONECONNECT  process_application(ONECONNECT con, const char *payload, int size_payload) {
/*
 * 1. 确定是哪类数据包
 * 2. 状态机转换
 * 3. 提取SQL
 * 4. 获取执行时间
 * 5. 输出
 */	
	
/*
 * DirectionToMySQL
 * 	Auth Packet
 * 	Query Packet
 * DirectionFromMySQL
 * 	Scramble Packet
 * 	OK Packet
 * 	ERR Packet
 * 	Result Packet
 */
	if(con == NULL) return;

	//应用层数据包长度过滤
	if(size_payload < 4) return;

	session_state old_state = con->s->state;

	//判断数据包类型
	int packet_type = PACKAGE_TYPE_UNKNOWN;
	if(con->direction == DirectionToMySQL) {
		if(is_auth(payload, size_payload) == PACKAGE_TYPE_AUTH) {
			packet_type = PACKAGE_TYPE_AUTH;
			//printf("::PACKAGE_TYPE_AUTH\n");
		} else {
			if(is_quit(payload, size_payload) == PACKAGE_TYPE_QUIT) {
				packet_type = PACKAGE_TYPE_QUIT;
				//printf("::PACKAGE_TYPE_QUIT\n");
			} else {
				packet_type = PACKAGE_TYPE_COMMAND;
				//printf("::PACKAGE_TYPE_COMMAND\n");
			}
		}
	} else if(con->direction == DirectionFromMySQL) {
		if(is_handshake(payload, size_payload) == PACKAGE_TYPE_HANDSHAKE) {
			packet_type = PACKAGE_TYPE_HANDSHAKE;
			//printf("::PACKAGE_TYPE_HANDSHAKE\n");
		} else if(is_auth_OK(payload, size_payload) == PACKAGE_TYPE_AUTH_OK) {
			packet_type = PACKAGE_TYPE_AUTH_OK;
			//printf("::PACKAGE_TYPE_AUTH_OK\n");
		} else if(is_auth_ERR(payload, size_payload) == PACKAGE_TYPE_AUTH_ERR) {
			packet_type = PACKAGE_TYPE_AUTH_ERR;
			//printf("::PACKAGE_TYPE_AUTH_ERR\n");
		} else {
			//判断是否是结果包
			if(is_result_final(payload, size_payload) == PACKAGE_TYPE_RESULT_FINAL) {
				packet_type = PACKAGE_TYPE_RESULT_FINAL;
				//printf("::PACKAGE_TYPE_RESULT_FINAL\n");
			} else {
				packet_type = PACKAGE_TYPE_RESULT;
				//printf("::PACKAGE_TYPE_RESULT\n");
			}
		}
	} else {
		goto end;
	}
	//状态转换
/*
 * InitStage + PACKAGE_TYPE_HANDSHAKE = HandShakeStage
 * HandShakeStage + PACKAGE_TYPE_AUTH = AuthStage
 * AuthStage + PACKAGE_TYPE_AUTH_OK = RequestWaitingStage
 * AuthStage + PACKAGE_TYPE_AUTH_ERR = QuitStage
 * InitStage/RequestWaitingStage +  PACKAGE_TYPE_COMMAND = ResponseWaitingStage
 * ResponseWaitingStage + PACKAGE_TYPE_RESULT = PACKAGE_TYPE_COMMAND
 */
	session_state state = con->s->state;
	if(con->direction == DirectionToMySQL) {
		if(packet_type == PACKAGE_TYPE_AUTH && state == HandShakeStage) {
			state = AuthStage;
		} else if(packet_type == PACKAGE_TYPE_COMMAND && state == RequestWaitingStage) {
			state = ResponseWaitingStage;
		} else if(packet_type == PACKAGE_TYPE_COMMAND && state == InitStage) {
			state = ResponseWaitingStage;
		} else if(packet_type == PACKAGE_TYPE_QUIT && state == RequestWaitingStage) {
			state = QuitStage;
		} else if(packet_type == PACKAGE_TYPE_QUIT && state == InitStage) {
			state = QuitStage;
		} else {
			//state = ErrorStage;
			goto end;
		}
	} else if(con->direction == DirectionFromMySQL) {
		if(packet_type == PACKAGE_TYPE_HANDSHAKE && state == InitStage) {
			state = HandShakeStage;
		} else if(packet_type == PACKAGE_TYPE_AUTH_OK && state == AuthStage) {
			state = RequestWaitingStage;
		} else if(packet_type == PACKAGE_TYPE_AUTH_ERR && state == AuthStage) {
			state = ErrorStage;
			goto end;
		} else if(packet_type == PACKAGE_TYPE_RESULT_FINAL && state == ResponseWaitingStage){
			state = RequestWaitingStage;
		} else if(packet_type == PACKAGE_TYPE_RESULT_FINAL && state == InitStage) {
			state = ErrorStage;
		} else {
			//state = ErrorStage;
			goto end;
		}
	} else {
		state = ErrorStage;
		goto end;
	}
	//提取SQL和CMD
	char *my_sql = NULL;
	if(packet_type == PACKAGE_TYPE_COMMAND) {
		my_sql = getSQL(payload);	
		if(con->s->packet_type == PACKAGE_TYPE_RESULT_FINAL) {
			if(con->s->sql) g_string_free(con->s->sql, TRUE);
			con->s->sql = NULL;
		}
		if(con->s->sql == NULL) con->s->sql = g_string_new(NULL);
		g_string_append(con->s->sql, my_sql);
		if(my_sql) free(my_sql);
		con->s->cmd = getCMD(payload);
		if(con->s->cmd > COM_END || con->s->cmd <0) con->s->cmd = -1;
		con->s->latency = 0;
	}
	if(con->direction == DirectionToMySQL && packet_type == PACKAGE_TYPE_QUIT) {
		con->s->cmd = getCMD(payload);
		con->s->latency = 0;
	}
	//处理时间
	struct timeval start;
	struct timeval end;
	if(packet_type == PACKAGE_TYPE_COMMAND) {
		gettimeofday(&(con->s->begin), NULL);
	} else if(packet_type == PACKAGE_TYPE_RESULT_FINAL) {
		gettimeofday(&end, NULL);
		start = con->s->begin;
		con->s->latency  = (end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec);
	}
	if(con->direction == DirectionToMySQL && packet_type == PACKAGE_TYPE_QUIT) {
		con->s->latency = 0;
	}
end:
	if(old_state != state) {
		con->s->packet_type = packet_type;
	}
	con->s->state = state;

	if(state == ErrorStage) {
		close_connect(con);
		return NULL;
	}
	return con;
}

void process_quit_connect(ONECONNECT con) {
	if(con && con->s && con->s->packet_type == PACKAGE_TYPE_QUIT) {
		close_connect(con);
	}
}

void show_session_info(ONECONNECT con) {
	//打印SQL与执行时间
	if(con && con->s && (
	(con->s->latency > 0 && con->s->packet_type == PACKAGE_TYPE_RESULT_FINAL) || 
	(con->s->packet_type == PACKAGE_TYPE_QUIT)
	)) {
		if(con->s->sql == NULL) return;
		char curtime[64] = {""};
		getCurrentTime(curtime);

		printf("====4 App Layer====\n");
		printf("timestamp:   %s\n", curtime);
		printf("src host:    %s:%d\n", inet_ntoa(con->s_ip), ntohs(con->s_port));
		printf("dst host:    %s:%d\n", inet_ntoa(con->d_ip), ntohs(con->d_port));
		printf("cmd:         %s\n", server_cmd[con->s->cmd]);
		printf("latency:     %ld (microsecond)\n", con->s->latency>0?con->s->latency:0);
		printf("sql:         %s\n", con->s->sql->str);
		//printf("state:       %d\n", con->s->state);
		//printf("packet_type: %d\n", con->s->packet_type);

		con->s->latency = -1;
	}
}

void show_connect_counter() {
	printf("====5 Current Connect Number====\n");
	printf("counter:   %d\n", g_list_length(list_connect));
}

/////////////////////////////////////////////////////////
//                    协议栈解析至应用层               //
/////////////////////////////////////////////////////////

/*
 * 1. 解析出IP Header/TCP Header/载荷/载荷数据长度
 * 2. 根据(s_ip, s_port, d_ip, d_port)四元组确定一个连接，连接的存储和销毁
 *    CONNECT * process_connect(s_ip, s_port, d_ip, d_port, direction);
 * 3. 处理应用层协议
 *    process_application(CONNECT *con, char *data, int size_data);
 */

#define MAX_ARGS_LEN 128

u_short mysql_port = 3306;
char device[MAX_ARGS_LEN] = {""};
/* 过滤表达示          | filter expression [3] */
char filter_exp[MAX_FILTER_EXP] = {""};
int addition = 8;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
        /* 包计数器                | packet counter */
        static long long count = 1;
        
        /* declare pointers to packet headers */
        const struct sniff_ethernet *ethernet;  /* 以太网头部 */
        const struct sniff_ip *ip;              /* IP 头部 */
        const struct sniff_tcp *tcp;            /* TCP 头部 */
        const char *payload;                    /* Packet payload */

        int size_ip;
        int size_tcp;
        int size_payload;
        
        /* 显示包总数 */
        //printf("\nPacket number %ld:\n", count);
        count++;
        
        /* 定义以太网头部
           define ethernet header */
        ethernet = (struct sniff_ethernet*)(packet);
        
        /* 定义/计算 IP 头部偏移
           define/compute ip header offset */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
                printf("   * Invalid IP header length: %u bytes\n", size_ip);
                return;
        }

        /* 确定协议 */        
        switch(ip->ip_p) {
                case IPPROTO_TCP:
            //            printf("   Protocol: TCP\n");
                        break;
                case IPPROTO_UDP:
            //            printf("   Protocol: UDP\n");
                        return;
                case IPPROTO_ICMP:
            //            printf("   Protocol: ICMP\n");
                        return;
                case IPPROTO_IP:
            //            printf("   Protocol: IP\n");
                        return;
                default:
            //            printf("   Protocol: unknown\n");
                        return;
        }
        
        /* define/compute tcp header offset */
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;

        //printf("   Src port: %d\n", ntohs(tcp->th_sport));
        //printf("   Dst port: %d\n", ntohs(tcp->th_dport));
        

        /* 定义/计算TCP有效载荷（段）偏移
           define/compute tcp payload (segment) offset */
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        
        /* 计算TCP有效载荷（段）的大小
           compute tcp payload (segment) size */
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        /*
         * 打印有效载荷数据，它可能是二进制的，所以不要只把它作为一个字符串。
         * Print payload data; it might be binary, so don't just
         * treat it as a string.
         */
	if(addition & 0x01) {
		printf("====1 TCP Hex Data====\n");
        	printf("From: %s:%d\n", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
        	printf("To:   %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
                printf("Payload (%d bytes):\n", size_payload);
                print_payload(payload, size_payload);
	} else if(addition & 0x02) {
		if(size_payload) {
			printf("====2 TCP Hex Data====\n");
        		printf("From: %s:%d\n", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
        		printf("To:   %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
			printf("Payload (%d bytes):\n", size_payload);
			print_payload(payload, size_payload);
		}
	}

	/* 打印TCP标志 */
	if(addition & 0x04) {
		print_tcp_flag(tcp);
	}

	if(addition & 0x20) {
		print_mysql_packet_type(payload, size_payload);
	}
	
	/* TCP 标志进行包过滤: RST/FIN/PUSH */
	//if(!filter_tcp_flag(tcp->th_flags)) {
	//	return;
	//}

        /* 显示源IP和目的IP
           print source and destination IP addresses */
        //printf("       From: %s\n", inet_ntoa(ip->ip_src));
        //printf("         To: %s\n", inet_ntoa(ip->ip_dst));
        
	/* 处理连接  */
	ONECONNECT con = process_connect(ip->ip_src, ip->ip_dst, 
			tcp->th_sport, tcp->th_dport, 
			getConnectDirection(tcp->th_sport, tcp->th_dport, mysql_port), 
			tcp->th_flags);
	//printOneConnect(con);
        con = process_application(con, payload, size_payload);
	
	if(addition & 0x08) {
		show_session_info(con);
	}

	if(addition & 0x10) {
		//打印当前连接数
		if(con && con->s->packet_type == PACKAGE_TYPE_RESULT_FINAL)
			show_connect_counter();
	}

	//收尾工作
	process_quit_connect(con);

/*
		if(size_payload > 0) {
        		print_flag(tcp, size_payload);
			printf("handshake:%d, auth:%d, auth_OK:%d, auth_ERR:%d\n", 
			is_handshake(payload, size_payload) == PACKAGE_TYPE_HANDSHAKE, 
			is_auth(payload, size_payload) == PACKAGE_TYPE_AUTH, 
			is_auth_OK(payload, size_payload) == PACKAGE_TYPE_AUTH_OK, 
			is_auth_ERR(payload, size_payload) == PACKAGE_TYPE_AUTH_ERR);
			print_payload(payload, size_payload);
			printf("packet-id:%d\n", get_packet_id(payload, size_payload));
			printf("SQL len = %d\n", uint3korr(payload));
		}
*/
        return;
}

///////////////////////////////////////////////////////////
//                    程序入口 & 以太网监听              //
///////////////////////////////////////////////////////////

/*
 * 1. 参数解析
 * 2. 监听与过滤
 * 3. 解析协议栈 got_packet()
 */

const char *help = "Usage:\n\
    -i 待捕获的网卡     # eg: -i eth0\n\
    -p mysql的端口号    # eg: -p 3306\n\
    -f 过滤条件         # eg: -f \"src host 1.1.1.1\"\n\
    -a 显示格式         # eg: 1 显示tcp 数据包;2 显示有载荷数据包;4 显示tcp flags;8 显示应用层解析结果;16 显示连接数;32 识别MySQL认证期间数据包类型\n\
    -h 帮助信息\n\n";


int main(int argc, char **argv)
{
	/* 参数处理 */
	int ch;
	while((ch = getopt(argc, argv, "hi:p:f:a:")) != -1) {
		switch(ch) {
			case 'h': {
				printf("%s", help);
				exit(1);
			}
			case 'p': {
				if(optarg == NULL) {
					printf("参数错误\n\n");
					exit(1);
				}				
				mysql_port = atoi(optarg);
				break;
			}
			case 'i': {
				if(optarg == NULL) {
					printf("参数错误\n\n");
					exit(1);
				}
				memcpy(device, optarg, strlen(optarg));
				break;
			}
			case 'f': {
				if(optarg == NULL) {
					printf("参数错误\n\n");
					exit(1);
				}
				memcpy(filter_exp, optarg, strlen(optarg));	
				break;
			}
			case 'a': {
				if(optarg == NULL) {
					printf("参数错误\n\n");
					exit(1);
				}
				addition = atoi(optarg);	
			}
			
		}
	}

	/* debug:: 参数检查  */
	//printf("device=%s \nfilter_exp=%s \nmysql_port=%d \naddition=%d\n", 
	//	device, filter_exp, mysql_port, addition), exit(1);

        /* 捕获设备的名称 | capture device name */
        char *dev = NULL;
        /* 错误的缓冲区   | error buffer */
        char errbuf[PCAP_ERRBUF_SIZE];
        /* 数据包捕获句柄 | packet capture handle */
        pcap_t *handle;

        /* 编译过滤表达示  | compiled filter program (expression) */
        struct bpf_program fp;
        /* 子网掩码                  | subnet mask */
        bpf_u_int32 mask;
        /* IP 地址                  | ip */
        bpf_u_int32 net;
        /* 捕获的数据包数量  | number of packets to capture */
        int num_packets = 0;

        /* 检查来自命令行参数需要捕获设备的名称
           check for capture device name on command-line */
        if (device[0] != '\0') {
            dev = device;
        }
        
        /* 如果未指定设备，则自动找到一个设备  */
        if(NULL == dev) {
            dev = pcap_lookupdev(errbuf);
            if(NULL == dev) {
                fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
                exit(EXIT_FAILURE);
            }
        } 

        /* 获得捕获设备的网络号和掩码
           get network number and mask associated with capture device */
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                    dev, errbuf);
                net = 0;
                mask = 0;
        }

        /* 显示捕获设备信息
           print capture info */
        printf("Device: %s\n", dev);
        printf("Number of packets: %d\n", num_packets);
        printf("Filter expression: %s\n", filter_exp);

        /* 打开捕获设备
           @1        捕获的设备
           @2        每次捕获数据的最大长度
           @3        1 启用混杂模式
           @4        捕获时间, 单位ms
           @5        错误缓冲区
           open capture device */
        handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                exit(EXIT_FAILURE);
        }

        /*        pcap_datalink();
                        返回数据链路层类型，例如DLT_EN10MB;

           确保我们对以太网设备捕获
           make sure we're capturing on an Ethernet device [2] */
        if (pcap_datalink(handle) != DLT_EN10MB) {
                fprintf(stderr, "%s is not an Ethernet\n", dev);
                exit(EXIT_FAILURE);
        }

        /* 编译过滤表达式
           compile the filter expression */
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n",
                    filter_exp, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

        /* 应用过滤规则
           apply the compiled filter */
        if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n",
                    filter_exp, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

        /* 设置回高函数并开始捕获包
           now we can set our callback function */
        pcap_loop(handle, num_packets, got_packet, NULL);

        /* cleanup */
        pcap_freecode(&fp);
        pcap_close(handle);

        printf("\nCapture complete.\n");

        return 0;
}
