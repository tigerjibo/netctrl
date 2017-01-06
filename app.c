#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>
#include <syslog.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

/* should correct with kernel ID */
#define NETCTRL_NETLINK_ID		24 	
#define MAX_MSGSIZE 2048

static struct option long_options[] = {
{"ip",		1,		NULL,		'i'},
{"id",		1,		NULL,		'd'},
{"help",	0,		NULL,		'h'},
{"port",	1,		NULL,		'p'},
{NULL,		0,		NULL,		 0}
};

/* system command type and data */
struct syscmd {
	int32_t type;
	union {
		int32_t data;
		void *pdata;
	};
};


const char *const short_options = "hi:p:d:";

enum PARAM_TYPE {
	PARAM_INT,
	PARAM_STR
};

static struct syscmd g_sys_cmd;

/* netctrl system command message type */
enum NETCTRL_TYPE {
	NETCTRL_AUTH_IP = 1,
	NETCTRL_AUTH_PORT,
    NETCTRL_AUTH_ID,
};

typedef struct msg_buf {
	uint16_t msg_type;
	uint16_t msg_len;
	uint8_t data[0];
} msg_buf_t;


struct local_id {
    int id;
};


struct local_ip {
	char ip[32];
};

struct local_port {
	int port;
};

/* create a new netlink-socket to send message and then close it */
int send_msg_to_kernel(uint8_t *buf, uint32_t buflen,
			uint8_t module)
{
	int ret = -1, sockfd;
	struct iovec iov;
	struct msghdr msg;
	struct nlmsghdr *nlhdr = NULL;
	struct sockaddr_nl saddr, daddr;

	if (buflen >= MAX_MSGSIZE)
		return ret;

	sockfd = socket(AF_NETLINK, SOCK_RAW, module);
	if (sockfd < 0) {
		perror("socket errro");
		return ret;
	}

	memset(&saddr, 0, sizeof(struct sockaddr_nl));
	memset(&daddr, 0, sizeof(struct sockaddr_nl));

	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();
	saddr.nl_groups = 0;

	ret = bind(sockfd, (struct sockaddr *)&saddr,
				sizeof(saddr));
	if (ret < 0) {
		perror("bind error");
		goto clean_none;
	}

	daddr.nl_family = AF_NETLINK;
	daddr.nl_pid = 0;
	daddr.nl_groups = 0;

	nlhdr = (struct nlmsghdr *)calloc(1, NLMSG_SPACE(MAX_MSGSIZE));
	
	memcpy(NLMSG_DATA(nlhdr), buf, buflen);
	memset(&msg, 0, sizeof(struct msghdr));

    nlhdr->nlmsg_type = ((msg_buf_t *)buf)->msg_type;
	nlhdr->nlmsg_len = NLMSG_LENGTH(buflen);
	nlhdr->nlmsg_pid = getpid();
	nlhdr->nlmsg_flags = 0;

	iov.iov_base = (void *)nlhdr;
	iov.iov_len = nlhdr->nlmsg_len;
	msg.msg_name = (void *)&daddr;
	msg.msg_namelen = sizeof(daddr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(sockfd, &msg, 0);
	if (ret < 0)
		perror("sendmsg error");

clean_none:
	close(sockfd);
	if (nlhdr) {
		free(nlhdr);
		nlhdr = NULL;
	}

	return ret;
}

int32_t auth_kernel_config_cmd(int16_t operation, 
			uint8_t *buf,
			uint32_t buflen)
{
	msg_buf_t *msg;
	uint32_t msglen;
	int ret = -1;

	msglen = sizeof(msg_buf_t) + buflen;
	msg = (msg_buf_t *)calloc(1, msglen);
	if (msg == NULL) {
		/* malloc error */
		printf("malloc error\n");
		return -1;
	}

	msg->msg_type = operation;

	if (buflen) {
		msg->msg_len = buflen;
		memcpy(msg->data, buf, buflen);
	}

    // create a new socket and send.
	ret = send_msg_to_kernel((uint8_t *)msg, msglen,
		NETLINK_USERSOCK);				
	if (ret <= 0)
		printf("send msg to kernel errro\n");

	free(msg);
	return 0;
}

int syscmd_set_auth_port(struct syscmd *cmd)
{
	int ret = 0;
	struct local_port port;

	port.port = cmd->data;
	ret = auth_kernel_config_cmd(cmd->type,
			(uint8_t *)&port, sizeof(struct local_port));
	if (ret < 0) {
		printf("auth_kernel_config_cmd error\n");
		return ret;
	}

	return ret;
}

int syscmd_set_auth_ip(struct syscmd *cmd)
{
	int ret = 0;
	struct local_ip ip;

	strncpy(ip.ip, cmd->pdata, sizeof(ip.ip));

	ret = auth_kernel_config_cmd(cmd->type,
			(uint8_t *)&ip, sizeof(struct local_ip));
	if (ret < 0) {
		printf("auth_kernel_config_cmd error\n");
		return ret;
	}

	return ret;
}

int syscmd_set_auth_id(struct syscmd *cmd)
{
	int ret = 0;
	struct local_id id;

    id.id = cmd->data;

	ret = auth_kernel_config_cmd(cmd->type,
			(uint8_t *)&id, sizeof(struct local_id));
	if (ret < 0) {
		printf("auth_kernel_config_cmd error\n");
		return ret;
	}

	return ret;
}


int syscmd_proc(struct syscmd *cmd)
{
	int ret = 0;

	switch (cmd->type) {
	case NETCTRL_AUTH_IP:
		ret = syscmd_set_auth_ip(cmd);
		break;
	case NETCTRL_AUTH_PORT:
		ret = syscmd_set_auth_port(cmd);
		break;
	case NETCTRL_AUTH_ID:
		ret = syscmd_set_auth_id(cmd);
		break;
	default:
		printf("unknown command\n");
		break;
	}

	return 0;
}

void usage(void)
{
	printf("NETCTRL USAGE:\n");
}


int32_t syscmd_parse_args(int32_t argc, char **argv)
{
	int ret = 0;
	int32_t c = 0;

	while ((c = getopt_long(argc, argv,
				short_options, long_options, NULL)) != -1) {
		if (optarg == NULL) {
			printf("arguments null\n");
			ret = -1;
			break;
		}

		switch (c) {
		case 'h':
			usage();
			ret = -1;
			break;
		case 'd':
			g_sys_cmd.type = NETCTRL_AUTH_ID;
			g_sys_cmd.data = atoi(optarg);
			break;
		case 'p':
			g_sys_cmd.type = NETCTRL_AUTH_PORT;
			g_sys_cmd.data = atoi(optarg);
			break;
		case 'i':
			g_sys_cmd.type = NETCTRL_AUTH_IP;
			g_sys_cmd.pdata = optarg;
			break;
		default:
			/* bad paramerters */
			printf("unknown param %s\n", optarg);
			ret = -1;
			break;
		}
	}

	return ret;
}

int main(int argc, char **argv)
{
	int ret = 0;

	if (argc <= 1) {
		usage();
		return 0;
	}
	
	ret = syscmd_parse_args(argc, argv);
	printf("ret %d\n", ret);

	if (ret != 0) {
		usage();
		goto end;
	}

	syscmd_proc(&g_sys_cmd);

end:
	return 0;
}
