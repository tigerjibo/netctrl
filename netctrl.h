#ifndef __NETCTRL_H_
#define __NETCTRL_H_

enum NETCTRL_TYPE {
	NETCTRL_AUTH_IP = 1,
	NETCTRL_AUTH_PORT,
    NETCTRL_AUTH_ID,
};

struct msg_buf {
	u16 msg_type;
	u16 msg_len;
	unsigned char data[0];
};

struct auth_ip {
    char ip[32];
};

struct auth_port {
    int port;
};

struct auth_id {
    int id;
};


#endif
