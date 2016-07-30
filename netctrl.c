#include <linux/module.h>  /* specifically, a module, needed by all modules */
#include <linux/kernel.h>	/* we are doing the kernel work, eg. KERN_INFO */
#include <linux/file.h>
#include <linux/init.h>		/* needed by macro */
#include <asm/uaccess.h>	/* for put_user */
#include <linux/proc_fs.h>	/*	necessary because we use proc fs */
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/syscalls.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <linux/freezer.h>
#include <linux/tty.h>
#include <linux/pid_namespace.h>
#include <net/netns/generic.h>
#include <net/netlink.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/spinlock.h>
#include <linux/tty.h>
#include <linux/version.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wbl");

enum NETCTRL_TYPE {
	NETCTRL_AUTH_IP,
	NETCTRL_AUTH_PORT,
};

struct msg_buf {
	u16 msg_type;
	u16 msg_len;
	unsigned char data[0];
};

static struct sock *netctrl_sock;

static DEFINE_MUTEX(netctrl_mutex);

static struct nf_hook_ops netctrl_hook;

unsigned int netctrl_hook_func(const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	return 0;
}

static int netctrl_hook_init(void)
{
	netctrl_hook.hook = netctrl_hook_func;
	netctrl_hook.hooknum = NF_INET_LOCAL_OUT;
	netctrl_hook.pf = PF_INET;
	netctrl_hook.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&netctrl_hook);

	return 0;
}


char *type2string(int cmdtype)
{
	switch (cmdtype) {
	case NETCTRL_AUTH_IP:
		return "NETCTRL_AUTH_IP";
	case NETCTRL_AUTH_PORT:
		return "NETCTRL_AUTH_PORT";
	default:
		return "unknown msg type";
	}
}

/* process system command from user app space */
static int netctrl_proc_msg(struct msg_buf *buf, int unipid)
{
	if (buf == NULL) {
		/* invalid param */
		return -1;
	}

	printk("msgtype %s\n", type2string(buf->msg_type));
	
	switch (buf->msg_type) {
	case NETCTRL_AUTH_IP:
		printk("ip %s\n", buf->data);
		break;
	case NETCTRL_AUTH_PORT:
		printk("port %d\n", *(int*)buf->data);
		break;
	default:
		break;
	}

	return 0;
}

static int netctrl_netlink_ok(struct sk_buff *skb, u16 msg_type)
{
	int err = 0;

	switch (msg_type) {
	case NETCTRL_AUTH_IP:
	case NETCTRL_AUTH_PORT:
		break;
	default:
		err = -EINVAL;
	}

	return err;
}


static int netctrl_receive_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	void *data;
	int datalen;
	int err, pid;

	err = netctrl_netlink_ok(skb, nlh->nlmsg_type);
	if (err)
		return err;

	pid = nlh->nlmsg_pid;
	
	datalen = nlh->nlmsg_len - NLMSG_SPACE(0) + NLMSG_ALIGNTO;

	data = kzalloc(datalen, GFP_ATOMIC);
	if (data == NULL) {
		printk("malloc failed");
		return -ENOMEM;
	}

	memcpy(data, NLMSG_DATA(nlh), datalen);

	err = netctrl_proc_msg((struct msg_buf *)data, pid);
	return 0;
}

/* 
 * Get message from skb. Each message is processed by nectrl_receive_msg.
 * Malformed skbs with wrong length are discarded silently.
 */
int netctrl_receive_skb(struct sk_buff *skb)	
{
	struct nlmsghdr *nlh;
	int len, err;

	nlh = nlmsg_hdr(skb);
	len = skb->len;

	while (nlmsg_ok(nlh, len)) {
		err = netctrl_receive_msg(skb, nlh);
		/* if err or if this message says it wants a response */
		if (err || (nlh->nlmsg_flags & NLM_F_ACK))
			netlink_ack(skb, nlh, err);

		nlh = nlmsg_next(nlh, &len);
	}

	return 0;
}


/* receive messages from netlink socket. */
static void netctrl_receive(struct sk_buff *skb)
{
	mutex_lock(&netctrl_mutex);
	netctrl_receive_skb(skb);
	mutex_unlock(&netctrl_mutex);
}

static __init int netctrl_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = netctrl_receive,
	};

	printk(KERN_INFO "wbl Netctrl start!\n");
	netctrl_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
	if (!netctrl_sock)
		return -ENOMEM;

	//netctrl_hook_init();
	return 0;
}

static __exit void netctrl_exit(void)
{
	printk(KERN_INFO "wbl Netctrl exit!\n");
	netlink_kernel_release(netctrl_sock);
}

module_init(netctrl_init);
module_exit(netctrl_exit);