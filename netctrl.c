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
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv4.h>
#include <linux/spinlock.h>
#include <linux/tty.h>
#include <linux/version.h>
#include <linux/sched.h>

#include "netctrl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wbl");

static struct sock *netctrl_sock;

static DEFINE_MUTEX(netctrl_mutex);

unsigned int netctrl_hook_local_out(const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

unsigned int netctrl_hook_pre_routing(const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

unsigned int netctrl_hook_post_routing(const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

unsigned int bridge_hook_pre_routing(const struct nf_hook_ops *ops,
			struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}



static struct nf_hook_ops netctrl_hooks[] = {
	{
		.hook		=	bridge_hook_pre_routing,
		.owner		=	THIS_MODULE,
		.pf			=	PF_BRIDGE,
		.hooknum	=   NF_BR_PRE_ROUTING,
		.priority	=   NF_BR_PRI_FIRST,
	},

    {
        .hook       =   netctrl_hook_local_out,
        .owner      =   THIS_MODULE,
        .pf         =   PF_INET,
        .hooknum    =   NF_INET_LOCAL_OUT,
        .priority   =   NF_IP_PRI_FIRST,
    },

    {
        .hook       =   netctrl_hook_pre_routing,
        .owner      =   THIS_MODULE,
        .pf         =   PF_INET,
        .hooknum    =   NF_INET_PRE_ROUTING,
        .priority   =   NF_IP_PRI_FIRST,
    },

    {
        .hook       =   netctrl_hook_post_routing,
        .owner      =   THIS_MODULE,
        .pf         =   PF_INET,
        .hooknum    =   NF_INET_POST_ROUTING,
        .priority   =   NF_IP_PRI_FIRST,
    },
};


static int netctrl_hooks_init(void)
{
    int ret = 0;
    ret = nf_register_hooks(netctrl_hooks, ARRAY_SIZE(netctrl_hooks));
    if (ret)
        printk("Failed to register hook\n");
    else
        printk("register hook success\n");

    return ret;
}

#if 0
static int netctrl_hook_init(void)
{
	netctrl_hook.hook = netctrl_hook_func;
	netctrl_hook.hooknum = NF_INET_LOCAL_OUT;
	netctrl_hook.pf = PF_INET;
	netctrl_hook.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&netctrl_hook);

	return 0;
}
#endif

char *type2string(int cmdtype)
{
	switch (cmdtype) {
	case NETCTRL_AUTH_IP:
		return "NETCTRL_AUTH_IP";
	case NETCTRL_AUTH_PORT:
		return "NETCTRL_AUTH_PORT";
    case NETCTRL_AUTH_ID:
        return "NETCTRL_AUTH_ID";
	default:
		return "unknown msg type";
	}
}

int netctrl_auth_ip(struct auth_ip *ip)
{
    printk("[%s %d]ip %s\n", __FUNCTION__, __LINE__, ip->ip);
    return 0;
}

int netctrl_auth_port(struct auth_port *port)
{
    printk("[%s %d]port %d\n", __FUNCTION__, __LINE__, port->port);
    return 0;
}

int netctrl_auth_id(struct auth_id *id)
{
    printk("[%s %d]id %d\n", __FUNCTION__, __LINE__, id->id);
    return 0;
}

/* process system command from user app space */
static int netctrl_proc_msg(struct msg_buf *buf, int unipid)
{
    int ret = 0;

	if (buf == NULL) {
		/* invalid param */
		return -1;
	}

	switch (buf->msg_type) {
	case NETCTRL_AUTH_IP:
        ret = netctrl_auth_ip((struct auth_ip*)buf->data);
		break;
	case NETCTRL_AUTH_PORT:
        ret = netctrl_auth_port((struct auth_port*)buf->data);
		break;
    case NETCTRL_AUTH_ID:
        ret = netctrl_auth_id((struct auth_id*)buf->data);
	default:
		break;
	}

	return ret;
}

static int netctrl_netlink_ok(struct sk_buff *skb, u16 msg_type)
{
	int err = 0;

    printk("[%s %d] msgtype[%d]: %s\n", 
            __FUNCTION__, __LINE__, msg_type, type2string(msg_type));

	switch (msg_type) {
	case NETCTRL_AUTH_IP:
    case NETCTRL_AUTH_PORT:
	case NETCTRL_AUTH_ID:
        break;
    default:
        err = -EINVAL;
        break;
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

	printk(KERN_INFO "Netctrl start!\n");
	netctrl_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
	if (!netctrl_sock)
		return -ENOMEM;

	netctrl_hooks_init();
	return 0;
}

static __exit void netctrl_exit(void)
{
	printk(KERN_INFO "Netctrl exit!\n");
	netlink_kernel_release(netctrl_sock);
	nf_unregister_hooks(netctrl_hooks, ARRAY_SIZE(netctrl_hooks));
}

module_init(netctrl_init);
module_exit(netctrl_exit);
