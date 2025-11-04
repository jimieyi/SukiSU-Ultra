#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include "ksu_netlink.h"
#include "ksu.h"
#ifdef CONFIG_KSU_MANUAL_SU
#include "manual_su.h"
#endif

#define NETLINK_KSU 31
#define KSU_CMD_MANUAL_SU 50

static struct sock *nl_sock = NULL;
static DEFINE_MUTEX(nl_mutex);

struct ksu_access_control {
    uid_t uid;
    bool allowed;
};

static struct ksu_access_control access_cache[256];
static int cache_count = 0;
static DEFINE_SPINLOCK(access_cache_lock);

static bool ksu_check_uid_access(uid_t uid)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&access_cache_lock, flags);

    for (i = 0; i < cache_count; i++) {
        if (access_cache[i].uid == uid) {
            bool result = access_cache[i].allowed;
            spin_unlock_irqrestore(&access_cache_lock, flags);
            return result;
        }
    }

    spin_unlock_irqrestore(&access_cache_lock, flags);

    bool allowed = (uid < 2001);

    spin_lock_irqsave(&access_cache_lock, flags);
    if (cache_count < 256) {
        access_cache[cache_count].uid = uid;
        access_cache[cache_count].allowed = allowed;
        cache_count++;
    }
    spin_unlock_irqrestore(&access_cache_lock, flags);

    return allowed;
}

void ksu_clear_access_cache(void)
{
    unsigned long flags;

    spin_lock_irqsave(&access_cache_lock, flags);
    cache_count = 0;
    memset(access_cache, 0, sizeof(access_cache));
    spin_unlock_irqrestore(&access_cache_lock, flags);

    pr_info("ksu_netlink: access cache cleared\n");
}

static void ksu_nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "KSU Netlink Reply";
    int res;
    uid_t caller_uid;

    if (!skb)
        return;

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;

    caller_uid = current_uid().val;

    if (!ksu_check_uid_access(caller_uid)) {
        pr_warn("ksu_netlink: access denied for UID %d (only UID < 2001 allowed)\n", caller_uid);
        return;
    }

    mutex_lock(&nl_mutex);

    if (nlh->nlmsg_type == KSU_CMD_MANUAL_SU) {
#ifdef CONFIG_KSU_MANUAL_SU
        struct manual_su_request *request = (struct manual_su_request *)nlmsg_data(nlh);
        int su_option = request->su_option;
        int ret;

        pr_info("ksu_netlink: received manual_su request from UID %d, option %d\n",
                caller_uid, su_option);

        ret = ksu_handle_manual_su_request(su_option, request);

        msg_size = sizeof(struct manual_su_request);
        skb_out = nlmsg_new(msg_size, GFP_KERNEL);
        if (!skb_out) {
            pr_err("ksu_netlink: failed to allocate new skb\n");
            mutex_unlock(&nl_mutex);
            return;
        }

        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
        NETLINK_CB(skb_out).dst_group = 0;
        memcpy(nlmsg_data(nlh), request, msg_size);

        res = nlmsg_unicast(nl_sock, skb_out, pid);
        if (res < 0) {
            pr_err("ksu_netlink: error sending reply: %d\n", res);
        } else {
            pr_info("ksu_netlink: reply sent successfully (ret=%d)\n", ret);
        }
#endif
    } else {
        pr_info("ksu_netlink: received unknown command type %d\n", nlh->nlmsg_type);

        msg_size = strlen(msg);
        skb_out = nlmsg_new(msg_size, GFP_KERNEL);
        if (!skb_out) {
            pr_err("ksu_netlink: failed to allocate new skb\n");
            mutex_unlock(&nl_mutex);
            return;
        }

        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
        NETLINK_CB(skb_out).dst_group = 0;
        strncpy(nlmsg_data(nlh), msg, msg_size);

        res = nlmsg_unicast(nl_sock, skb_out, pid);
        if (res < 0) {
            pr_err("ksu_netlink: error sending reply: %d\n", res);
        }
    }

    mutex_unlock(&nl_mutex);
}

int ksu_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = ksu_nl_recv_msg,
    };

    nl_sock = netlink_kernel_create(&init_net, NETLINK_KSU, &cfg);
    if (!nl_sock) {
        pr_err("ksu_netlink: error creating netlink socket\n");
        return -ENOMEM;
    }

    pr_info("ksu_netlink: initialized successfully (protocol=%d, cmd=%d)\n",
            NETLINK_KSU, KSU_CMD_MANUAL_SU);
    return 0;
}

void ksu_netlink_exit(void)
{
    if (nl_sock) {
        netlink_kernel_release(nl_sock);
        nl_sock = NULL;
        pr_info("ksu_netlink: released\n");
    }
    ksu_clear_access_cache();
}
