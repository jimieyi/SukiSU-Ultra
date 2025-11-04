#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "ksu_uid_intercept.h"

#define MAX_INTERCEPT_RULES 128

struct uid_intercept_rule {
    uid_t from_uid;
    uid_t to_uid;
    enum intercept_action action;
    struct list_head list;
};

static LIST_HEAD(intercept_rules);
static DEFINE_SPINLOCK(intercept_lock);
static int rule_count = 0;

static struct uid_intercept_rule *find_rule(uid_t from_uid, uid_t to_uid)
{
    struct uid_intercept_rule *rule;

    list_for_each_entry(rule, &intercept_rules, list) {
        if (rule->from_uid == from_uid && rule->to_uid == to_uid) {
            return rule;
        }
    }

    return NULL;
}

int ksu_add_intercept_rule(uid_t from_uid, uid_t to_uid, enum intercept_action action)
{
    struct uid_intercept_rule *rule;
    unsigned long flags;

    if (rule_count >= MAX_INTERCEPT_RULES) {
        pr_warn("ksu_intercept: rule limit reached (%d)\n", MAX_INTERCEPT_RULES);
        return -ENOMEM;
    }

    spin_lock_irqsave(&intercept_lock, flags);

    rule = find_rule(from_uid, to_uid);
    if (rule) {
        rule->action = action;
        spin_unlock_irqrestore(&intercept_lock, flags);
        pr_info("ksu_intercept: updated rule %d->%d action=%d\n",
                from_uid, to_uid, action);
        return 0;
    }

    rule = kmalloc(sizeof(*rule), GFP_ATOMIC);
    if (!rule) {
        spin_unlock_irqrestore(&intercept_lock, flags);
        return -ENOMEM;
    }

    rule->from_uid = from_uid;
    rule->to_uid = to_uid;
    rule->action = action;
    list_add_tail(&rule->list, &intercept_rules);
    rule_count++;

    spin_unlock_irqrestore(&intercept_lock, flags);

    pr_info("ksu_intercept: added rule %d->%d action=%d (total: %d)\n",
            from_uid, to_uid, action, rule_count);

    return 0;
}

int ksu_remove_intercept_rule(uid_t from_uid, uid_t to_uid)
{
    struct uid_intercept_rule *rule;
    unsigned long flags;

    spin_lock_irqsave(&intercept_lock, flags);

    rule = find_rule(from_uid, to_uid);
    if (!rule) {
        spin_unlock_irqrestore(&intercept_lock, flags);
        return -ENOENT;
    }

    list_del(&rule->list);
    kfree(rule);
    rule_count--;

    spin_unlock_irqrestore(&intercept_lock, flags);

    pr_info("ksu_intercept: removed rule %d->%d (remaining: %d)\n",
            from_uid, to_uid, rule_count);

    return 0;
}

enum intercept_action ksu_check_setuid_intercept(uid_t from_uid, uid_t to_uid)
{
    struct uid_intercept_rule *rule;
    enum intercept_action action = INTERCEPT_ALLOW;
    unsigned long flags;

    spin_lock_irqsave(&intercept_lock, flags);

    rule = find_rule(from_uid, to_uid);
    if (rule) {
        action = rule->action;
        pr_debug("ksu_intercept: matched rule %d->%d action=%d\n",
                 from_uid, to_uid, action);
    }

    spin_unlock_irqrestore(&intercept_lock, flags);

    return action;
}

void ksu_clear_all_intercept_rules(void)
{
    struct uid_intercept_rule *rule, *tmp;
    unsigned long flags;
    int cleared = 0;

    spin_lock_irqsave(&intercept_lock, flags);

    list_for_each_entry_safe(rule, tmp, &intercept_rules, list) {
        list_del(&rule->list);
        kfree(rule);
        cleared++;
    }

    rule_count = 0;

    spin_unlock_irqrestore(&intercept_lock, flags);

    pr_info("ksu_intercept: cleared %d rules\n", cleared);
}

int ksu_get_intercept_rule_count(void)
{
    return rule_count;
}

void ksu_uid_intercept_init(void)
{
    pr_info("ksu_intercept: initialized (max_rules=%d)\n", MAX_INTERCEPT_RULES);
}

void ksu_uid_intercept_exit(void)
{
    ksu_clear_all_intercept_rules();
    pr_info("ksu_intercept: exited\n");
}
