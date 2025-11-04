#ifndef __KSU_UID_INTERCEPT_H
#define __KSU_UID_INTERCEPT_H

#include <linux/types.h>

enum intercept_action {
    INTERCEPT_ALLOW = 0,
    INTERCEPT_DENY = 1,
    INTERCEPT_LOG = 2,
};

int ksu_add_intercept_rule(uid_t from_uid, uid_t to_uid, enum intercept_action action);
int ksu_remove_intercept_rule(uid_t from_uid, uid_t to_uid);
enum intercept_action ksu_check_setuid_intercept(uid_t from_uid, uid_t to_uid);
void ksu_clear_all_intercept_rules(void);
int ksu_get_intercept_rule_count(void);
void ksu_uid_intercept_init(void);
void ksu_uid_intercept_exit(void);

#endif
