#ifndef __KSU_NETLINK_H
#define __KSU_NETLINK_H

#include <linux/types.h>

int ksu_netlink_init(void);
void ksu_netlink_exit(void);
void ksu_clear_access_cache(void);

#endif
