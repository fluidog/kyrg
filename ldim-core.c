/**
 * @file ldim-core.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief
 * @version 0.1
 * @date 2022-12-22
 *
 * @copyright Copyright (c) 2022
 *
 */
// #define DEBUG
#include "ldim.h"

#include <linux/kernel.h>

static enum {
    RG_STATUS_STOP = 0,
    RG_STATUS_RUNNING,
    RG_STATUS_PERIOD,
    RG_STATUS_EVENT,
    RG_STATUS_MAX,
} rg_status = RG_STATUS_RUNNING;


static char *hash_alg = "sm3";
module_param(hash_alg, charp, S_IRUSR | S_IWUSR);

static unsigned long interval = 5 * 60; // 5 minute
module_param(interval, ulong, S_IRUSR | S_IWUSR);

int ldim_do_validate(void)
{
    if (rg_status == RG_STATUS_STOP)
        return 0;

    pr_debug("Do ldim\n");

    rgkernel_do_validate();
    rgproc_do_validate();

    pr_info("Successfully do ldim integrity validation\n");
    return 0;
}

static int start_rg(void)
{
    if (interval == 0) // not periodic
        return 0;

    init_periodic_timer(ldim_do_validate, interval * 1000);

    return 0;
}

static void stop_rg(void)
{
    exit_periodic_timer();
}

int ldim_get_status(void)
{
    return rg_status;
}

int ldim_set_status(int status)
{
    if (status >= RG_STATUS_MAX)
        return -EINVAL;

    if (rg_status == RG_STATUS_STOP && status >= RG_STATUS_RUNNING)
        start_rg();

    if (rg_status >= RG_STATUS_RUNNING && status == RG_STATUS_STOP)
        stop_rg();
    
    rg_status = status;

    return 0;
}

unsigned long long ldim_get_periodic(void)
{
    return interval;
}

int ldim_set_periodic(unsigned long long period_sec)
{
    interval = period_sec;

    if (rg_status == RG_STATUS_STOP)
        return 0;

    stop_rg();
    return start_rg();
}

int ldim_init(void)
{
    int rc;

    rc = hash_alg_init(hash_alg);
    if (rc)
        return rc;

    rc = rgkernel_init();
    if (rc)
        return rc;

    rc = rgproc_init();
    if (rc)
        return rc;

    rc = ldim_fs_init();
    if (rc)
        return rc;

    ldim_thread_init();

    if (rg_status >= RG_STATUS_RUNNING)
        return start_rg();

    pr_info("Kylin Runtime Guard init success!\n");

    return 0;
}

void ldim_exit(void)
{
    if (rg_status >= RG_STATUS_RUNNING)
        stop_rg();

    ldim_thread_exit();

    ldim_fs_exit();

    rgkernel_exit();

    rgproc_exit();

    hash_alg_exit();
    pr_info("Kylin Runtime Guard exit.\n");
}