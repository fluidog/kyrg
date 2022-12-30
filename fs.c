/**
 * @file fs.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief
 * @version 0.1
 * @date 2023-05-15
 *
 * @copyright Copyright (c) 2022
 *
 */
#include "ldim.h"

#include <linux/security.h>
#include <linux/uaccess.h>

// only specified program can write these files
static bool have_permission(void)
{
    static const char *allowed[] = {"kydima", "kydima_set", "cat", \
            "kytrust-agent", "kydimaex"};
    int i;
    const char *program = current->comm;

    for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
        if (!strcmp(program, allowed[i]))
            return true;

    pr_warn("Denied program %s wirte kyextend fs\n", program);

    return false;
}

static int seq_file_show_interval(struct seq_file *seq, void *v)
{
    seq_printf(seq, "%llu", ldim_get_periodic());
    return 0;
}
static int seq_file_interval_open(struct inode *inode, struct file *file)
{
    return single_open(file, &seq_file_show_interval, NULL);
}

static ssize_t write_interval(struct file *file, const char __user *buf,
                              size_t size, loff_t *ppos)
{
    unsigned int interval_sec, rc;

    if (!have_permission())
        return -EPERM;

    if (kstrtou32_from_user(buf, size, 10, &interval_sec))
        return -EINVAL;

    rc = ldim_set_periodic(interval_sec);
    if (rc)
        return rc;

    return size;
}

/**
 * @brief  add <path> <enforce> | del <path>
 *              eg. add /bin/bash 1
 */
static ssize_t write_policy_proc(struct file *file, const char __user *buf,
                                 size_t size, loff_t *ppos)
{
    int ret = -EINVAL;
    ssize_t length = 0;
    char *tmp, *opt, *path;
    bool enforce = 0;
    char *kbuf;

    if (!have_permission())
        return -EPERM;

    KZALLOC(kbuf, size);

    copy_from_user(kbuf, buf, size);

    opt = strsep(&kbuf, " ");
    if (unlikely(!opt || !kbuf))
        goto out;
    length += kbuf - opt;

    if (!strcmp(opt, "add")) {
        path = strsep(&kbuf, " ");
        if (unlikely(!path || !kbuf))
            goto out;
        length += kbuf - path;

        tmp = strsep(&kbuf, "\n");
        if (unlikely(!tmp || !kbuf || kstrtobool(tmp, &enforce)))
            goto out;
        length += kbuf - tmp;

        ret = rgproc_add_policy(path, enforce);
        if (!ret)
            ret = length; // return length

        goto out;
    }

    if (!strcmp(opt, "del")) {
        path = strsep(&kbuf, "\n");
        if (unlikely(!path || !kbuf))
            goto out;
        length += kbuf - path;

        rgproc_del_policy(path);
        ret = length; // return length
        goto out;
    }

out:
    pr_debug("%s %s %d, return:%d\n", opt, path, enforce, ret);
    kfree(opt); // kbuf pointer have changed, opt points the original kbuf.

    return ret;
}

/**
 * @brief add <modname> <enforce> | del <modname>
 *             eg. add kernel 1
 */
static ssize_t write_policy_kernel(struct file *file, const char __user *buf,
                                   size_t size, loff_t *ppos)
{
    int ret = -EINVAL;
    ssize_t length = 0;
    char *tmp, *opt, *modname;
    bool enforce = 0;
    char *kbuf;

    if (!have_permission())
        return -EPERM;

    KZALLOC(kbuf, size);

    copy_from_user(kbuf, buf, size);

    opt = strsep(&kbuf, " ");
    if (unlikely(!opt || !kbuf))
        goto out;
    length += kbuf - opt;

    if (!strcmp(opt, "add")) {
        modname = strsep(&kbuf, " ");
        if (unlikely(!modname || !kbuf))
            goto out;
        length += kbuf - modname;

        tmp = strsep(&kbuf, "\n");
        if (unlikely(!tmp || !kbuf || kstrtobool(tmp, &enforce)))
            goto out;
        length += kbuf - tmp;

        ret = rgkernel_add_policy(modname, enforce);
        if (!ret)
            ret = length; // return length

        goto out;
    }

    if (!strcmp(opt, "del")) {
        modname = strsep(&kbuf, "\n");
        if (unlikely(!modname || !kbuf))
            goto out;
        length += kbuf - modname;

        rgkernel_del_policy(modname);
        ret = length; // return length
        goto out;
    }

out:
    pr_debug("%s %s %d, return:%d\n", opt, modname, enforce, ret);
    kfree(opt); // kbuf pointer have changed, opt points the original kbuf.
    return ret;
}

static ssize_t write_trigger(struct file *file, const char __user *buf,
                             size_t size, loff_t *ppos)
{
    if (!have_permission())
        return -EPERM;
    ldim_do_validate();
    // any write to this file will trigger an immediate check
    // do_rg();
    return size;
}

static int seq_file_show_status(struct seq_file *seq, void *v)
{
    seq_printf(seq, "%d", ldim_get_status());
    return 0;
}
static int seq_file_status_open(struct inode *inode, struct file *file)
{
    return single_open(file, &seq_file_show_status, NULL);
}
static ssize_t write_status(struct file *file, const char __user *buf,
                            size_t size, loff_t *ppos)
{
    int status, rc;
    if (!have_permission())
        return -EPERM;

    if (kstrtos32_from_user(buf, size, 10, &status))
        return -EINVAL;

    rc = ldim_set_status(status);
    if (rc)
        return rc;

    return size;
}

static const struct file_operations interval_ops = {
    .owner = THIS_MODULE,
    .open = seq_file_interval_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = write_interval,
};

static const struct file_operations status_ops = {
    .owner = THIS_MODULE,
    .open = seq_file_status_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = write_status,
};

static const struct file_operations trigger_ops = {
    .owner = THIS_MODULE,
    .write = write_trigger,
};

static const struct file_operations policy_proc_ops = {
    .owner = THIS_MODULE,
    .open = rgproc_seq_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
    .write = write_policy_proc,
};
static const struct file_operations policy_kernel_ops = {
    .owner = THIS_MODULE,
    .open = rgkernel_seq_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
    .write = write_policy_kernel,
};

static const struct tree_descr ldim_files[] = {
    {"status", &status_ops, S_IRUGO | S_IWUSR},
    {"interval", &interval_ops, S_IRUGO | S_IWUSR},
    {"trigger", &trigger_ops, S_IRUGO | S_IWUSR},
    {"policy_modules", &policy_kernel_ops, S_IRUGO | S_IWUSR},
    {"policy_processes", &policy_proc_ops, S_IRUGO | S_IWUSR},
    /* last one */
    {NULL}};

static struct dentry *ldim_root = NULL, *files_dentry[10];

int ldim_fs_init(void)
{
    int i;
    pr_debug("Init ldim fs\n");

    ldim_root = securityfs_create_dir("ldim", NULL);
    if (IS_ERR_OR_NULL(ldim_root))
        return PTR_ERR(ldim_root) ?: -1;

    for (i = 0; ldim_files[i].name; i++) {
        files_dentry[i] = securityfs_create_file(ldim_files[i].name,
                                                 ldim_files[i].mode, ldim_root, NULL, ldim_files[i].ops);
    }
    pr_debug("Successfully init ldim fs\n");

    return 0;
}

void ldim_fs_exit(void)
{
    int i;
    if (!ldim_root)
        return;

    for (i = 0; ldim_files[i].name; i++) {
        securityfs_remove(files_dentry[i]);
    }
    securityfs_remove(ldim_root);

    pr_debug("Successfully exit ldim fs\n");
}
