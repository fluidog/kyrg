/**
 * @file rg_modlist.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief
 * @version 0.1
 * @date 2023-05-15
 *
 * @copyright Copyright (c) 2023
 *
 */
#include "ldim.h"

struct rgmem {
    void *base;
    unsigned long size;
    bool modified;
    char base_hash[HASH_ALG_SIZE]; // hash of csegment
    char current_hash[HASH_ALG_SIZE];
};

#define MAX_VMMEM_COUNT 3
struct policy {
    struct list_head list;
    const char *modname;
    struct module *module;
    bool enforce;
    bool modified;
    int vmmem_index; // the count of vmmem in use
    struct rgmem vmmem[MAX_VMMEM_COUNT];
    char sum_base_hash[HASH_ALG_SIZE];    // hash of code segment
    char sum_current_hash[HASH_ALG_SIZE]; // hash of code segment
    ktime_t first_time;                   // measure time
    ktime_t last_time;
};

static LIST_HEAD(policies);

struct module *(*ksyms_find_module)(const char *name);

static void calc_module_hash(struct policy *p, bool init)
{
    int i, vmmem_count = p->vmmem_index;

    // not be inserted
    if (!p->module)
        return;

    for (i = 0; i < vmmem_count; i++) {
        if (!p->vmmem[i].base) // addr 0 means jump over
            continue;
        hash_value((void *)p->vmmem[i].base, p->vmmem[i].size, p->vmmem[i].current_hash);
        if (init) {
            memcpy(p->vmmem[i].base_hash, p->vmmem[i].current_hash, HASH_ALG_SIZE);
        } else {
            if (memcmp(p->vmmem[i].base_hash, p->vmmem[i].current_hash, HASH_ALG_SIZE)) {
                p->vmmem[i].modified = true;
                p->modified = true;
            }
        }
    }

    if (init) {
        hash_value_init();
        for (i = 0; i < vmmem_count; i++) {
            hash_value_update(p->vmmem[i].base_hash, HASH_ALG_SIZE);
        }
        hash_value_final(p->sum_base_hash);
        p->first_time = ktime_get_real();

        ldim_tpm_extend(p->sum_base_hash, p->modname); // extend pcr as first calc
    }

    // Update current hash only when modified
    if (p->modified) {
        hash_value_init();
        for (i = 0; i < vmmem_count; i++) {
            hash_value_update(p->vmmem[i].current_hash, HASH_ALG_SIZE);
        }
        hash_value_final(p->sum_current_hash);

        ldim_tpm_extend(p->sum_current_hash, p->modname); // extend pcr as changed
    }

    p->last_time = ktime_get_real();
}

#include <asm/syscall.h>

static int rgkernel_get_sctmem(struct rgmem *mem)
{
    mem->base = (void *)ksyms_kallsyms_lookup_name("sys_call_table");
    mem->size = NR_syscalls * sizeof(void *);
    return 0;
}

#if defined(__i386__) || defined(__x86_64__)
#include <asm/desc.h>
#endif

static int rgkernel_get_idtmem(struct rgmem *mem)
{
#if defined(__i386__) || defined(__x86_64__)
    struct desc_ptr idt;
    store_idt(&idt);
    mem->base = (void *)idt.address;
    mem->size = idt.size;
#else // TODO: other arch
    mem->base = (void *)0;
    mem->size = 0;
#endif
    return 0;
}

static int rgkernel_get_kernelmem(struct rgmem *mem)
{
    mem->base = (void *)ksyms_kallsyms_lookup_name("_stext");
    mem->size = ksyms_kallsyms_lookup_name("_etext") - (unsigned long)mem->base;
    return 0;
}

int rgkernel_add_module_to_policy(struct module *module)
{
    struct policy *p;
    size_t len = strlen(module->name);

    list_for_each_entry(p, &policies, list)
        if (len == strlen(p->modname) && strcmp(p->modname, module->name) == 0)
            break;

    // not exist
    if (&p->list == &policies)
        return 0;

    p->module = module;
    p->vmmem_index = 2;
    p->vmmem[0].base = module->core_layout.base;
    p->vmmem[0].size = module->core_layout.text_size;
    p->vmmem[1].base = module->core_layout.base + module->core_layout.text_size;
    p->vmmem[1].size = module->core_layout.ro_size - module->core_layout.text_size;

    calc_module_hash(p, 1);
    return 0;
}

void rgkernel_del_module_from_policy(struct module *module)
{
    struct policy *p;
    size_t len = strlen(module->name);

    list_for_each_entry(p, &policies, list) 
        if (len == strlen(p->modname) && strcmp(p->modname, module->name) == 0) 
            break;

    // not exist
    if (&p->list == &policies)
        return;

    p->module = NULL;
    p->vmmem_index = 0;
}

/**
 * @brief add a policy
 *
 * @param modname
 * @param enforce
 * @return int
 */
int rgkernel_add_policy(const char *modname, bool enforce)
{
    struct policy *p;
    struct module *module;
    size_t len = strlen(modname);

    // already exist
    list_for_each_entry(p, &policies, list)
    {
        if (len == strlen(p->modname) && strcmp(p->modname, modname) == 0) {
            p->enforce = enforce;
            pr_debug("Update module policy: name=%s enforce=%d\n", modname, enforce);
            audit_log(audit_context(), GFP_ATOMIC, AUDIT_KYRG,
                      "KYRG: Update module policy: name=%s enforce=%d\n", modname, enforce);
            return 0;
        }
    }

    KZALLOC(p, sizeof(struct policy));

    p->enforce = enforce;
    p->modified = false;
    p->modname = kstrdup(modname, GFP_KERNEL);
    p->vmmem_index = 0;
    p->module = NULL;

    list_add_tail(&p->list, &policies);

    module = ksyms_find_module(modname);
    if (module)
        rgkernel_add_module_to_policy(module);

    if (!strcmp(modname, "_sct")) {
        list_move(&p->list, &policies);
        p->module = (typeof(p->module))1; // just for mark
        p->vmmem_index = 1;
        rgkernel_get_sctmem(&p->vmmem[0]);
        calc_module_hash(p, 1);
    }
    if (!strcmp(modname, "_idt")) {
        list_move(&p->list, &policies);
        p->module = (typeof(p->module))1; // just for mark
        p->vmmem_index = 1;
        rgkernel_get_idtmem(&p->vmmem[0]);
        calc_module_hash(p, 1);
    }
    if (!strcmp(modname, "_kernel")) {
        list_move(&p->list, &policies);
        p->module = (typeof(p->module))1; // just for mark
        p->vmmem_index = 1;
        rgkernel_get_kernelmem(&p->vmmem[0]);
        calc_module_hash(p, 1);
    }

    pr_debug("Add module policy: name=%s enforce=%d\n", modname, enforce);
    audit_log(audit_context(), GFP_ATOMIC, AUDIT_KYRG,
              "KYRG: Add module policy: name=%s enforce=%d\n", modname, enforce);
    return 0;
}

/**
 * @brief remove a policy
 *
 * @param modname
 */
void rgkernel_del_policy(const char *modname)
{
    struct policy *p;
    size_t len = strlen(modname);

    list_for_each_entry(p, &policies, list)
    {
        if (len == strlen(p->modname) && strcmp(p->modname, modname) == 0) {
            kfree(p->modname);
            list_del(&p->list);
            kfree(p);
            pr_debug("Del module policy: name=%s\n", modname);
            audit_log(audit_context(), GFP_ATOMIC, AUDIT_KYRG,
                      "KYRG: Del module policy: name=%s\n", modname);
            return;
        }
    }
}

void rgkernel_do_validate(void)
{
    struct policy *p;
    char *hash_hex_base, *hash_hex_current;

    hash_hex_base = kzalloc(PAGE_SIZE, GFP_KERNEL);
    hash_hex_current = kzalloc(PAGE_SIZE, GFP_KERNEL);

    list_for_each_entry(p, &policies, list)
    {
        calc_module_hash(p, 0);
        if (p->modified) {
            bin2hex(hash_hex_base, p->sum_base_hash, HASH_ALG_SIZE);
            bin2hex(hash_hex_current, p->sum_current_hash, HASH_ALG_SIZE);
            // pr_info("%s { module } for pid=NULL comm=NULL name=%s baseline=%s measurement=%s loginuid=%d\n",
            //         p->enforce ? "kill" : "warning",
            //         p->modname, hash_hex_base, hash_hex_current, 0);
            audit_log(audit_context(), GFP_ATOMIC, AUDIT_KYRG,
                      "%s { module } for pid=NULL comm=NULL name=%s baseline=%s measurement=%s loginuid=%d\n",
                      p->enforce ? "kill" : "warning",
                      p->modname, hash_hex_base, hash_hex_current, 0);

            if (p->enforce) {
                // kill
            }
        }
    }

    kfree(hash_hex_base);
    kfree(hash_hex_current);
}

static void *my_seq_start(struct seq_file *m, loff_t *pos)
{
    if(*pos == 0){
        seq_puts(m, "#<modname> <enforce> <first-time>-<last-time> <modified> <base-hash>[-><current-hash>]\n#\
   <vmstart~vmend> <modified> <base-hash>[-><current-hash>]\n");
    }
    return seq_list_start(&policies, *pos);
}
static void *my_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
    return seq_list_next(v, &policies, pos);
}
static void my_seq_stop(struct seq_file *m, void *v)
{
    /* Nothing to do here */
}
static int my_seq_show(struct seq_file *m, void *v)
{
    struct policy *p;
    char *hex_hash;
    int i;

    KZALLOC(hex_hash, PAGE_SIZE);

    p = (struct policy *)list_entry(v, struct policy, list);
    seq_printf(m, "\n%s %d %llu-%llu %d ",
               p->modname,
               p->enforce,
               p->first_time,
               p->last_time,
               p->modified);

    if (!p->module) { // not inserted
        seq_printf(m, "xxx\n");
        kfree(hex_hash);
        return 0;
    }
    // show hash value
    bin2hex(hex_hash, p->sum_base_hash, HASH_ALG_SIZE);
    seq_printf(m, "0x%s", hex_hash);
    if (p->modified) {
        bin2hex(hex_hash, p->sum_current_hash, HASH_ALG_SIZE);
        seq_printf(m, "->0x%s", hex_hash);
    }
    seq_printf(m, "\n");

    for (i = 0; i < p->vmmem_index; i++) {
        seq_printf(m, "\t0x%px~0x%px %d ",
                   p->vmmem[i].base,
                   (char *)p->vmmem[i].base + p->vmmem[i].size,
                   p->vmmem[i].modified);
        bin2hex(hex_hash, p->vmmem[i].base_hash, HASH_ALG_SIZE);
        seq_printf(m, "0x%s", hex_hash);
        if (p->vmmem[i].modified) {
            bin2hex(hex_hash, p->vmmem[i].current_hash, HASH_ALG_SIZE);
            seq_printf(m, "->0x%s", hex_hash);
        }
        seq_printf(m, "\n");
    }

    kfree(hex_hash);
    return 0;
}

static const struct seq_operations my_seq_ops = {
    .start = my_seq_start,
    .next = my_seq_next,
    .stop = my_seq_stop,
    .show = my_seq_show};

int rgkernel_seq_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &my_seq_ops);
}


static int module_event_notifier(struct notifier_block *this, unsigned long event, void *kmod)
{
    struct module *module = (struct module *)kmod;

    if (event == MODULE_STATE_COMING) {
        rgkernel_add_module_to_policy(module);
    }

    if (event == MODULE_STATE_GOING) {
        rgkernel_del_module_from_policy(module);
    }
    return 0;
}
static struct notifier_block module_block_notifier = {
    .notifier_call = module_event_notifier,
    .next = NULL,
    .priority = INT_MAX
};

int rgkernel_init(void)
{
    ksyms_find_module = (typeof(ksyms_find_module))ksyms_kallsyms_lookup_name("find_module");
    if (IS_ERR_OR_NULL(ksyms_find_module)) {
        pr_err("ksyms not found");
        return -ENXIO;
    }

    // rgkernel_add_policy("_kernel", 0);
    // rgkernel_add_policy("_sct", 0);
    register_module_notifier(&module_block_notifier);

    pr_debug("Successfully init guard kernel module\n");
    return 0;
}

void rgkernel_exit(void)
{
    // free all resources
    struct policy *p, *n;
    unregister_module_notifier(&module_block_notifier);

    list_for_each_entry_safe(p, n, &policies, list)
    {
        kfree(p->modname);
        list_del(&p->list);
        kfree(p);
    }
    pr_debug("Successfully Exit guard kernel module\n");
}
