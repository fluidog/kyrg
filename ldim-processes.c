/**
 * @file rg_processes.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief
 * @version 0.1
 * @date 2023-05-15
 *
 * @copyright Copyright (c) 2023
 *
 */
#include "ldim.h"

#include <linux/kprobes.h>
#include <linux/atmioc.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/fs.h>
#include <linux/file.h>

struct policy {
    struct list_head list;
    const char *exe_path;    // path of executable file
    char comm[TASK_COMM_LEN]; // for speed up
    struct list_head proces; // all process in this policy
    bool enforce;            // if kill process in this policy
    bool modified;           // if any process in this policy is modified
    struct rcu_head rcu;
};

#define MAX_VMMEM_COUNT 3
struct rgprocess {
    struct list_head list;
    struct policy *policy; // point to policy
    int pid;
    // struct task_struct *task;
    struct rcu_head rcu;
    atomic_t usage;
    bool modified;      // if modified
    ktime_t first_time; // first measure time, 0 means not calc hash
    ktime_t last_time;
    char sum_base_hash[HASH_ALG_SIZE];    // hash of code segment
    char sum_current_hash[HASH_ALG_SIZE]; // hash of code segment
    struct {
        unsigned long vm_start; /* Our start address within vm_mm. */
        unsigned long vm_end;   /* The first byte after our end address */
        bool modified;
        char base_hash[HASH_ALG_SIZE];    // hash of code segment
        char current_hash[HASH_ALG_SIZE]; // hash of code segment
        const char *vm_path;
    } vmmem[MAX_VMMEM_COUNT];
    int vmmem_index; // the count of vmmem in use
};

#define get_rgprocess(proc) do { atomic_inc(&(proc)->usage); } while(0)

static inline void put_rgprocess(struct rgprocess *proc)
{
    struct policy *p;
	if (atomic_dec_and_test(&proc->usage)){
        p = proc->policy;

        // remove
        // list_del(&proc->list);
        // synchronize_rcu();
        // kfree(proc);
        list_del_rcu(&proc->list);
        kfree_rcu(proc, rcu);

        // restore modified flage if all other proc ok
        rcu_read_lock();
        list_for_each_entry_rcu(proc, &p->proces, list)
        {
            if (proc->modified)
                break;
        }
        if (&proc->list == &p->proces)
            p->modified = 0;
        rcu_read_unlock();
    }
}

static LIST_HEAD(policies);

/**
 * @brief add a policy, if already exist, update it
 *
 * @param path
 * @param enforce
 * @return int
 */
int rgproc_add_policy(const char *exe_path, bool enforce)
{
    struct policy *p;
    struct task_struct *task;

    // already exist, just update it
    rcu_read_lock();
    list_for_each_entry_rcu(p, &policies, list)
    {
        if (strlen(p->exe_path) != strlen(exe_path) || strcmp(p->exe_path, exe_path)) {
            continue;
        }

        p->enforce = enforce;
        pr_debug("Update process policy=%s comm=%s enforce=%d\n\n",
                 p->exe_path, p->comm, p->enforce);
        audit_log(audit_context(), GFP_ATOMIC, AUDIT_KYRG,
                  "KYRG: Update process policy=%s comm=%s enforce=%d\n",
                  p->exe_path, p->comm, p->enforce);
        rcu_read_unlock();
        return 0;
    }
    rcu_read_unlock();

    pr_debug("Add policy...\n");

    KZALLOC(p, sizeof(struct policy));

    INIT_LIST_HEAD(&p->proces);
    p->enforce = enforce;
    p->modified = false;
    p->exe_path = kstrdup(exe_path, GFP_KERNEL);

    strncpy(p->comm, strrchr(p->exe_path, '/') +1, TASK_COMM_LEN-1);
    p->comm[TASK_COMM_LEN-1] = '\0';

    list_add_rcu(&p->list, &policies);

    for_each_process(task)
        rgproc_add_task_to_policy(task);

    pr_debug("Successfully add policy=%s comm=%s enforce=%d\n",
             p->exe_path, p->comm, p->enforce);
    audit_log(audit_context(), GFP_ATOMIC, AUDIT_KYRG,
              "KYRG: Add process policy=%s comm=%s enforce=%d\n",
              p->exe_path, p->comm, p->enforce);
    return 0;
}

/**
 * @brief delete a policy
 *
 * @param path
 */
void rgproc_del_policy(const char *exe_path)
{
    struct policy *p;
    struct rgprocess *proc, *n;

    list_for_each_entry_rcu(p, &policies, list)
    {
        if (strlen(p->exe_path) == strlen(exe_path) || strcmp(p->exe_path, exe_path) == 0)
            break;
    }
    // not exist
    if (&p->list == &policies)
        return;

    pr_debug("Delete policy=%s\n", p->exe_path);
    audit_log(audit_context(), GFP_ATOMIC, AUDIT_KYRG,
              "KYRG: Del process policy=%s\n", p->exe_path);

    // remove all process in this policy
    list_for_each_entry_safe(proc, n, &p->proces, list)
    {
        put_rgprocess(proc);
    }

    kfree(p->exe_path);
    list_del_rcu(&p->list);
    kfree_rcu(p, rcu);

    pr_debug("Successfully policy\n");
}

static void access_vm_cb(struct task_struct *task, char *buffer, unsigned long size, void *private)
{
    // struct rg_area *area = (struct rg_area *)private;
    hash_value_update(buffer, size);
}

static void access_mmap_cb(struct task_struct *task, struct vm_area_struct *mmap, void *private)
{
    struct rgprocess *proc = (struct rgprocess *)private;
    char *buf, *vm_path;

    // only code segment
    if (mmap->vm_flags & VM_WRITE)
        return;
    // if (!(mmap->vm_flags & VM_EXEC))
    //      return;

    // must have backing file (in case [vdso] segment)
    if (mmap->vm_file == NULL || mmap->vm_file->f_path.dentry == NULL)
        return;

    buf = kzalloc(PAGE_SIZE, GFP_KERNEL);

    // not include ".so" vmem because there have not ".so" while calling syscall:exec.
    vm_path = d_path(&mmap->vm_file->f_path, buf, PAGE_SIZE);
    if (strlen(vm_path) != strlen(proc->policy->exe_path) || strcmp(vm_path, proc->policy->exe_path))
        return;

    if (proc->vmmem_index >= MAX_VMMEM_COUNT) {
        pr_debug("Maps count exceed MAX_VMMEM_COUNT:%d\n", MAX_VMMEM_COUNT);
        kfree(buf);
        return;
    }

    pr_debug("Hash mmap of process(%d): path=%s, start=0x%px, end=0x%px, pgoff=%ld, flags=%lx\n",
             task->pid, vm_path,
             (void *)mmap->vm_start, (void *)mmap->vm_end, mmap->vm_pgoff,
             mmap->vm_flags);

    hash_value_init();
    walk_process_vm(task, mmap, access_vm_cb, NULL);
    hash_value_final(proc->vmmem[proc->vmmem_index].current_hash);

    pr_debug("Hash mmap of process(%d) successful\n", task->pid);

    // first hash this vmsegment
    if (!proc->vmmem[proc->vmmem_index].vm_path) {
        proc->vmmem[proc->vmmem_index].vm_path = kstrdup(vm_path, GFP_KERNEL);
        proc->vmmem[proc->vmmem_index].vm_start = mmap->vm_start;
        proc->vmmem[proc->vmmem_index].vm_end = mmap->vm_end;
        memcpy(proc->vmmem[proc->vmmem_index].base_hash,
               proc->vmmem[proc->vmmem_index].current_hash, HASH_ALG_SIZE);
    } else {
        // modified
        if (memcmp(proc->vmmem[proc->vmmem_index].base_hash,
                   proc->vmmem[proc->vmmem_index].current_hash, HASH_ALG_SIZE)) {
            proc->vmmem[proc->vmmem_index].modified = true;
            proc->modified = true;
            proc->policy->modified = true;
        }
    }

    proc->vmmem_index++;
    kfree(buf);
}

static void calc_proc_sum_hash(struct rgprocess *proc)
{
    int i, vmmem_count = proc->vmmem_index;

    hash_value_init();
    for (i = 0; i < vmmem_count; i++)
        hash_value_update(proc->vmmem[i].base_hash, HASH_ALG_SIZE);
    hash_value_final(proc->sum_base_hash);

    hash_value_init();
    for (i = 0; i < vmmem_count; i++)
        hash_value_update(proc->vmmem[i].current_hash, HASH_ALG_SIZE);
    hash_value_final(proc->sum_current_hash);
}


/**
 * @brief calculate hash of code segment
 *
 * @param p_ed_process
 * @return 0: all ok
 *         1: modified if do check
 */
static int _calc_proc_hash(void *arg)
{
    struct rgprocess *proc = (struct rgprocess *)arg;
    char *hash_hex_base, *hash_hex_current;

    if(!proc->pid){ // task exited already
        put_rgprocess(proc);
        return 0;
    }

    pr_debug("Hash proc start: %s(%d)\n", proc->policy->comm, proc->pid);

    proc->vmmem_index = 0;

    walk_process_mmaps(proc->pid, access_mmap_cb, proc);

    calc_proc_sum_hash(proc);

    hash_hex_base = kzalloc(PAGE_SIZE, GFP_KERNEL);
    hash_hex_current = kzalloc(PAGE_SIZE, GFP_KERNEL);

    bin2hex(hash_hex_base, proc->sum_base_hash, HASH_ALG_SIZE);
    bin2hex(hash_hex_current, proc->sum_current_hash, HASH_ALG_SIZE);

    if (proc->modified) {
        // pr_info("%s { process } for pid=%d comm=%s name=%s baseline=%s measurement=%s loginuid=%d\n",
        //         proc->policy->enforce ? "kill" : "warning",
        //         proc->pid, proc->policy->comm, proc->policy->exe_path,
        //         hash_hex_base, hash_hex_current, 0);

        audit_log(audit_context(), GFP_ATOMIC, AUDIT_KYRG,
                  "%s { process } for pid=%d comm=%s name=%s baseline=%s measurement=%s loginuid=%d\n",
                  proc->policy->enforce ? "kill" : "warning",
                  proc->pid, proc->policy->comm, proc->policy->exe_path,
                  hash_hex_base, hash_hex_current, 0);

        ldim_tpm_extend(proc->sum_current_hash, proc->policy->exe_path); // extend pcr as changed

        if (proc->policy->enforce) {
            // kill
            kill_pid(find_get_pid(proc->pid), SIGTERM, 1);
        }
    }

    proc->last_time = ktime_get_real();
    if(proc->first_time == 0){
        proc->first_time = proc->last_time;
        ldim_tpm_extend(proc->sum_current_hash, proc->policy->exe_path); // extend pcr as first calc
    }

    pr_debug("Hash proc sussessful: %s(%d), result:%d\n", proc->policy->comm, proc->pid, proc->modified);

    kfree(hash_hex_base);
    kfree(hash_hex_current);
    put_rgprocess(proc);

    return 0;
}

static int calc_proc_hash(struct rgprocess *proc)
{
    get_rgprocess(proc);
    ldim_thread_run_job(_calc_proc_hash, proc);
    return 0;
}

static struct file *private_get_mm_exe_file(struct mm_struct *mm)
{
	struct file *exe_file;

	rcu_read_lock();
	exe_file = rcu_dereference(mm->exe_file);
	if (exe_file && !get_file_rcu(exe_file))
		exe_file = NULL;
	rcu_read_unlock();
	return exe_file;
}

/**
 * @brief add a process to policy,
 *    should be called when process called 'execve',
 *    because we only get the code segemnt of process after 'execve'.
 *
 * @param p_ed_process
 * @return int
 */
int rgproc_add_task_to_policy(struct task_struct *task)
{
    struct mm_struct *mm;
    struct file *exe_file;
    struct policy *p;
    struct rgprocess *proc;
    char *exe_path, *buf;
    int len;

    mm = get_task_mm(task);
    if(!mm)
        return 0;

    exe_file = private_get_mm_exe_file(mm);
    if(!exe_file){
        mmput(mm);
        return 0;
    }

    KZALLOC(buf, PAGE_SIZE);

    // exe_path must be the same
    exe_path = d_path(&exe_file->f_path, buf, PAGE_SIZE);

    rcu_read_lock();
    list_for_each_entry_rcu(p, &policies, list)
    { 
        if (strcmp(p->exe_path, exe_path) == 0) {
            break;
        }
    }
    rcu_read_unlock();

    kfree(buf);
    mmput(mm);
    fput(exe_file);

    // should not be controled
    if (&p->list == &policies)
        return 0;

    // already added
    rcu_read_lock();
    list_for_each_entry_rcu(proc, &p->proces, list)
    {
        if (proc->pid == task->pid) {
            pr_warn("Bug: process(%d):%s already added to policy\n",
                    task->pid, p->exe_path);
            return 0;
        }
    }
    rcu_read_unlock();

    KZALLOC(proc, sizeof(struct rgprocess));

    pr_debug("Add process...\n");

    // Add to policy
    proc->policy = p;
    proc->pid = task->pid;
    proc->modified = false;
    proc->first_time = 0;
    proc->last_time = 0;
    atomic_set(&proc->usage, 1);

    // Calc hash of code segment
    calc_proc_hash(proc);

    list_add_rcu(&proc->list, &p->proces);

    pr_debug("Successfully add process(%d) to policy: %s\n",
             proc->pid, proc->policy->exe_path);
    return 0;
}

/**
 * @brief remove a process from policy,
 *    should be called when process exit.
 *
 * @param p_ed_process
 * @param force
 */
void rgproc_del_proc_from_policy(struct task_struct *task)
{
    struct policy *p;
    struct rgprocess *proc;

    list_for_each_entry_rcu(p, &policies, list){
        list_for_each_entry_rcu(proc, &p->proces, list){
            if(proc->pid == task->pid){
                pr_debug("Remove process(%d) from policy: %s\n", proc->pid, proc->policy->exe_path);
                proc->pid = 0;
                put_rgprocess(proc);
                return;
            }
        }
    }
}

void rgproc_do_validate(void)
{
    struct policy *p;
    struct rgprocess *proc;
    rcu_read_lock();
    list_for_each_entry_rcu(p, &policies, list)
    {
        list_for_each_entry_rcu(proc, &p->proces, list)
        {
            calc_proc_hash(proc);
        }
    }
    rcu_read_unlock();
}

static void *my_seq_start(struct seq_file *m, loff_t *pos)
{
    if(*pos == 0){
        seq_puts(m, "#<path> <enforce> <modified>\n#\
   <pid> <first-time>-<last-time> <modified> <base-hash>[-><current-hash>]\n#\
      <vmstart~vmend> <modified> <base-hash>[-><current-hash>] <path>\n");
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
    struct rgprocess *proc;
    struct policy *p;
    char *hash_hex;
    int vmmem_count, i;

    KZALLOC(hash_hex, PAGE_SIZE);

    p = (struct policy *)list_entry(v, struct policy, list);
    seq_printf(m, "\n%s %d %d\n",
               p->exe_path,
               p->enforce,
               p->modified);

    rcu_read_lock();
    list_for_each_entry_rcu(proc, &p->proces, list)
    {
        if(!proc->pid || !proc->first_time) // exit or not calc hash yet
            continue;

        bin2hex(hash_hex, proc->sum_base_hash, HASH_ALG_SIZE);
        seq_printf(m, "\t%d %llu-%llu %d 0x%s",
                   proc->pid,
                   proc->first_time,
                   proc->last_time,
                   proc->modified,
                   hash_hex);
        if (proc->modified) {
            bin2hex(hash_hex, proc->sum_current_hash, HASH_ALG_SIZE);
            seq_printf(m, "->0x%s", hash_hex);
        }
        seq_printf(m, "\n");

        // show mem info
        vmmem_count = proc->vmmem_index;
        for (i = 0; i < vmmem_count; i++) {
            bin2hex(hash_hex, proc->vmmem[i].base_hash, HASH_ALG_SIZE);
            seq_printf(m, "\t\t0x%px~0x%px %d 0x%s",
                       (void *)proc->vmmem[i].vm_start,
                       (void *)proc->vmmem[i].vm_end,
                       proc->vmmem[i].modified,
                       hash_hex);
            if (proc->vmmem[i].modified) {
                bin2hex(hash_hex, proc->vmmem[i].current_hash, HASH_ALG_SIZE);
                seq_printf(m, "->0x%s", hash_hex);
            }
            seq_printf(m, " %s\n", proc->vmmem[i].vm_path);
        }
    }
    rcu_read_unlock();

    kfree(hash_hex);
    return 0;
}

static const struct seq_operations my_seq_ops = {
    .start = my_seq_start,
    .next = my_seq_next,
    .stop = my_seq_stop,
    .show = my_seq_show};

int rgproc_seq_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &my_seq_ops);
}


static int execve_ret(struct kretprobe_instance *p_ri, struct pt_regs *p_regs)
{
    // get task
    struct task_struct *task = current;
    get_task_struct(task);

    rgproc_add_task_to_policy(task);

    put_task_struct(task);
    return 0;
}

static struct kretprobe execve_kretprobe = {
    .handler = execve_ret,
    // .entry_handler = execve_entry,
    //  .data_size = sizeof(struct my_data),
    /* Probe up to 20 instances concurrently. */
    .kp.symbol_name = "proc_exec_connector",
};

static int exit_entry(struct kretprobe_instance *p_ri, struct pt_regs *p_regs)
{
    struct task_struct *task = current;
    get_task_struct(task);

    rgproc_del_proc_from_policy(task);

    put_task_struct(task);
    return 0;
}

static struct kretprobe exit_kretprobe = {
    //  .handler = ret_handler,
    .entry_handler = exit_entry,
    //  .data_size = sizeof(struct my_data),
    /* Probe up to 20 instances concurrently. */
    .kp.symbol_name = "do_exit",
};

int rgproc_init(void)
{
    if (register_kretprobe(&execve_kretprobe) || register_kretprobe(&exit_kretprobe)) {
        pr_err("register_kretprobe failed!\n");
        return -1;
    }

    // rgproc_add_policy("/usr/bin/man", 0);
    // rgproc_add_policy("/usr/bin/ls", 0);

    pr_debug("Successfully init guard process\n");
    return 0;
}

void rgproc_exit(void)
{
    // free all resources
    struct policy *p, *p_n;
    struct rgprocess *proc, *proc_n;

    unregister_kretprobe(&execve_kretprobe);
    unregister_kretprobe(&exit_kretprobe);

    list_for_each_entry_safe(p, p_n, &policies, list)
    {
        list_for_each_entry_safe(proc, proc_n, &p->proces, list)
        {
            list_del(&proc->list);
            kfree(proc);
        }
        kfree(p->exe_path);
        list_del(&p->list);
        kfree(p);
    }

    pr_debug("Successfully exit guard process\n");
}