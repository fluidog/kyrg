// #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt


#ifndef KYEXTEND_H
#define KYEXTEND_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/audit.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#define AUDIT_KYRG 1467

// Support only "sm3" and "sha256", for its fixed length
#define HASH_ALG_SIZE (256 >> 3) // 256/8 bytes
#define HASH_ALG_HEX_SIZE ((HASH_ALG_SIZE>>1) + 1) // 256/4 + 1 bytes

#define KZALLOC(ptr, size) \
  { ptr = kzalloc(size, GFP_KERNEL); \
  if (IS_ERR_OR_NULL(ptr)) \
     return PTR_ERR(ptr) ?: -1; }

unsigned long ksyms_kallsyms_lookup_name(const char *name);

int ldim_init(void);
void ldim_exit(void);
int ldim_do_validate(void);
int ldim_get_status(void);
int ldim_set_status(int status);
unsigned long long ldim_get_periodic(void);
int ldim_set_periodic(unsigned long long period_sec);

void init_periodic_timer(int (*cb)(void), unsigned long long msecs_period);
void exit_periodic_timer(void);

int ldim_fs_init(void);
void ldim_fs_exit(void);


int hash_alg_init(char *hash_alg_name);
void hash_alg_exit(void);
// Call hash_alg_init() before using these below.
int hash_value_init(void);
int hash_value_update(const u8 *data, unsigned int len);
int hash_value_final(u8 *out);
int hash_value(const u8 *data, unsigned int len, u8 *out);

#ifdef CONFIG_TCG_TPM
void ldim_tpm_extend(const u8 *hash, const char *path);
#else
static inline void ldim_tpm_extend(const u8 *hash, const char *path){
  return;
}
#endif

int walk_process_vm(struct task_struct *task, struct vm_area_struct *mmap,
                    void (*func)(struct task_struct *, char *, unsigned long, void *), void *);
int walk_process_mmaps(int vpid, void (*func)(struct task_struct *, struct vm_area_struct *, void *), void *private);

int rgproc_init(void);
void rgproc_exit(void);
int rgproc_add_policy(const char* path, bool enforce);
void rgproc_del_policy(const char* path);
int rgproc_seq_open(struct inode *inode, struct file *file);
void rgproc_do_validate(void);
int rgproc_add_task_to_policy(struct task_struct *task);
void rgproc_del_proc_from_policy(struct task_struct *task);

int rgkernel_init(void);
void rgkernel_exit(void);
int rgkernel_add_policy(const char* modname, bool enforce);
void rgkernel_del_policy(const char* modname);
void rgkernel_do_validate(void);
int rgkernel_seq_open(struct inode *inode, struct file *file);

int ldim_thread_init(void);
void ldim_thread_exit(void);
int ldim_thread_run_job(int (*f)(void *), void *arg);

#endif
