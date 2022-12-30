/**
 * @file main.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief
 * @version 0.1
 * @date 2022-12-16
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/version.h>

// /*
//  * Access another process' address space as given in mm.  If non-NULL, use the
//  * given task for page fault accounting.
//  */
// int __access_remote_vm_locked(struct task_struct *tsk, struct mm_struct *mm,
// 		unsigned long addr, void *buf, int len, unsigned int gup_flags)
// {
// 	struct vm_area_struct *vma;
// 	void *old_buf = buf;
// 	int write = gup_flags & FOLL_WRITE;

// 	/* ignore errors, just check how much was successfully transferred */
// 	while (len) {
// 		int bytes, ret, offset;
// 		void *maddr;
// 		struct page *page = NULL;

// 		ret = get_user_pages_remote(tsk, mm, addr, 1,
// 				gup_flags, &page, &vma, NULL);
// 		if (ret <= 0) {
// #ifndef CONFIG_HAVE_IOREMAP_PROT
// 			break;
// #else
// 			/*
// 			 * Check if this is a VM_IO | VM_PFNMAP VMA, which
// 			 * we can access using slightly different code.
// 			 */
// 			vma = find_vma(mm, addr);
// 			if (!vma || vma->vm_start > addr)
// 				break;
// 			if (vma->vm_ops && vma->vm_ops->access)
// 				ret = vma->vm_ops->access(vma, addr, buf,
// 							  len, write);
// 			if (ret <= 0)
// 				break;
// 			bytes = ret;
// #endif
// 		} else {
// 			bytes = len;
// 			offset = addr & (PAGE_SIZE-1);
// 			if (bytes > PAGE_SIZE-offset)
// 				bytes = PAGE_SIZE-offset;

// 			maddr = kmap(page);
// 			if (write) {
// 				copy_to_user_page(vma, page, addr,
// 						  maddr + offset, buf, bytes);
// 				set_page_dirty_lock(page);
// 			} else {
// 				copy_from_user_page(vma, page, addr,
// 						    buf, maddr + offset, bytes);
// 			}
// 			kunmap(page);
// 			put_page(page);
// 		}
// 		len -= bytes;
// 		buf += bytes;
// 		addr += bytes;
// 	}

// 	return buf - old_buf;
// }



/**
 * @brief walk through process memory of a mmap.
 *
 * @param task
 * @param mmap
 * @param private
 * @param func
 * @return int
 */
int walk_process_vm(struct task_struct *task, struct vm_area_struct *mmap,
                    void (*func)(struct task_struct *, char *, unsigned long, void *), void *private)
{
    int rc;
    char *vaddr;
    struct page *pages;
    unsigned long vm_start, length, offset, bytes;

    vm_start= mmap->vm_start;
    length = mmap->vm_end - mmap->vm_start;

    while (length > 0) {
        if(!task->mm){ // sometimes "mm" change to be NULL, its weird.
            pr_debug("walk_process_vm: mm is NULL!\n");
            return -1;
        }
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
        rc = get_user_pages_remote(task, task->mm, vm_start, 1,
				0, &pages, NULL, NULL);
#else
        rc = get_user_pages_remote(task->mm, vm_start, 1,
				0, &pages, NULL, NULL);
#endif
        if( rc <= 0){ // not retry, just return err
            pr_err("get_user_pages_remote err, task:%s(%d) addr:%lx\n", 
                    task->comm, task->pid, vm_start);
            return -1;
        }

		offset = vm_start & (PAGE_SIZE-1);
        bytes = length;
		if (bytes > PAGE_SIZE-offset)
			bytes = PAGE_SIZE-offset;

        vaddr = kmap(pages);

        if (func)
            func(task, vaddr, bytes, private);

        kunmap(pages);
		put_page(pages);

        length -= bytes;
		vm_start += bytes;
    }

    return 0;
}

/**
 * @brief walk through process mmaps.
 *
 * @param vpid
 * @param func
 * @return int
 */
int walk_process_mmaps(int vpid, void (*func)(struct task_struct *, struct vm_area_struct *, void *), void *private)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *mmap;
    int rc = 0;

    task = get_pid_task(find_get_pid(vpid), PIDTYPE_PID);
    if (IS_ERR_OR_NULL(task))
        return PTR_ERR(task) ?: -1;

    mm = get_task_mm(task);
    if (IS_ERR_OR_NULL(mm)){
        put_task_struct(task);
        return PTR_ERR(mm) ?: -1;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    if (down_read_killable(&mm->mmap_sem)){
#else
    if (down_read_killable(&mm->mmap_lock)){
#endif
        pr_err("Killed while acquiring mm->mmap_sem");
		return 0;
    }

    for (mmap = mm->mmap; mmap != NULL; mmap = mmap->vm_next) {
        if (func)
            func(task, mmap, private);
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    up_read(&mm->mmap_sem);
#else
    up_read(&mm->mmap_lock);
#endif

    mmput(mm);
    put_task_struct(task);
    return rc;
}

// example usage
static void simple_access_vm_cb(struct task_struct *task, char *buffer, unsigned long size, void *private)
{
    // print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 4, buffer, size, true);
    return;
}

static void simple_access_mmap_cb(struct task_struct *task, struct vm_area_struct *mmap, void *private)
{
    char *buf;
    // only code segment
    if (!(mmap->vm_flags & VM_EXEC))
        return;

    // must have backing file (in case [vdso] segment)
    if (mmap->vm_file == NULL || mmap->vm_file->f_path.dentry == NULL)
        return;

    buf = kzalloc(PAGE_SIZE, GFP_KERNEL);

    pr_debug("path: %s, start: %lx, end: %lx, pgoff: %lx, flags: %lx",
             d_path(&mmap->vm_file->f_path, buf, 256),
             mmap->vm_start, mmap->vm_end, mmap->vm_pgoff,
             mmap->vm_flags);

    kfree(buf);

    walk_process_vm(task, mmap, simple_access_vm_cb, NULL);
}

int simple_access_process_memory(int vpid)
{
    return walk_process_mmaps(vpid, simple_access_mmap_cb, NULL);
}
