/**
 * @file thread.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief 
 * @version 0.1
 * @date 2023-09-10
 * 
 * @copyright Copyright (c) 2023
 * 
 */
#include <linux/kthread.h>

#include <linux/kfifo.h>
#include <linux/wait.h>


struct job{
	int (*f)(void *);
	void *arg;
};

#define FIFO_SIZE 4096

DEFINE_KFIFO(fifo, struct job, FIFO_SIZE);
DECLARE_WAIT_QUEUE_HEAD(wq);

int ldim_thread_run_job(int (*f)(void *), void *arg)
{
    int err = 0;
	struct job j = {f, arg};

    err = kfifo_in(&fifo, &j, 1);
	if(err < 0){
		pr_err("kfifo_in err");
		return -1;
	}
    wake_up(&wq);
    return 0;
}

static int kyrt_thread(void *arg)
{
	int err;
	struct job j;

	while (!kthread_should_stop()){

		wait_event_timeout(wq, kfifo_len(&fifo), 100);
		err = kfifo_out(&fifo, &j, 1);

		if (err == 0) // empty
			continue;

		if(err != 1){// something wrong
			pr_err("kfifo_out err:%d", err);
			continue;
		}

		if(j.f)
			j.f(j.arg);
	}

	return 0;
}

static struct task_struct *ldim_task;

int ldim_thread_init(void)
{
    ldim_task = kthread_run(kyrt_thread, NULL, "ldim");
	if (IS_ERR(ldim_task))
		return -1;
	return 0;
}

void ldim_thread_exit(void)
{
    kthread_stop(ldim_task);
}
