#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>


int add(int a, int b)
{
    return 5;
}

int add1(int a, int b)
{
    return 7;
}

void sig_user1_handler(int sig, siginfo_t *si, void *data)
{
    int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize < 0) {
        pagesize = 4096;
    }

    int len = (unsigned long)add1-(unsigned long)add;

    uintptr_t addr = (((uintptr_t)add) / pagesize) * pagesize;
    fprintf(stderr, "%s: iminus: %p, aligned: 0x%lx, sz %d\n", __func__, add, addr, len);
    if (mprotect((void*)addr, (uintptr_t)add - addr + len, PROT_WRITE|PROT_READ|PROT_EXEC) < 0) {
        fprintf(stderr, "%s\n", strerror(errno));
    }

    memcpy((void*)add, (void*)add1, len);

    if (mprotect((void*)addr, (uintptr_t)&add - addr + len, PROT_READ|PROT_EXEC) < 0) {
        fprintf(stderr, "%s\n", strerror(errno));
    }
}


int main()
{
    struct sigaction newact, oldact;
    sigemptyset(&newact.sa_mask);
    newact.sa_sigaction = sig_user1_handler;
    sigaction(SIGUSR1, &newact, &oldact);

    for(;;)
    {
        //printf("%d\n", add(1, 1));
        sleep(3);
    }
}
