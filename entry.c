#include <linux/kernel.h>
#include <linux/module.h>

#include "ldim.h"

// Overload these two weak functions.
int __weak init_main(void)
{
    return ldim_init();
}
void __weak exit_main(void)
{
    ldim_exit();
}

int __init module_init_main(void)
{
    pr_debug("Hello world!\n");

    return init_main();
}

void __exit module_exit_main(void)
{
    exit_main();
    pr_debug("Goodbye world!\n");
}

#ifdef MODULE
module_init(module_init_main);
#else
late_initcall_sync(module_init_main);
#endif
module_exit(module_exit_main);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("liuqi");
MODULE_VERSION("v0.1");
MODULE_DESCRIPTION("module example");
