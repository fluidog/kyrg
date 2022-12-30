// #define DEBUG
#define pr_fmt(fmt) KBUILD_MODNAME": " fmt

#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/kprobes.h>

#define SYMLEN 64
static char symbol[SYMLEN];

module_param_string(name, symbol, SYMLEN, 0644);

static struct kprobe kp = {
        .symbol_name = symbol,
};

int __init init_main(void)
{
	int error = 0;
	pr_info("Start test ldim module, symbol:%s!\n", symbol);

	// kprobe will modify the instruction at the address of symbol
	error = register_kprobe(&kp);
	if(error < 0){
		pr_err("register_kprobe failed, returned %d\n", error);
		return error;
	}

	pr_info("Modify the code at %pS\n", kp.addr);
	
	return 0;
}

void __exit exit_main(void)
{
	unregister_kprobe(&kp);
	pr_info("End test ldim module!\n");
}

module_init(init_main);
module_exit(exit_main);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("liuqi");
MODULE_VERSION("v0.1");
MODULE_DESCRIPTION("TEST_KYRG");
