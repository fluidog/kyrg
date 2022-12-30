
build: build-process build-module
clean: clean-process clean-module
test: test-process test-module test-kernel

app := test-ldim-process

build-process: $(app)

test-process: build-process
	./$(app) &
	echo "add `realpath test-ldim-process` 1" | cat > /sys/kernel/security/ldim/policy_processes
	echo 1 | cat > /sys/kernel/security/ldim/trigger
	# It will modify the code segment by itself. When the specified signal is received.
	/bin/kill -s 'SIGUSR1' `pidof -s $(app)`
	echo 1 | cat > /sys/kernel/security/ldim/trigger
	echo "del `realpath test-ldim-process`" | cat > /sys/kernel/security/ldim/policy_processes

clean-process:
	rm -f *.o $(app)

## Makefile for the Linux kernel module

MODULE := test-ldim
FILES := test-ldim-module.c

ifdef KERNELRELEASE

obj-m += $(MODULE).o
$(MODULE)-m := $(FILES:%.c=%.o)

else

KDIR ?= /lib/modules/$(shell uname -r)/build

build-module:
	make -C $(KDIR) M=$(shell pwd) modules
clean-module:
	make -C $(KDIR) M=$(shell pwd) clean

test-module: MODPARAMS := name=ldim_do_validate
test-module: MOD := ldim
test-kernel: MODPARAMS := name=vprintk
test-kernel: MOD := kernel

test-module test-kernel:
	echo "add $(MOD) 0" | cat > /sys/kernel/security/ldim/policy_modules
	echo 1 | cat > /sys/kernel/security/ldim/trigger
	# This ko will modify the code segment of the ldim module.
	insmod $(MODULE).ko $(MODPARAMS)
	echo 1 | cat > /sys/kernel/security/ldim/trigger
	rmmod $(MODULE)
	echo "del $(MOD)" | cat > /sys/kernel/security/ldim/policy_modules

endif
