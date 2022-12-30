## Makefile for the Linux kernel module.

# Overwrite the variables of "TARGET、FILE..." 
#	in "./.Kbuild.cfg" according to your needs.
#
# example:
# 	TARGET := module_name
# 	FILES := source1.c source2.c source3.c
#	ccflags-y := -DDEBUG
#	CFLAGS_<source1>.o := -DDEBUG
####################################################

# module name
TARGET ?= ldim
# source files
FILES ?= entry.c fs.c ldim-kernel.c ldim-processes.c ldim-core.c hash.c kallsyms-lookup-name.c periodic-timer.c thread.c walk-procmem.c

ifeq ($(CONFIG_TCG_TPM),y)
FILES += tpm.c
endif

# ccflags-y := -DDEBUG
# CFLAGS_<file>.o := -DDEBUG

obj-m += $(TARGET).o
$(TARGET)-y := $(FILES:%.c=%.o)

# $(warning pwd="$(shell pwd)" obj-m="$(obj-m)" $(TARGET)-y="$($(TARGET)-y)" )

KDIR ?= /lib/modules/$(shell uname -r)/build
INSTALLDIR ?= /lib/modules/$(shell uname -r)/updates

build:
	make -C $(KDIR) M=$(shell pwd) modules

clean:
	make -C $(KDIR) M=$(shell pwd) clean

install:
	install -d $(DESTDIR)$(INSTALLDIR)
	install -m 644 $(TARGET).ko $(DESTDIR)$(INSTALLDIR)
