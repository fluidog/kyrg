MAKEFLAGS += --no-print-directory

build:
	make -f Kbuild build
	make -C test/ build

clean:
	make -f Kbuild clean
	make -C test/ clean

install:
	make -f Kbuild install

test:
	insmod ldim.ko dyndbg="+p"
	make -C test/ test
	rmmod ldim.ko

