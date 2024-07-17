ifndef KERNELDIR
	KERNELDIR  := /lib/modules/$(shell uname -r)/build
endif

obj-m += the_ref.o

the_ref-objs := utils/hash.o utils/func_aux.o ref.o

# Aggiungo CFLAGS per abilitare C99
ccflags-y := -std=gnu99

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	
mount:
	insmod the_ref.ko the_file=$(realpath ./singlefile-FS/mount/the-file)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

unmount:
	rmmod the_ref.ko