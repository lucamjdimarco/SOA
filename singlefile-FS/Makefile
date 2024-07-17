obj-m += singlefilefs.o
singlefilefs-objs += singlefilefs_src.o file.o dir.o

all:
	gcc singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

load:
	sudo insmod singlefilefs.ko

create:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	mkdir mount
	
mnt:
	sudo mount -o loop -t singlefilefs image ./mount/

	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
remove:
	rm -rf image
	rm -rf mount
	
	
	
