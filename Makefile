SYSNAME:=${shell uname}
SYSNAME!=uname
CFLAGS=-Wall -g -I include -DSYSNAME=$(SYSNAME)
LFLAGS=-Llibspfs -lspfs

.PHONEY: default

default: lingfs

lingfs: lingfs.o libspfs/libspfs.a
	$(CC) -o lingfs $(CFLAGS) lingfs.o $(LFLAGS) $(NPFS_LFLAGS)

libspfs/libspfs.a:
	make -C libspfs

clean:
	rm -f *.o *~ lingfs core.*

%.c: include/spfs.h Makefile

%.o: %.c 
	$(CC) $(CFLAGS) -c $*.c

