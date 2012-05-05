SYSNAME:=${shell uname}
SYSNAME!=uname
HFILES=../include/spfs.h spfsimpl.h
CFLAGS=-Wall -g -I ../include

LIBFILES=\
	conn.o\
	error.o\
	fcall.o\
	fdconn.o\
	fidpool.o\
	file.o\
	fmt.o\
	np.o\
	poll.o\
	socksrv.o\
	srv.o\
	user.o\
	ethsrv.o\
	ethconn.o

libspfs.a: $(LIBFILES)
	ar rc libspfs.a $(LIBFILES)
	ranlib libspfs.a

install:
	cp ../include/spfs.h /usr/local/include
	cp libspfs.a /usr/local/lib

clean:
	rm -f *.o *.a *~ core.*

$(LIBFILES): Makefile $(HFILES)

%.o: %.c 
	$(CC) $(CFLAGS) -c $*.c
