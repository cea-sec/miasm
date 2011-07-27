CFLAGS=-Wall  -I/usr/include/python2.6 -lpython2.6
CC = gcc
all: libcodenat.so libcodenat_tcc.so libcodenat_interface.so

libcodenat_interface.so: libcodenat_interface.c
	$(CC) $(CFLAGS) -shared -o $@ $<  -lm -lcodenat -L`pwd` -Wl,-rpath,`pwd`

libcodenat.so: libcodenat.c
	$(CC) $(CFLAGS) -shared -o $@ $<  -lm 

libcodenat_tcc.so: libcodenat_tcc.c 
	$(CC) $(CFLAGS) -shared -o $@ $<  -ldl  /usr/lib/i386-linux-gnu/libtcc.a



test: main.o libcodenat.a
	$(CC) $< $(CFLAGS)  -L. -L/usr/lib -lcodenat -lpython2.6

clean:
	rm -f libcodenat.so libcodenat_interface.so libcodenat_interface.o libcodenat.o a.out libcodenat_tcc.o libcodenat_tcc.so
