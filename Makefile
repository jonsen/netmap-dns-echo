# For multiple programs using a single source file each,
# we can just define 'progs' and create custom targets.
PROGS	=	echo2 echo3 echo3a echo4 echo5 

CLEANFILES = $(PROGS) *.o
NO_MAN=
CFLAGS = -g -O2 -pipe
#CFLAGS += -Werror -Wall
CFLAGS += -I ../netmap-release/sys 
CFLAGS += -Wextra
CFLAGS += -DNO_PCAP

LDFLAGS += -lpthread
LDFLAGS += -lrt	# needed on linux, does not harm on BSD

all: $(PROGS)

nm_util.o echo2.o: nm_util.h

echo2: echo2.o nm_util.o
	$(CC) $(CFLAGS) -o $@ $^ 

echo3: echo3.o nm_util.o
	 $(CC) $(CFLAGS) -o $@ $^

echo3a: echo3a.o nm_util.o
	 $(CC) $(CFLAGS) -o $@ $^

echo4: echo4.o nm_util.o
	$(CC) $(CFLAGS) -o $@ $^

echo5: echo5.o nm_util.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	-@rm -rf $(CLEANFILES)
