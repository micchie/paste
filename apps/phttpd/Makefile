#CFLAGS += -Werror -Wall -O2 -g -fsanitize=address
CFLAGS += -Werror -Wall -O2 -g
NMLIB = ../../libnetmap/libnetmap.a
LDFLAGS += $(NMLIB) -lpthread -lm
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
LDFLAGS += -lbsd
endif
#CFLAGS += -I/usr/local/include -I../libsqlite/include
OBJS = phttpd-b.o phttpd-k.o phttpd-f.o bplus_support.o bplus_impl.o
SPATH ?= -I../../sys/ -I../include -I../../libnetmap -DNETMAP_WITH_LIBS
BOPT = -DWITH_BPLUS -I./
FOPT = -DWITH_NOFLUSH
OOPT = -DWITH_CLFLUSHOPT -mclflushopt

#
# compile phttpd-o only if your CPU supports clflushopt
#
#PROG = phttpd phttpd-b phttpd-o phttpd-f
PROG = phttpd phttpd-b phttpd-f

all: $(PROG)

#test_nvdimm: test_nvdimm.o
#	$(CC) $(CFLAGS) -o test_nvdimm test_nvdimm.o $(LDFLAGS) $(EXTRA_LDFLAGS)
#test_nvdimm.o: test_nvdimm.c nmlib.h
#	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(SPATH) -c test_nvdimm.c -o test_nvdimm.o $(EXTRA_CFLAGS)
phttpd: phttpd.c nmlib.h
	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(SPATH) phttpd.c -o phttpd $(EXTRA_CFLAGS) $(LDFLAGS)

#phttpd-o: phttpd-o.o
#	$(CC) $(CFLAGS) -o phttpd-o phttpd-o.o $(LDFLAGS) $(EXTRA_CFLAGS)
#phttpd-o.o: phttpd.c nmlib.h
#	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(OOPT) $(SPATH) -c phttpd.c -o phttpd-o.o $(EXTRA_CFLAGS)

phttpd-f: phttpd-f.o
	$(CC) $(CFLAGS) -o phttpd-f phttpd-f.o $(LDFLAGS) $(EXTRA_CFLAGS)
phttpd-f.o: phttpd.c nmlib.h
	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(FOPT) $(SPATH) -c phttpd.c -o phttpd-f.o $(EXTRA_CFLAGS)

phttpd-b: phttpd-b.o bplus_support.o bplus_impl.o
	$(CC) $(CFLAGS) -o phttpd-b phttpd-b.o bplus_impl.o bplus_support.o $(LDFLAGS) $(EXTRA_CFLAGS)
phttpd-b.o: phttpd.c nmlib.h bplus_common.h bplus_support.h
	$(CC) $(CFLAGS) $(OPT) $(SOPT) $(BOPT) $(SPATH) -c phttpd.c -o phttpd-b.o $(EXTRA_CFLAGS)
bplus_impl.o: bplus_impl.c
	$(CC) $(CFLAGS) $(BOPT) -c bplus_impl.c
bplus_support.o: bplus_support.c
	$(CC) $(CFLAGS) $(BOPT) -c bplus_support.c
clean:
	-@rm -f $(PROG) $(OBJS)
