TARGET = atcatest
LIBRARY = lib$(TARGET).a

# tools - only if you need them.
# Most platforms have this already defined
# CC = gcc
# AR = ar
# MAKE = make
# SIZE = size

INCLUDES := -I.. -I../lib
CFLAGS  = $(WARNINGS) $(DEBUGGING) $(OPTIMIZATION) $(STANDARDS) $(INCLUDES) $(DEFINES)

SRC := $(wildcard atcacert/*.c) \
	$(wildcard test/tls/*.c) \
	unity.c \
	unity_fixture.c \
	atca_basic_tests.c \
	atca_crypto_sw_tests.c \
	atca_unit_tests.c \
	atca_test.c \
	cmd-processor.c

OBJS := ${SRC:.c=.o}

all: $(LIBRARY) Makefile

lib: $(LIBRARY)

$(LIBRARY): $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)

.c.o:
	${CC} -c ${CFLAGS} $*.c -o $@

depend:
	rm -f .depend
	${CC} -MM ${CFLAGS} *.c >> .depend

clean:
	rm -rf $(OBJS) $(LIBRARY)

include: .depend
