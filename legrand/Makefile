TARGET := atca-legrand
LIBRARY = lib$(TARGET).a

# tools - only if you need them.
# Most platforms have this already defined
# CC = gcc
# AR = ar
# MAKE = make
# SIZE = size

INCLUDES := -I../lib/ -I../lib/atcacert -I../lib/basic -I../lib/crypto -I../lib/tls -I../lib/host
CFLAGS  += $(WARNINGS) $(DEBUGGING) $(OPTIMIZATION) $(STANDARDS) $(INCLUDES) $(DEFINES)

OBJS := $(patsubst %.c,%.o,$(wildcard *.c))

all: $(LIBRARY)

lib: $(LIBRARY)

$(LIBRARY): $(OBJS) Makefile
	$(AR) rcs $@ $(OBJS)

.c.o:
	${CC} -c ${CFLAGS} $*.c -o $@

depend:
	rm -f .depend
	${CC} -MM ${CFLAGS} *.c >> .depend

clean:
	rm -rf core $(OBJS) $(LIBRARY)

include: .depend
