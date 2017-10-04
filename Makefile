TARGET := atca-cmd

# tools - only if you need them.
# Most platforms have this already defined
# CC = gcc
# AR = ar
# MAKE = make
# SIZE = size

# Export the variables defined here to all subprocesses
# (see http://www.gnu.org/software/automake/manual/make/Special-Targets.html)
.EXPORT_ALL_VARIABLES:

INCLUDES := -I./lib



OPTIMIZATION := -Os
DEBUGGING :=
WARNINGS := -Wall -Wmissing-prototypes
ifeq (${BUILD},debug)
OPTIMIZATION = -O0
DEBUGGING = -g -DDEBUG_ENABLED=1
endif


# libraries
ATCA_LIB := -Llib,-latca
TEST_LIB := -Ltest,-latcatest
LEGRAND_LIB := -Llegrand,-latca-legrand
SYSTEM_LIB   := -lc,-lgcc,-lrt,-lm
LFLAGS := -Wl,$(TEST_LIB),$(ATCA_LIB),$(LEGRAND_LIB),$(SYSTEM_LIB)

$(info CURRENT DIR $(CURDIR) $(PWD))
ifeq ($(HAL_NRF52832),1)	
	DEFINES := -DATCAPRINTF -DATCA_HAL_I2C

else
 DEFINES := -DATCAPRINTF -DATCA_HAL_I2C -DATCA_HAL_KIT_CDC -DATCA_RASPBERRY_PI_3
 HAL_SRC := \
  ./lib/hal/atca_hal.c \
  ./lib/hal/hal_linux_timer_userspace.c \
  ./lib/hal/hal_linux_i2c_userspace.c   \
  ./lib/hal/hal_linux_kit_cdc.c	\
  ./lib/hal/kit_protocol.c
 
endif
CFLAGS += $(WARNINGS) $(DEBUGGING) $(OPTIMIZATION) $(STANDARDS) $(INCLUDES) $(DEFINES)

HAL_OBJS := ${HAL_SRC:.c=.o}

OBJS := $(HAL_OBJS)

all: library legrand test $(TARGET)
.PHONY : all library legrand test clean

test:
	$(MAKE) -s -C test all

library: $(OBJS)
	$(MAKE) -s -C lib all

legrand:
	$(MAKE) -s -C legrand all

$(TARGET): $(OBJS) Makefile	
	${CC} ${OBJS} ${LFLAGS} -o $@

.c.o:
	${CC} -c ${CFLAGS} $*.c -o $@

depend:
	rm -f .depend
	${CC} -MM ${CFLAGS} *.c >> .depend

clean:
	$(MAKE) -s -C lib clean
	$(MAKE) -s -C test clean
	$(MAKE) -s -C legrand clean
	rm -rf $(OBJS)
	rm -rf $(TARGET)

include: .depend
