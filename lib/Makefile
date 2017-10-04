TARGET := atca
LIBRARY = lib$(TARGET).a

# tools - only if you need them.
# Most platforms have this already defined
# CC = gcc
# AR = ar
# MAKE = make
# SIZE = size

INCLUDES += -I. -I./atcacert -I./basic -I./crypto -I./tls -I./host
CFLAGS  += $(WARNINGS) $(DEBUGGING) $(OPTIMIZATION) $(STANDARDS) $(INCLUDES) $(DEFINES)

OBJS := $(patsubst %.c,%.o,$(wildcard *.c)) \
	$(patsubst %.c,%.o,$(wildcard atcacert/*.c)) \
	$(patsubst %.c,%.o,$(wildcard basic/*.c)) \
	$(patsubst %.c,%.o,$(wildcard crypto/*.c)) \
	$(patsubst %.c,%.o,$(wildcard crypto/hashes/*.c)) \
	$(patsubst %.c,%.o,$(wildcard host/*.c)) \
	$(patsubst %.c,%.o,$(wildcard tls/*.c))
	
ifeq ($(HAL_NRF52832),1)
	INCLUDES += -I../$(NRF52_SDK_ROOT)/components/device -I../$(NRF52_SDK_ROOT)/components/toolchain/cmsis/include
	INCLUDES += -I../$(NRF52_SDK_ROOT)/components/toolchain -I../$(NRF52_SDK_ROOT)/components/drivers_nrf/delay 
	INCLUDES += -I../$(NRF52_SDK_ROOT)/components/drivers_nrf/twi_master -I../$(NRF52_SDK_ROOT)/components/libraries/util
	INCLUDES += -I../$(NRF52_SDK_ROOT)/components/drivers_nrf/hal -I../$(NRF52_SDK_ROOT)/components/libraries/util
	INCLUDES += -I../$(NRF52_SDK_ROOT)/components/softdevice/s132/headers -I $(SDK_CONFIG_DIR)
	OBJS+= hal/hal_nrf5_timer.o
	OBJS+= hal/hal_nrf5_i2c.o
	OBJS+= hal/atca_hal.o
endif 	

all: $(LIBRARY)

lib: $(LIBRARY)

$(LIBRARY): $(OBJS) Makefile
	$(AR) rcs $@ $(LEGRAND_OBJS) $(OBJS) $(HAL_OBJS) 

.c.o:
	${CC} -c ${CFLAGS} $*.c -o $@

depend:
	rm -f .depend
	${CC} -MM ${CFLAGS} *.c >> .depend

clean:
	rm -rf core $(OBJS) $(LIBRARY)

include: .depend
