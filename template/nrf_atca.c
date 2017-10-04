/**
 * @file
 *
 * @brief Handle the configuration and operation of the
 * ATCA connected to the I2C
 *
 * @date July 6, 2017
 * @author Steve Karg
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "seeprom.h"
#include "watchdog.h"
/* our hardware files */
#include "hardware.h"
#include "nrf.h"
#include "cryptoauthlib.h"

static ATCAIfaceCfg cfg_ateccx08a_i2c_ippan2 = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype = ATECC508A,
    .atcai2c.slave_address = 0xC0,
    .atcai2c.bus = 0,
    .atcai2c.baud = 400000,
    .wake_delay = 1500,
    .rx_retries = 20
};

/**
 * Initialize the ATCA I2C connection
 */
void atca_init(
    void)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t revision[4] = { 0 };

    status = atcab_init(&cfg_ateccx08a_i2c_ippan2);
    while (status != ATCA_SUCCESS) {
        /* failed */
    }
    status = atcab_info(revision);
    while (status != ATCA_SUCCESS) {
        /* failed */
    }
    status = atcab_release();
    while (status != ATCA_SUCCESS) {
        /* failed */
    }
}

#ifdef TEST_ATCA
#include "nrf_delay.h"

/**************************************************************************
* Description: The starting point of the C program
* Returns: none
* Notes: called from crt.s module
**************************************************************************/
int main(
    void)
{
    SystemCoreClockUpdate();
    atca_init();
    /*  run forever */
    for (;;) {
        /* tasks */
        nrf_delay_ms(1000);
    }
}
#endif
