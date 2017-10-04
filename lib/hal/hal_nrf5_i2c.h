/**
 * \file
 * \brief ATCA Hardware abstraction layer for Nordic nRF5 I2C over Nordic SDK
 * drivers.
 *
 * Prerequisite: add TWI Master SDK files support to application.
 *
 */

#ifndef HAL_NRF5_I2C_H_
#define HAL_NRF5_I2C_H_

#include <stdlib.h>
#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_drv_twi.h"

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating
 * with a CryptoAuth device
 *
   @{ */


#define MAX_I2C_BUSES    2

/** \brief this is the hal_data for ATCA HAL for nRF5 SDK
 */
typedef struct atcaI2Cmaster {
    nrf_drv_twi_t const *i2c_master_instance;
    // for info only - which pins were used
	uint32_t pin_sda;
	uint32_t pin_scl;
    int ref_ct;
    // for conveniences during interface release phase
    int bus_index;
} ATCAI2CMaster_t;

void change_i2c_speed(
    ATCAIface iface,
    uint32_t speed);

/** @} */

#endif /* HAL_NRF5_I2C_H_ */
