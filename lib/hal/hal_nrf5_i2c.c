/**
 * \file
 * \brief ATCA Hardware abstraction layer for Nordic nRF5 I2C over Nordic SDK
 * drivers.
 *
 * This code is structured in two parts.
 * Part 1 is the connection of the ATCA HAL API to the physical I2C
 * implementation.
 * Part 2 is the Nordic TWI SDK primitives to set up the interface.
 *
 * Prerequisite: add TWI Master SDK files support to application.
 *
 */
#include <string.h>
#include "atca_hal.h"
#include "atca_device.h"
#include "hal_nrf5_i2c.h"
#include "atca_start_config.h"
#include "atca_start_iface.h"

/* IPPAN2 i2c interface aka TWI */
#define NRF5_DEFAULT_SCL_PIN   19
#define NRF5_DEFAULT_SDA_PIN   11

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating
 * with a CryptoAuth device
 *
   @{ */
#if TWI0_ENABLED
static const nrf_drv_twi_t TWI_Master_Instance_0 = NRF_DRV_TWI_INSTANCE(0);
#endif
#if TWI1_ENABLED
static const nrf_drv_twi_t TWI_Master_Instance_1 = NRF_DRV_TWI_INSTANCE(1);
#endif
/* map logical, 0-based bus number to index */
static ATCAI2CMaster_t i2c_hal_data[MAX_I2C_BUSES];
/* total in-use count across buses */
static int i2c_bus_ref_ct = 0;

/* Notes:
    - this HAL implementation assumes you've included the Nordic nRF5 SDK.
    Otherwise, the HAL layer will not compile because the Nordic TWI drivers
	are a dependency
 */

/** \brief discover i2c buses available for this hardware
 * this maintains a list of logical to physical bus mappings freeing the
 * application of the a-priori knowledge
 * \param[in] i2c_buses - an array of logical bus numbers
 * \param[in] max_buses - maximum number of buses the app wants to attempt
 * to discover
 */
ATCA_STATUS hal_i2c_discover_buses(
    int i2c_buses[],
    int max_buses)
{
    i2c_buses[0] = 0;

    return ATCA_SUCCESS;
}

/** \brief discover any CryptoAuth devices on a given logical bus number
 * \param[in]  busNum  logical bus number on which to look for CryptoAuth
 * devices
 * \param[out] cfg     pointer to head of an array of interface config
 * structures which get filled in by this method. Note: discovery will
 * nicely overwrite memory since the size of the cfg array is not passed
 * into this function. BUG BUG BUG
 * \param[out] found   number of devices found on this bus
 */
ATCA_STATUS hal_i2c_discover_devices(
    int busNum,
    ATCAIfaceCfg cfg[],
    int *found)
{
    ATCAIfaceCfg *head = cfg;
    uint8_t slaveAddress = 0x01;
    ATCADevice device;
    ATCAIface discoverIface;
    ATCACommand command;
    ATCAPacket packet;
    uint32_t execution_time;
    ATCA_STATUS status;
    uint8_t revs508[1][4] = { {0x00, 0x00, 0x50, 0x00} };
    uint8_t revs108[1][4] = { {0x80, 0x00, 0x10, 0x01} };
    uint8_t revs204[3][4] = { {0x00, 0x02, 0x00, 0x08},
    {0x00, 0x02, 0x00, 0x09},
    {0x00, 0x04, 0x05, 0x00}
    };
    int i;

    /** \brief default configuration, to be reused during discovery process */
    ATCAIfaceCfg discoverCfg = {
        .iface_type = ATCA_I2C_IFACE,
        .devtype = ATECC508A,
        .atcai2c.slave_address = 0x07,
        .atcai2c.bus = busNum,
        .atcai2c.baud = 400000,
        .wake_delay = 1500,
        .rx_retries = 20
    };

    ATCAHAL_t hal;

    hal_i2c_init(&hal, &discoverCfg);
    device = newATCADevice(&discoverCfg);
    discoverIface = atGetIFace(device);
    command = atGetCommands(device);

    /* iterate through all addresses on given i2c bus
       all valid 7-bit addresses go from 0x07 to 0x78 */
    for (slaveAddress = 0x07; slaveAddress <= 0x78; slaveAddress++) {
        /* turn it into an 8-bit address which is what the rest
           of the i2c HAL is expecting when a packet is sent */
        discoverCfg.atcai2c.slave_address = slaveAddress << 1;

        // wake up device
        // If it wakes, send it a dev rev command.  Based on that response, determine the device type
        // BTW - this will wake every cryptoauth device living on the same bus (ecc508a, sha204a)

        if (hal_i2c_wake(discoverIface) == ATCA_SUCCESS) {
            (*found)++;
            memcpy((uint8_t *) head, (uint8_t *) & discoverCfg,
                sizeof(ATCAIfaceCfg));

            memset(packet.data, 0x00, sizeof(packet.data));

            // get devrev info and set device type accordingly
            atInfo(command, &packet);
            execution_time = atGetExecTime(command, CMD_INFO) + 1;

            // send the command
            if ((status =
                    atsend(discoverIface, (uint8_t *) & packet,
                        packet.txsize)) != ATCA_SUCCESS) {
                /* packet send error */
                continue;
            }
            // delay the appropriate amount of time for command to execute
            atca_delay_ms(execution_time);

            // receive the response
            if ((status =
                    atreceive(discoverIface, &(packet.data[0]),
                        &(packet.rxsize))) != ATCA_SUCCESS)
                continue;

            if ((status = isATCAError(packet.data)) != ATCA_SUCCESS) {
                /* command response error */
                continue;
            }
            // determine device type from common info and dev rev response byte strings
            for (i = 0; i < (int) sizeof(revs508) / 4; i++) {
                if (memcmp(&packet.data[1], &revs508[i], 4) == 0) {
                    discoverCfg.devtype = ATECC508A;
                    break;
                }
            }

            for (i = 0; i < (int) sizeof(revs204) / 4; i++) {
                if (memcmp(&packet.data[1], &revs204[i], 4) == 0) {
                    discoverCfg.devtype = ATSHA204A;
                    break;
                }
            }

            for (i = 0; i < (int) sizeof(revs108) / 4; i++) {
                if (memcmp(&packet.data[1], &revs108[i], 4) == 0) {
                    discoverCfg.devtype = ATECC108A;
                    break;
                }
            }

            atca_delay_ms(15);
            // now the device type is known, so update the caller's cfg array element with it
            head->devtype = discoverCfg.devtype;
            head++;
        }

        hal_i2c_idle(discoverIface);
    }

    hal_i2c_release(&hal);

    return ATCA_SUCCESS;
}

/* \brief hal_i2c_init manages requests to initialize a physical interface.
 * It manages use counts so when an interface has released the physical layer,
 * it will disable the interface for some other use.
 * You can have multiple ATCAIFace instances using the same bus, and you can
 * have multiple ATCAIFace instances on multiple i2c buses,
 * so hal_i2c_init manages these things and ATCAIFace is abstracted
 * from the physical details.
 */

ATCA_STATUS hal_i2c_init(
    void *hal,
    ATCAIfaceCfg * cfg)
{
    int bus = cfg->atcai2c.bus; // 0-based logical bus number
    ATCAHAL_t *phal = (ATCAHAL_t *) hal;
    uint32_t freq_constant;     // I2C frequency configuration constant in kHz
    nrf_drv_twi_t const * p_instance;
    ret_code_t err_code = NRF_ERROR_BUSY;
    nrf_drv_twi_config_t config =
    {
       .scl                = NRF5_DEFAULT_SCL_PIN,
       .sda                = NRF5_DEFAULT_SDA_PIN,
       .frequency          = NRF_TWI_FREQ_400K,
       .interrupt_priority = TWI_DEFAULT_CONFIG_IRQ_PRIORITY,
        /* Send clocks (max 9) until slave device back from stuck mode */
       .clear_bus_init     = true,
       .hold_bus_uninit    = false
    };

    // total across buses
    i2c_bus_ref_ct++;
    if (bus >= 0 && bus < MAX_I2C_BUSES) {
        // if this is the first time this bus and interface has been created,
        // do the physical work of enabling it
        if (i2c_hal_data[bus].ref_ct == 0) {
            switch (bus) {
                case 0:
#if TWI0_ENABLED
                    i2c_hal_data[bus].i2c_master_instance =
                        &TWI_Master_Instance_0;
                    i2c_hal_data[bus].ref_ct = 1;
#endif
                    break;
                case 1:
#if TWI1_ENABLED
                    i2c_hal_data[bus].i2c_master_instance =
                        &TWI_Master_Instance_1;
                    i2c_hal_data[bus].ref_ct = 1;
#endif
                    break;
                case 2:
                    break;
                case 3:
                    break;
                case 4:
                    break;
                case 5:
                    break;
            }
            // store I2C baudrate in kHz
            freq_constant = cfg->atcai2c.baud / 1000;
            p_instance = i2c_hal_data[bus].i2c_master_instance;
            // store this for use during the release phase
            i2c_hal_data[bus].bus_index = bus;
            i2c_hal_data[bus].pin_scl = config.scl;
            i2c_hal_data[bus].pin_sda = config.sda;
            if (cfg->atcai2c.baud >= 400000) {
                config.frequency = NRF_TWI_FREQ_400K;
            } else if (cfg->atcai2c.baud >= 250000) {
                config.frequency = NRF_TWI_FREQ_250K;
            } else {
                config.frequency = NRF_TWI_FREQ_100K;
            }
            nrf_drv_twi_uninit(p_instance);
            // set I2C baudrate and enable I2C module
            err_code = nrf_drv_twi_init(p_instance, &config, NULL, NULL);
            while (err_code != NRF_SUCCESS ) {
                /* developer: fix the config! */
            }
            nrf_drv_twi_enable(p_instance);
        } else {
            // otherwise, another interface already initialized the bus,
            // so this interface will share it and any different
            // cfg parameters will be ignored...first one to initialize
            // this sets the configuration
            i2c_hal_data[bus].ref_ct++;
        }
        phal->hal_data = &i2c_hal_data[bus];

        return ATCA_SUCCESS;
    }

    return ATCA_COMM_FAIL;
}

/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_i2c_post_init(
    ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C send over START
 * \param[in] iface     instance
 * \param[in] txdata    pointer to space to bytes to send
 * \param[in] txlength  number of bytes to send
 * \return ATCA_STATUS
 */

ATCA_STATUS hal_i2c_send(
    ATCAIface iface,
    uint8_t * txdata,
    int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    nrf_drv_twi_t const * p_instance;
    ret_code_t err_code = NRF_ERROR_BUSY;

    // for this implementation of I2C with CryptoAuth chips,
    // txdata is assumed to have ATCAPacket format
    // other device types that don't require i/o tokens on the
    // front end of a command need a different hal_i2c_send and
    // wire it up instead of this one
    // this covers devices such as ATSHA204A and ATECCx08A
    // that require a word address value pre-pended to the packet
    // txdata[0] is using _reserved byte of the ATCAPacket
    txdata[0] = 0x03;   // insert the Word Address Value, Command token
    txlength++; // account for word address value byte.
    p_instance = i2c_hal_data[bus].i2c_master_instance;
    err_code = nrf_drv_twi_tx(p_instance, cfg->atcai2c.slave_address >> 1,
        txdata, txlength, false);
    if (err_code != NRF_SUCCESS) {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C receive function for START I2C
 * \param[in] iface     instance
 * \param[in] rxdata    pointer to space to receive the data
 * \param[in] rxlength  ptr to expected number of receive bytes to request
 * \return ATCA_STATUS
 */

ATCA_STATUS hal_i2c_receive(
    ATCAIface iface,
    uint8_t * rxdata,
    uint16_t * rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    int retries = cfg->rx_retries;
    nrf_drv_twi_t const * p_instance;
    ret_code_t err_code = NRF_ERROR_BUSY;

    p_instance = i2c_hal_data[bus].i2c_master_instance;
    while ((retries-- > 0) && (err_code != NRF_SUCCESS)) {
        err_code = nrf_drv_twi_rx(p_instance, cfg->atcai2c.slave_address >> 1,
            rxdata, *rxlength);
    }
    if (err_code != NRF_SUCCESS) {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief method to change the bus speec of I2C
 * \param[in] iface  interface on which to change bus speed
 * \param[in] speed  baud rate (typically 100000 or 400000)
 */

void change_i2c_speed(
    ATCAIface iface,
    uint32_t baud)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    nrf_twim_frequency_t freq_constant = NRF_TWI_FREQ_100K;
    nrf_drv_twi_t const * p_instance;
    NRF_TWIM_Type * p_twim;

    p_instance = i2c_hal_data[bus].i2c_master_instance;
    // disable I2C module
    nrf_drv_twi_disable(p_instance);
    // calculate the I2C frequency configuration constant
    if (baud >= 400000) {
        freq_constant = NRF_TWI_FREQ_400K;
    } else if (baud >= 250000) {
        freq_constant = NRF_TWI_FREQ_250K;
    } else {
        freq_constant = NRF_TWI_FREQ_100K;
    }
    // set I2C baudrate
    p_twim = p_instance->reg.p_twim;
    nrf_twim_frequency_set(p_twim, freq_constant);
    // enable I2C module
    nrf_drv_twi_enable(p_instance);
}

/** \brief wake up CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to wakeup
 */

ATCA_STATUS hal_i2c_wake(
    ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    int retries = cfg->rx_retries;
    uint32_t bdrt = cfg->atcai2c.baud;
    ret_code_t err_code = NRF_ERROR_BUSY;
    nrf_drv_twi_t const * p_instance;
    uint8_t data[4] = { 0 }, expected[4] = { 0x04, 0x11, 0x33, 0x43 };

    if (bdrt != 100000) {
        // if not already at 100KHz, change it
        change_i2c_speed(iface, 100000);
    }
    p_instance = i2c_hal_data[bus].i2c_master_instance;
    // Send the 00 address as the wake pulse
    err_code = nrf_drv_twi_tx(p_instance,0, data, 0, false);
    // wait tWHI + tWLO which is configured based on
    // device type and configuration structure
    atca_delay_us(cfg->wake_delay);
    // receive the wake up response
    while ((retries-- > 0) && (err_code != NRF_SUCCESS)) {
        err_code = nrf_drv_twi_rx(p_instance,
            cfg->atcai2c.slave_address >> 1,
            data, 4);
    }
    // if necessary, revert baud rate to what came in.
    if (bdrt != 100000) {
        change_i2c_speed(iface, bdrt);
    }
    if (err_code == NRF_SUCCESS) {
        // compare received data with expected value
        if (memcmp(data, expected, 4) == 0) {
            return ATCA_SUCCESS;
        }
    }

    return ATCA_COMM_FAIL;
}

/** \brief idle CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to idle
 */

ATCA_STATUS hal_i2c_idle(
    ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    uint8_t data[4];
    ret_code_t err_code = NRF_ERROR_BUSY;
    nrf_drv_twi_t const * p_instance;

    p_instance = i2c_hal_data[bus].i2c_master_instance;
    // idle word address value
    data[0] = 0x02;
    err_code = nrf_drv_twi_tx(p_instance,cfg->atcai2c.slave_address >> 1,
        &data[0], 1, false);
    if (err_code != NRF_SUCCESS) {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief sleep CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to sleep
 */

ATCA_STATUS hal_i2c_sleep(
    ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;
    uint8_t data[4];
    ret_code_t err_code = NRF_ERROR_BUSY;
    nrf_drv_twi_t const * p_instance;

    p_instance = i2c_hal_data[bus].i2c_master_instance;
    data[0] = 0x01;     // sleep word address value
    err_code = nrf_drv_twi_tx(p_instance,cfg->atcai2c.slave_address >> 1,
        &data[0], 1, false);
    if (err_code != NRF_SUCCESS) {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 */

ATCA_STATUS hal_i2c_release(
    void *hal_data)
{
    ATCAI2CMaster_t *hal = (ATCAI2CMaster_t *) hal_data;

    // track total i2c bus interface instances for
    // consistency checking and debugging
    i2c_bus_ref_ct--;
    if (hal && hal->ref_ct) {
        hal->ref_ct--;
        if (hal->ref_ct == 0) {
            // if the use count for this bus has gone to 0 references,
            // disable it.  protect against an unbracketed release
            nrf_drv_twi_disable(hal->i2c_master_instance);
        }
    }

    return ATCA_SUCCESS;
}

/** @} */
