/**
 * \file
 * \brief ATCA Hardware abstraction layer for Linux using kit protocol over a USB CDC device.
 *
 * \copyright Copyright (c) 2017 Microchip Technology Inc. and its subsidiaries (Microchip). All rights reserved.
 *
 * \page License
 *
 * You are permitted to use this software and its derivatives with Microchip
 * products. Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Microchip may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with a
 *    Microchip integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY MICROCHIP "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL MICROCHIP BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "atca_hal.h"
#include "kit_phy.h"
#include "hal_linux_kit_cdc.h"
#include "kit_protocol.h"

#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

// File scope macros
#ifndef __cplusplus
#define max(a, b)    (((a) > (b)) ? (a) : (b))
#define min(a, b)    (((a) < (b)) ? (a) : (b))
#endif


// Function declarations
// DAG
ATCA_STATUS hal_cdc_discover_buses(int cdc_buses[], int max_buses);
ATCA_STATUS hal_cdc_discover_devices(int busNum, ATCAIfaceCfg cfg[], int *found);
ATCA_STATUS hal_kit_phy_num_found(int8_t* num_found);

// File scope globals
atcacdc_t _gCdc;


/** \brief HAL implementation of Kit USB CDC init
 *
 * this discovery assumes a udev rule is active which renames the ATCK101 CDC device as a ttyATCA%n
 * the udev rule is:
 *
 *  SUBSYSTEMS=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2122", MODE:="0777", SYMLINK+="ttyATCA%n"
 *
 *  \param[in] hal pointer to HAL specific data that is maintained by this HAL
 *  \param[in] cfg pointer to HAL specific configuration data that is used to initialize this HAL
 * \return ATCA_STATUS
 */

char *dev = "/dev/ttyACM0";  // default device, Atmel CryptoAuth %n
//char *dev = "/dev/ttyATCA0";  // default device, Atmel CryptoAuth %n
int speed = B115200;

/** \brief discover cdc buses available for this hardware
 * this maintains a list of logical to physical bus mappings freeing the application
 * of the a-priori knowledge
 * \param[in] cdc_buses - an array of logical bus numbers
 * \param[in] max_buses - maximum number of buses the app wants to attempt to discover
 */

ATCA_STATUS hal_cdc_discover_buses(int cdc_buses[], int max_buses)
{
    return ATCA_UNIMPLEMENTED;
}

/** \brief discover any CryptoAuth devices on a given logical bus number
 * \param[in] busNum - logical bus number on which to look for CryptoAuth devices
 * \param[out] cfg[] - pointer to head of an array of interface config structures which get filled in by this method
 * \param[out] *found - number of devices found on this bus
 */

ATCA_STATUS hal_cdc_discover_devices(int busNum, ATCAIfaceCfg cfg[], int *found)
{
    return ATCA_UNIMPLEMENTED;
}

ATCA_STATUS hal_kit_cdc_init(void* hal, ATCAIfaceCfg* cfg)
{
    ATCAHAL_t *phal = NULL;
    struct termios serialTermios;
    uint32_t i = 0;
    uint32_t index = 0;
    int fd;

    // Check the input variables
    if ((hal == NULL) || (cfg == NULL))
        return ATCA_BAD_PARAM;

    // Cast the hal to the ATCAHAL_t structure
    phal = (ATCAHAL_t*)hal;

    // Initialize the _gCdc structure
    memset(&_gCdc, 0, sizeof(_gCdc));
    for (i = 0; i < CDC_DEVICES_MAX; i++)
    {
        _gCdc.kits[i].read_handle = INVALID_HANDLE_VALUE;
        _gCdc.kits[i].write_handle = INVALID_HANDLE_VALUE;
    }
    _gCdc.num_kits_found = 0;

    // Get the read & write handles
    // todo: perform an actual discovery here...
    if ( (fd = open(dev, O_RDWR | O_NOCTTY)) < 0)
    {
        printf("Failed to open %s ret:%02X\n", dev, fd);
        return ATCA_COMM_FAIL;
    }
    index++;
    // Save the results of this discovery of CDC
    if (index > 0)
    {
        _gCdc.num_kits_found = 1;
        phal->hal_data = &_gCdc;
    }

    tcgetattr(fd, &serialTermios);
    cfsetispeed(&serialTermios, speed);
    cfsetospeed(&serialTermios, speed);
    cfmakeraw(&serialTermios);

    serialTermios.c_cflag |= CS8 | CLOCAL | CREAD;
    serialTermios.c_iflag = 0;
    serialTermios.c_oflag = 0;
    serialTermios.c_lflag = 0;
    // serialTermios.c_cc[VMIN] = 1;
    // serialTermios.c_cc[VTIME] = 0;

    tcsetattr(fd, TCSANOW, &serialTermios);

    _gCdc.kits[0].read_handle = fd;
    _gCdc.kits[0].write_handle = fd;

    return ATCA_SUCCESS;
}

/** \brief HAL implementation of Kit USB CDC post init
 *  \param[in] iface  instance
 *  \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_cdc_post_init(ATCAIface iface)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    atcacdc_t* phaldat = atgetifacehaldat(iface);
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    //int cdcid = cfg->atcauart.port;
    int i = 0;

    // Init all kit USB devices
    for (i = 0; i < phaldat->num_kits_found; i++)
    {
        // Set the port
        cfg->atcauart.port = i;
        // Perform the kit protocol init
        status = kit_init(iface);
        if (status != ATCA_SUCCESS)
            return status;
    }

    return status;
}

/** \brief HAL implementation of send over USB CDC
 *  \param[in] iface     instance
 *  \param[in] txdata    pointer to bytes to send
 *  \param[in] txlength  number of bytes to send
 *  \return ATCA_STATUS
 */
ATCA_STATUS kit_phy_send(ATCAIface iface, const char* txdata, int txlength)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int cdcid = cfg->atcauart.port;
    atcacdc_t* pCdc = (atcacdc_t*)atgetifacehaldat(iface);
    // size_t bytesWritten = 0;  unused

#ifdef KIT_DEBUG
    printf("--> %s", txdata);
#endif
    // Verify the input parameters
    if ((txdata == NULL) || (pCdc == NULL))
        return ATCA_BAD_PARAM;

    // Verify the write handle
    if (pCdc->kits[cdcid].write_handle == INVALID_HANDLE_VALUE)
        return ATCA_COMM_FAIL;

    // Write the bytes to the specified com port
    write(pCdc->kits[cdcid].write_handle, txdata, txlength);

    return status;
}

/** \brief HAL implementation of kit protocol send over USB CDC
 * \param[in]    iface   instance
 * \param[out]   rxdata  pointer to space to receive the data
 * \param[inout] rxsize  ptr to expected number of receive bytes to request
 * \return ATCA_STATUS
 */
ATCA_STATUS kit_phy_receive(ATCAIface iface, char* rxdata, int* rxsize)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int cdcid = cfg->atcauart.port;
    atcacdc_t* pCdc = (atcacdc_t*)atgetifacehaldat(iface);
    uint8_t buffer[CDC_BUFFER_MAX] = { 0 };
    bool continue_read = true;
    int bytes_read = 0;
    uint16_t total_bytes = 0;
    char* location = NULL;
    int bytes_remain = 0;
    int bytes_to_cpy = 0;

    do
    {
        // Verify the input variables
        if ((rxdata == NULL) || (rxsize == NULL) || (pCdc == NULL))
        {
            status = ATCA_BAD_PARAM;
            break;
        }
        // Verify the write handle
        if (pCdc->kits[cdcid].read_handle == INVALID_HANDLE_VALUE)
        {
            status = ATCA_COMM_FAIL;
            break;
        }
        // Read all of the bytes
        while (continue_read == true)
        {
            bytes_read = read(pCdc->kits[cdcid].read_handle, buffer, CDC_BUFFER_MAX);

            // Find the location of the '\n' character in read buffer
            // todo: generalize this read...  it only applies if there is an ascii protocol with an <eom> of \n and if the <eom> exists
            location = strchr((char*)&buffer[0], '\n');
            if (location == NULL)
            {
                // Copy all of the bytes
                bytes_to_cpy = bytes_read;
            }
            else
            {
                // Copy only the bytes remaining in the read buffer to the <eom>
                bytes_to_cpy = (uint8_t)(location - (char*)buffer) + 1;
                // The response has been received, stop receiving more data
                continue_read = false;
            }
            // Protect rxdata from overwriting, this will have the result of truncating the returned bytes
            // Remaining space in rxdata
            bytes_remain = (*rxsize - total_bytes);
            // Use the minimum between number of bytes read and remaining space
            bytes_to_cpy = min(bytes_remain, bytes_to_cpy);

            // Copy the received data
            memcpy(&rxdata[total_bytes], &buffer[0], bytes_to_cpy);
            total_bytes += bytes_to_cpy;
        }

    }
    while (0);

    *rxsize = total_bytes;
#ifdef KIT_DEBUG
    printf("<-- %s", rxdata);
#endif
    return status;
}

/** \brief Number of USB CDC devices found
 *  \param[out] num_found
 *  \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_phy_num_found(int8_t* num_found)
{
    *num_found = _gCdc.num_kits_found;
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of kit protocol send over USB CDC
 *  \param[in] iface     instance
 *  \param[in] txdata    pointer to bytes to send
 *  \param[in] txlength  number of bytes to send
 *  \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_cdc_send(ATCAIface iface, uint8_t* txdata, int txlength)
{
    // Call the hal_kit_send() function that will call hal_phy_send() implemented below
    return kit_send(iface, txdata, txlength);
}

/** \brief HAL implementation of send over USB CDC
 * \param[in]    iface   instance
 * \param[in]    rxdata  pointer to space to receive the data
 * \param[inout] rxsize  ptr to expected number of receive bytes to request
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_cdc_receive(ATCAIface iface, uint8_t* rxdata, uint16_t* rxsize)
{
    // Call the hal_kit_receive() function that will call hal_phy_receive() implemented below
    return kit_receive(iface, rxdata, rxsize);
}

/** \brief Call the wake for kit protocol
 * \param[in] iface ATCAIface instance that is the interface object to send the bytes over
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_cdc_wake(ATCAIface iface)
{
    // Call the hal_kit_wake() function that will call hal_phy_send() and hal_phy_receive()
    return kit_wake(iface);
}

/** \brief Call the idle for kit protocol
 * \param[in] iface ATCAIface instance that is the interface object to send the bytes over
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_cdc_idle(ATCAIface iface)
{
    // Call the hal_kit_idle() function that will call hal_phy_send() and hal_phy_receive()
    return kit_idle(iface);
}

/** \brief Call the sleep for kit protocol
 * \param[in] iface ATCAIface instance that is the interface object to send the bytes over
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_cdc_sleep(ATCAIface iface)
{
    // Call the hal_kit_sleep() function that will call hal_phy_send() and hal_phy_receive()
    return kit_sleep(iface);
}

/** \brief Close the physical port for CDC
 * \param[in] hal_data The hardware abstraction data specific to this HAL
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_cdc_release(void* hal_data)
{
    int i = 0;
    atcacdc_t* phaldat = (atcacdc_t*)hal_data;

    if ((hal_data == NULL))
        return ATCA_BAD_PARAM;

    // Close all kit USB devices
    for (i = 0; i < phaldat->num_kits_found; i++)
    {
        if (phaldat->kits[i].read_handle != INVALID_HANDLE_VALUE)
        {
            close(phaldat->kits[i].read_handle);
            phaldat->kits[i].read_handle = INVALID_HANDLE_VALUE;
        }

        if (phaldat->kits[i].write_handle != INVALID_HANDLE_VALUE)
        {
            close(phaldat->kits[i].write_handle);
            phaldat->kits[i].write_handle = INVALID_HANDLE_VALUE;
        }
    }
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_kit_cdc_discover_buses(int i2c_buses[], int max_buses)
{
    // TODO: Implement
    return ATCA_UNIMPLEMENTED;
}

ATCA_STATUS hal_kit_cdc_discover_devices(int busNum, ATCAIfaceCfg *cfg, int *found)
{
    // TODO: Implement
    *found = 0;
    return ATCA_UNIMPLEMENTED;
}
/** @} */
