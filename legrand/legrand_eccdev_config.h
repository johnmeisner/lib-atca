/*
 * Copyright 2017 Legrand US
 * All rights reserved.
 *
 * File contains ECC device configuration information
 *
 */

#ifndef LEGRAND_ECCDEV_CONFIG_H
#define LEGRAND_ECCDEV_CONFIG_H


/* defines used to map various items to ECC slots */
#define SLOT_DEVICE_PRIVATE_KEY             0
#define SLOT_CURRENT_PAN_ENC_KEY            1
#define SLOT_DEVICE_ECDHE_KEY               2    // slot used for ECDHE private key
#define SLOT_DEVICE_ECDHE_SHARED_KEY        3    // slot where shared kit is written
#define SLOT_MAC_ADDRESS                    4
#define SLOT_RESERVED_A                     5
#define SLOT_RESERVED_B                     6
#define SLOT_ENC_READ_WRITE_KEY             7   // used for encrypted read/writes to/from device
#define SLOT_TOPLEVEL_PUBLIC_KEYS           8
#define SLOT_FACTORY_CA_PUBLIC_KEY          9
#define SLOT_FACTORY_CA_COMPRESSED_CERT     10  // factory and device compressed certs
#define SLOT_DEVICE_COMPRESSED_CERT         11
#define SLOT_RESERVED_C                     12
#define SLOT_RESERVED_D                     13
#define SLOT_RESERVED_E                     14
#define SLOT_APPLICATION_DATA               15

#endif


