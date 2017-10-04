/*
 * Copyright 2017 Legrand North Central America
 * All Rights reserved
 *
 * Defines for building the signer and device certs
 *
 * NOTE: This code will run on the end device.
 */
#ifndef LEGRAND_CERT_H
#define LEGRAND_CERT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "atca_iface.h"

#define CERT_SERIAL_NUM_LEN             16
#define ECC_P384_PUBLIC_KEYLEN          96
#define ECC_P256_PUBLIC_KEYLEN          64
#define CET_ENCODED_DATE_LEN             3
#define CERT_KEY_ID_LEN                 20      // subject and authority key id
#define MAX_COMMON_NAME                 50

// Three keys are stored together, the Legrand Root and Intermediate keys followed
// by the Microchip Mfg CA key.  The Legrand Root and Intermediate keys are P384 curves,
// the Microchip Mfg CA key is a P256 curve.
#define PUBLIC_KEYS_SIZE                ((2 * ECC_P384_PUBLIC_KEYLEN) + ECC_P256_PUBLIC_KEYLEN)

// The size of one ECC signature component, either R or S
// The total signature size is 64 bytes (P256 curve).
#define ECC_P256_SIGNATURE_PART_SIZE    32
#define CERT_MAX_DATE_LEN               30

enum cert_type_id {
    CERT_UNKNOWN = 0,
    CERT_DEVICE = 1,
    CERT_SIGNER = 2
};

typedef enum cert_type_id CERT_TYPE;

/* Compressed cert format */

#pragma pack (push, 1)  // force byte alignment

typedef struct compressed_cert {
    uint8_t signature[64];
    uint8_t dates[3];   // encoded valid dates
    uint8_t signerid[2];        // Microchip signer id
    uint8_t tempchain;  // Template chain ids
    uint8_t snformat;   // serial num, format id
    uint8_t reserved;   // not used
} COMPRESSED_CERT;

#pragma pack(pop)

/* enum types for elements */
enum cert_elem_id {
    CERT_ELM_SERIALNUM = 0,
    CERT_ELM_SIGNER_COMMON_NAME = 1,
    CERT_ELM_NOT_BEFORE_DATE = 2,
    CERT_ELM_EXPIRE_DATE = 3,
    CERT_ELM_SUBJECT_COMMON_NAME = 4,
    CERT_ELM_PUBLIC_KEY = 5,
    CERT_ELM_AUTH_KEY_ID = 6,
    CERT_ELM_SUBJECT_KEY_ID = 7,
    CERT_ELM_SIG_BITSTRING_START = 8,
    CERT_ELM_SIGNATURE_R = 9,

    // must be last
    CERT_ELM_SIGNATURE_S = 10,
    CERT_ELM_MAX = CERT_ELM_SIGNATURE_S + 1
};

typedef enum cert_elem_id CERT_ELEMENT_ID;

/* structs used to define offsets into template */
struct cert_element_info {
    const CERT_ELEMENT_ID elementId;
    const uint32_t offset;
    const uint32_t fieldLen;

    // the value to store
    uint8_t *value;
    uint32_t valueLen;
};

typedef struct cert_element_info CERT_ELEMENT;

struct ATCAIfaceCfg;

#ifdef __cplusplus
extern "C" {
#endif

// function declarations
    bool lg_device_read_certificate(
        uint8_t * certBuf,
        const uint32_t certBufLen,
        uint32_t * certAdjLen);
    bool lg_factory_ca_read_certificate(
        uint8_t * certBuf,
        const uint32_t certBufLen,
        uint32_t * certAdjLen);
    bool lg_get_microchip_pubkey(
        uint8_t * pubKeyBuf,
        uint32_t bufLen);
    bool lg_generate_serialnum(
        uint8_t * serialNumber,
        const uint8_t * devicePublicKey,
        const uint8_t * date);
    bool lg_read_compressed_cert(
        COMPRESSED_CERT * compCert,
        CERT_TYPE certType);
    bool lg_init_template(
        CERT_ELEMENT * elements,
        uint32_t numElements);
    bool lg_get_mac_address(
        uint8_t * macAddBuf,
        uint32_t bufLen);
    bool lg_get_pan_key(
        uint8_t * key_buffer,
        uint32_t key_buffer_len);
    bool lg_store_pan_key(
        uint8_t * key_buffer,
        uint32_t key_buffer_len);
    bool lg_get_application_data(
        uint8_t * buffer,
        uint32_t buffer_len);
    bool lg_store_application_data(
        uint8_t * buffer,
        uint32_t buffer_len);
    bool lg_get_publickey_version(
        uint8_t * version_buffer,
        uint32_t version_buffer_len);
    bool lg_get_publickey(
        uint8_t * publicKeyBuf,
        uint32_t keyBufLen,
        CERT_TYPE certType);
    bool lg_generate_key_id(
        const uint8_t * inputKeyBuf,
        const uint32_t inputBufLen,
        uint8_t * keyIdBuf,
        uint32_t keyIdBufLen);
    bool lg_get_signer_common_name(
        uint8_t * certTemplateBuf,
        uint8_t * signerCNBuffer,
        const uint32_t bufLen,
        uint8_t signerId[2],
        CERT_ELEMENT * signerCNElem);
    bool lg_convert_dates(
        enum cert_type_id type,
        uint8_t * compDates,
        uint8_t * validFromDate,
        size_t * validDateLen,
        uint8_t * expireDate,
        size_t * expireDateLen);
    bool lg_store_cert_values(
        uint8_t * certBuf,
        const uint32_t bufLen,
        uint32_t * certAdjLen,
        CERT_ELEMENT * certElements,
        uint32_t numElements);

    const unsigned char * lg_root_certificate_chain_pem(void);
    size_t lg_root_certificate_chain_pem_size(void);

/* ATCA specific functions */
    bool lg_release_atca(
        void);
    bool lg_init_atca(
        ATCAIfaceCfg * cfg);
/* ATCATLS specific functions */
    bool lg_init_atcatls(
        ATCAIfaceCfg* pCfg);
    bool lg_release_atcatls(
        void);

#ifdef __cplusplus
}
#endif
#endif
