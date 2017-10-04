/*
 * Copyright 2017 Legrand North Central America
 * All Rights reserved
 *
 * Legrand specific routines to build a device cert from various
 * components stored in the ECC508A.
 *
 * NOTE: This code will run on the end device.
 */

#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
/* ATCA specific implementation */
#include "cryptoauthlib.h"
#include "crypto/atca_crypto_sw_sha2.h"
#include "atcacert/atcacert_date.h"
#include "atcacert/atcacert_def.h"
#include "tls/atcatls.h"
#include "atca_status.h"
#include "atca_iface.h"

/* Legrand specific */
#include "legrand_cert.h"
#include "legrand_eccdev_config.h"

/**
 * \brief The device and signer templates are comprised of dynamic fields
 *        and static fields.  The ECC can not store the entire certificate, so
 *        the code needs to assemble the certificate by using a static template
 *        and filling in the dynamic parts from what is stored in the ECC.
 *        For example, the device signature is stored in the ECC.  When building
 *        the device certificate, this signature is read from the ECC and copied
 *        to this static template.
 *
 *        NOTE: All of the dynamic fields are fixed length.
 */


/*
 * The device cert template.
 *
 */
#ifdef DEV_ROOT_OF_TRUST
/* public certificate chain - PEM format */
static const unsigned char legrand_root_chain_pem[] = {
    /* WSLNA_dev_Root.crt */
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBuzCCAWKgAwIBAgIQf1uFhAtybMUbhDnY+QDnQjAKBggqhkjOPQQDAjA2MQ4w"
    "DAYDVQQKDAVXU0xOQTEkMCIGA1UEAwwbV1NMTkEgRGV2ZWxvcG1lbnQgUm9vdCBD"
    "QSAxMCAXDTE2MTEyMzAwMDgxNVoYDzk5OTkxMjMxMjM1OTU5WjA2MQ4wDAYDVQQK"
    "DAVXU0xOQTEkMCIGA1UEAwwbV1NMTkEgRGV2ZWxvcG1lbnQgUm9vdCBDQSAxMFkw"
    "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGFcxboPwmxNlllujuWWy8rCXcvd5tNgt"
    "Tuf2QSRKFzvv5cOqGZb2u9VvJZ+gooc/H/hBnxBBxmoYeKFdLu7kjKNQME4wHQYD"
    "VR0OBBYEFNdc7iOM4AbYeRLK2iYgNOgjgaDXMB8GA1UdIwQYMBaAFNdc7iOM4AbY"
    "eRLK2iYgNOgjgaDXMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgdD9P"
    "ZDSI0UKcC9iivO4bJa2aJXPCzL3uTr2de9mg7OUCIESRWzukUPzOFjgl0oI8DwPf"
    "/F8Zqs1uAspKDLUtQ245\n"
    "-----END CERTIFICATE-----\n"
};

static const unsigned char device_cert_template[] = {
    0x30, 0x82, 0x01, 0x8D, 0x30, 0x82, 0x01, 0x34, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,/*(serialnum-16)*/ 0x65,
    0xC9, 0x49, 0x0E, 0xE7, 0x78, 0x74, 0xE2, 0x64, 0xAD, 0xF5, 0xA0, 0x45, 0x6D, 0x1C, 0x50, 0x30,
    0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x3E, 0x31, 0x0E, 0x30,
    0x0C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x05, 0x57, 0x53, 0x4C, 0x4E, 0x41, 0x31, 0x2C, 0x30,
    0x2A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x23,/*(signer_common_name-35)*/ 0x57, 0x53, 0x4C, 0x4E, 0x41, 0x20, 0x44, 0x65,
    0x76, 0x65, 0x6C, 0x6F, 0x70, 0x6D, 0x65, 0x6E, 0x74, 0x20, 0x43, 0x41, 0x31, 0x20, 0x53, 0x69,
    0x67, 0x6E, 0x65, 0x72, 0x20, 0x31, 0x20, 0x30, 0x35, 0x30, 0x39, 0x30, 0x20, 0x17, 0x0D,/*(notbefore_date-13)*/ 0x31,
    0x37, 0x30, 0x33, 0x31, 0x30, 0x32, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x18, 0x0F,/*(expire_date-15)*/ 0x39, 0x39,
    0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x2D, 0x31,
    0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x05, 0x57, 0x53, 0x4C, 0x4E, 0x41, 0x31,
    0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x12,/*(subject_common_name-18)*/ 0x38, 0x38, 0x41, 0x33, 0x43, 0x43,
    0x30, 0x46, 0x33, 0x31, 0x31, 0x30, 0x2E, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,/*(pub_key-64)*/ 0xA9, 0x0E, 0x35, 0x4B, 0x65, 0x8E, 0x41, 0x0C, 0x9F,
    0xE6, 0x5F, 0xCB, 0x4A, 0x7F, 0x84, 0x31, 0x14, 0x71, 0x6A, 0x6E, 0x4F, 0x59, 0x77, 0x0E, 0x62,
    0x97, 0x2D, 0xA5, 0x43, 0xB3, 0x58, 0x54, 0x7A, 0x4A, 0xBB, 0x94, 0x76, 0x82, 0x33, 0x51, 0xC5,
    0x53, 0x85, 0xBE, 0xF2, 0x33, 0xC3, 0x75, 0x9A, 0x02, 0x7D, 0x8A, 0xD4, 0x6E, 0x6B, 0xDA, 0x71,
    0x3F, 0xBE, 0xC0, 0xA9, 0x95, 0xBE, 0xF3, 0xA3, 0x23, 0x30, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55,
    0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,/*(auth_keyid-20)*/ 0x6C, 0xF5, 0x87, 0x1E, 0x22, 0x5C, 0xEF, 0x53,
    0x5F, 0xDE, 0x72, 0xE4, 0xFC, 0xAA, 0x16, 0xB4, 0x74, 0x68, 0x44, 0x54, 0x30, 0x0A, 0x06, 0x08,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,/*(sign_bitstring-0)*/ 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20,/*(signature_R-32)*/ 0x6A,
    0x8A, 0x00, 0x01, 0x18, 0xA0, 0x62, 0x1C, 0x2B, 0x9C, 0x59, 0x9A, 0x91, 0x47, 0x1B, 0x89, 0xBF,
    0x98, 0x71, 0x27, 0x6D, 0x84, 0xCC, 0x91, 0xCB, 0x6C, 0xB9, 0xB3, 0xF2, 0xB9, 0xBC, 0x2B, 0x02,
    0x20,/*(signature_S-32)*/ 0x3C, 0x2B, 0xC0, 0x08, 0x7A, 0x9C, 0xA7, 0xC0, 0x1E, 0x41, 0x7B, 0x15, 0x1D, 0xFC, 0xA5,
    0x3E, 0xC0, 0x33, 0xE0, 0xC5, 0x4C, 0x80, 0x0B, 0xBD, 0x9B, 0xAA, 0x35, 0xA3, 0x49, 0x3F, 0x81,
    0x2D
};

/*
off: 0, len: 0, name: subj_keyid
off: 15, len: 16, name: serialnum
off: 72, len: 35, name: signer_common_name
off: 111, len: 13, name: notbefore_date
off: 126, len: 15, name: expire_date
off: 170, len: 18, name: subject_common_name
off: 215, len: 64, name: pub_key
off: 296, len: 20, name: auth_keyid
off: 328, len: 0, name: sign_bitstring
off: 335, len: 32, name: signature_R
off: 369, len: 32, name: signature_S
*/

// for the device cert, will have similar defines for the signer cert
static CERT_ELEMENT device_cert_elements[CERT_ELM_MAX] =
{
    {  // Serial Number
            .elementId = CERT_ELM_SERIALNUM,
            .offset = 15,
            .fieldLen = 16,
    },
    {  // Signer common name
            .elementId = CERT_ELM_SIGNER_COMMON_NAME,
            .offset = 72,
            .fieldLen = 35,
    },
    {  // Not before date
            .elementId = CERT_ELM_NOT_BEFORE_DATE,
            .offset = 111,
            .fieldLen = 13,
    },
    {  // expire date
            .elementId = CERT_ELM_EXPIRE_DATE,
            .offset = 126,
            .fieldLen = 15,
    },
    {  // subject_common_name
            .elementId = CERT_ELM_SUBJECT_COMMON_NAME,
            .offset = 170,
            .fieldLen = 18,
    },
    {  // public key
            .elementId = CERT_ELM_PUBLIC_KEY,
            .offset = 215,
            .fieldLen = 64,
    },
    {  // auth_keyid
            .elementId = CERT_ELM_AUTH_KEY_ID,
            .offset = 296,
            .fieldLen = 20,
    },
    {  // subj_keyid
            .elementId = CERT_ELM_SUBJECT_KEY_ID,  // device does not have a subject key id
            .offset = 0,
            .fieldLen = 0,
    },
    {  // offset to the BIT STRING start of the signature block
            .elementId = CERT_ELM_SIG_BITSTRING_START,
            .offset = 328,
            .fieldLen = 0,
    },
    {  // signature_R
            .elementId = CERT_ELM_SIGNATURE_R,
            .offset = 335,
            .fieldLen = 32,  // leading 0 in case MS bit is set, do not want negative number for signature
    },
    {  // signature_S
            .elementId = CERT_ELM_SIGNATURE_S,
            .offset = 369,
            .fieldLen = 32,  // leading 0 in case MS bit is set, do not want negative number for signature
    },
};
#else
/* public certificate chain - PEM format */
static const unsigned char legrand_root_chain_pem[] = {
    /* Legrand_Root1.crt */
    "-----BEGIN CERTIFICATE-----\n"
    "MIICZzCCAe2gAwIBAgIQdR6Q91uZXKY+UiyIuYvDnDAKBggqhkjOPQQDAjB0MQsw"
    "CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU2FuIERp"
    "ZWdvMRAwDgYDVQQKEwdMZWdyYW5kMRAwDgYDVQQLEwdMZWdyYW5kMRgwFgYDVQQD"
    "Ew9MZWdyYW5kIFJvb3QgUjEwIBcNMTcwNzI2MTc0NTAwWhgPMjA1NzA3MjYxNzQ1"
    "MDBaMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQH"
    "EwlTYW4gRGllZ28xEDAOBgNVBAoTB0xlZ3JhbmQxEDAOBgNVBAsTB0xlZ3JhbmQx"
    "GDAWBgNVBAMTD0xlZ3JhbmQgUm9vdCBSMTB2MBAGByqGSM49AgEGBSuBBAAiA2IA"
    "BC8QIHtda3z+hsZawGzpH4wMQ0xcnr6wthIbDJOFtqcSAoYXsKDsJUaDLPni3/c5"
    "MtJQjXshZRMWRHlXU8MZzPGYGLK4l+KpFpQ/Y/BneS1cVE0x/sQW7oKJuU/jYgGJ"
    "kKNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE"
    "FLcTVv0kzK4sjSD61/yZ13HcP8DwMAoGCCqGSM49BAMCA2gAMGUCMBZbGRvK3V/8"
    "wIgffObFEOaL0H1caHBK0VCbKdLtFaEXKo5JCcFCaY1gJOaA/SG/9wIxAPzkB3Wt"
    "LSLEJBmlMUtRmfaGKRLCliOTBnRxIsa/3h/PUePvcvfKughDqMFdQIgLTQ==\n"
    "-----END CERTIFICATE-----\n"
    /* Legrand_BCSIntCA.crt */
    "-----BEGIN CERTIFICATE-----\n"
    "MIICiTCCAg6gAwIBAgIQcIjMnZH1OpvZ/nwY+G+nizAKBggqhkjOPQQDAjB0MQsw"
    "CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU2FuIERp"
    "ZWdvMRAwDgYDVQQKEwdMZWdyYW5kMRAwDgYDVQQLEwdMZWdyYW5kMRgwFgYDVQQD"
    "Ew9MZWdyYW5kIFJvb3QgUjEwIBcNMTcwNzI2MTc1OTAwWhgPMjA1NzA3MjYxNzU5"
    "MDBaMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRIwEAYDVQQH"
    "EwlTYW4gRGllZ28xEDAOBgNVBAoTB0xlZ3JhbmQxFDASBgNVBAsTC0xlZ3JhbmQg"
    "QkNTMRQwEgYDVQQDEwtMZWdyYW5kIEJDUzB2MBAGByqGSM49AgEGBSuBBAAiA2IA"
    "BPe3Bf5wFcluHFEKnv4NuAu2OhFeKsXKrbKyAk0YdAs5pfaJhVUnLA5yRSCJVKoc"
    "kjKu95XuhY+yvy/RAF/VdGbDt/zoQfcdrbUGj3V861vKQFbgmI/He5msd59cPZXb"
    "eqNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE"
    "FJn+106aHaKT5F+5drVj7Nv74t3tMB8GA1UdIwQYMBaAFLcTVv0kzK4sjSD61/yZ"
    "13HcP8DwMAoGCCqGSM49BAMCA2kAMGYCMQDwtb0QmOLAilbFFQDHJ87Sff7PhWxs"
    "6LF7ObFHGdw/8i1XEFGZxADdVtdbmtNr9EMCMQDvHrfiUkwk5uRfMii+MduYuy1M"
    "lGztLDwN9cK0JyIENQDNaPJ6jBfzY/jrMxKlA/s=\n"
    "-----END CERTIFICATE-----\n"
    /* Legrand_ManuCA_MC.crt */
    "-----BEGIN CERTIFICATE-----\n"
    "MIICezCCAgGgAwIBAgIQY9ey8Vwb0QrGjzTKcfHaqTAKBggqhkjOPQQDAjB0MQsw"
    "CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UEBxMJU2FuIERp"
    "ZWdvMRAwDgYDVQQKEwdMZWdyYW5kMRQwEgYDVQQLEwtMZWdyYW5kIEJDUzEUMBIG"
    "A1UEAxMLTGVncmFuZCBCQ1MwIBcNMTcwNzI2MTgwNzAwWhgPMjA1MjA3MjYxODA3"
    "MDBaMIGAMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTESMBAGA1UE"
    "BxMJU2FuIERpZWdvMRAwDgYDVQQKEwdMZWdyYW5kMRQwEgYDVQQLEwtMZWdyYW5k"
    "IEJDUzEgMB4GA1UEAxMXTGVncmFuZCBNYW51ZmFjdHVyZXIgTUMwWTATBgcqhkjO"
    "PQIBBggqhkjOPQMBBwNCAATZb5zbq/0iO7ofMlW2CIy5jBgkFnG/zaz389/RFnbH"
    "XgtzS99jJ64FjVZ6GNa67NSUKHwuZRp1lV7V1OwsHxTso2YwZDAOBgNVHQ8BAf8E"
    "BAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQU/TE6AYza0GUzcgNv"
    "HbpvauCXQ5IwHwYDVR0jBBgwFoAUmf7XTpodopPkX7l2tWPs2/vi3e0wCgYIKoZI"
    "zj0EAwIDaAAwZQIwSRJ3fX25sdFxsg0ZL9Lvyf536ApaEtM+KdPcfxjqjcjqgwDz"
    "GbTW8C/t6PTuoNXnAjEAlmeSHVfkwgLiEAg8k61u5da6ax1VlKVrw4hrbLLSYIx/"
    "/lbEscXKtn6dy2FOxOHY\n"
    "-----END CERTIFICATE-----\n"
};

unsigned const char device_cert_template[] = {
    0x30, 0x82, 0x02, 0xD7, 0x30, 0x82, 0x02, 0x7D, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,/*(serialnum-16)*/ 0x4D,
    0x54, 0x7F, 0xA0, 0x90, 0x04, 0xAE, 0x86, 0x8B, 0x4C, 0x71, 0xEB, 0xC4, 0x22, 0x1B, 0x01, 0x30,
    0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x81, 0x87, 0x31, 0x0B,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x43, 0x61, 0x6C, 0x69, 0x66, 0x6F, 0x72, 0x6E, 0x69, 0x61,
    0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x09, 0x53, 0x61, 0x6E, 0x20, 0x44,
    0x69, 0x65, 0x67, 0x6F, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x4C,
    0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C,
    0x0B, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x20, 0x42, 0x43, 0x53, 0x31, 0x27, 0x30, 0x25,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1E,/*(signer_common_name-30)*/ 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x20, 0x46,
    0x61, 0x63, 0x74, 0x6F, 0x72, 0x79, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x65, 0x72, 0x20, 0x4D, 0x43,
    0x20, 0x41, 0x30, 0x37, 0x38, 0x30, 0x1E, 0x17, 0x0D,/*(notbefore_date-13)*/ 0x31, 0x37, 0x30, 0x36, 0x32, 0x32, 0x31,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D,/*(expire_date-13)*/ 0x31, 0x38, 0x30, 0x36, 0x32, 0x32, 0x31, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x7B, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x43,
    0x61, 0x6C, 0x69, 0x66, 0x6F, 0x72, 0x6E, 0x69, 0x61, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
    0x04, 0x07, 0x0C, 0x09, 0x53, 0x61, 0x6E, 0x20, 0x44, 0x69, 0x65, 0x67, 0x6F, 0x31, 0x10, 0x30,
    0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x31,
    0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0B, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E,
    0x64, 0x20, 0x42, 0x43, 0x53, 0x31, 0x1B, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x12,/*(subject_common_name-18)*/
    0x38, 0x38, 0x41, 0x33, 0x43, 0x43, 0x30, 0x31, 0x45, 0x31, 0x31, 0x30, 0x2E, 0x6C, 0x6F, 0x63,
    0x61, 0x6C, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
    0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,/*(pub_key-64)*/ 0xA6, 0xE3, 0x02,
    0x2C, 0xFD, 0x29, 0x4D, 0x98, 0xDC, 0x68, 0xA2, 0x60, 0x8E, 0x15, 0x5D, 0x38, 0x45, 0x69, 0x08,
    0xFF, 0xC2, 0x01, 0x08, 0x0D, 0xAF, 0x4D, 0x18, 0x6F, 0x33, 0x2F, 0xA5, 0x05, 0xDF, 0x0E, 0x15,
    0xB0, 0x32, 0x87, 0x1A, 0xC7, 0xD4, 0x9E, 0xC1, 0x36, 0xA9, 0xFF, 0x91, 0x53, 0x79, 0xFB, 0x77,
    0xFE, 0x81, 0x10, 0x3A, 0x8B, 0xA9, 0x9F, 0xDB, 0x51, 0x72, 0xD6, 0xF6, 0xDB, 0xA3, 0x81, 0xD5,
    0x30, 0x81, 0xD2, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1F,
    0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,/*(auth_keyid-20)*/ 0xA1, 0x1F, 0x24, 0x86, 0x80,
    0x34, 0x13, 0x31, 0xD9, 0x01, 0x7D, 0xDE, 0xD3, 0x43, 0x52, 0x29, 0xF7, 0x32, 0xB7, 0xF6, 0x30,
    0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30,
    0x81, 0x93, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x81, 0x8B, 0x30, 0x81, 0x88, 0x30, 0x81, 0x85,
    0xA0, 0x32, 0xA0, 0x30, 0x86, 0x2E, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x70, 0x6B,
    0x69, 0x2E, 0x6C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x2E, 0x75, 0x73, 0x2F, 0x6C, 0x65, 0x67,
    0x72, 0x61, 0x6E, 0x64, 0x2D, 0x62, 0x63, 0x73, 0x2F, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73,
    0x2E, 0x63, 0x72, 0x6C, 0xA2, 0x4F, 0xA4, 0x4D, 0x30, 0x4B, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0C, 0x0B, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x20, 0x42, 0x43, 0x53,
    0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0B, 0x4C, 0x65, 0x67, 0x72, 0x61,
    0x6E, 0x64, 0x20, 0x42, 0x43, 0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C,
    0x07, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x55, 0x53, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03,
    0x02,/*(sign_bitstring-0)*/ 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20,/*(signature_R-32)*/ 0x56, 0xE9, 0x0E, 0x4C, 0xA2, 0xB1, 0x66, 0x5D,
    0x43, 0x18, 0x82, 0xD1, 0xE7, 0x7F, 0xD3, 0xF7, 0xEB, 0x58, 0xF0, 0x21, 0x65, 0xB2, 0xC8, 0x3C,
    0x8C, 0x57, 0xD2, 0x64, 0x37, 0xF9, 0x50, 0xC5, 0x02, 0x21,/*(signature_S-33)*/ 0x00, 0x89, 0xF6, 0x2B, 0x70, 0x5A,
    0x82, 0xD8, 0x94, 0x10, 0x70, 0x61, 0xA7, 0x17, 0x75, 0x2E, 0xE4, 0x90, 0x6B, 0xBA, 0x12, 0xF3,
    0x7B, 0x19, 0x2F, 0x4D, 0x7D, 0x7C, 0x3D, 0xDC, 0xBA, 0x75, 0xD0
};


/*
 * NOTE: Client does not  have a subject key id since it is the last in the chain.
 *
off: 0, len: 0, name: subj_keyid
off: 15, len: 16, name: serialnum
off: 151, len: 30, name: signer_common_name
off: 185, len: 13, name: notbefore_date
off: 200, len: 13, name: expire_date
off: 320, len: 18, name: subject_common_name
off: 365, len: 64, name: pub_key
off: 459, len: 20, name: auth_keyid
off: 657, len: 0, name: sign_bitstring
off: 664, len: 32, name: signature_R
off: 698, len: 33, name: signature_S

 */


// for the device cert, will have similar defines for the signer cert
static CERT_ELEMENT device_cert_elements[CERT_ELM_MAX] =
{
    {  // Serial Number
            .elementId = CERT_ELM_SERIALNUM,
            .offset = 15,
            .fieldLen = 16,
    },
    {  // Signer common name
            .elementId = CERT_ELM_SIGNER_COMMON_NAME,
            .offset = 151,
            .fieldLen = 30,
    },
    {  // Not before date
            .elementId = CERT_ELM_NOT_BEFORE_DATE,
            .offset = 185,
            .fieldLen = 13,
    },
    {  // expire date
            .elementId = CERT_ELM_EXPIRE_DATE,
            .offset = 200,
            .fieldLen = 13,
    },
    {  // subject_common_name
            .elementId = CERT_ELM_SUBJECT_COMMON_NAME,
            .offset = 320,
            .fieldLen = 18,
    },
    {  // public key
            .elementId = CERT_ELM_PUBLIC_KEY,
            .offset = 365,
            .fieldLen = 64,
    },
    {  // auth_keyid
            .elementId = CERT_ELM_AUTH_KEY_ID,
            .offset = 459,
            .fieldLen = 20,
    },
    {  // subj_keyid
            .elementId = CERT_ELM_SUBJECT_KEY_ID,  // device does not have a subject key id
            .offset = 0,
            .fieldLen = 0,
    },
    {  // offset to the BIT STRING start of the signature block
            .elementId = CERT_ELM_SIG_BITSTRING_START,
            .offset = 657,
            .fieldLen = 0,
    },
    {  // signature_R
            .elementId = CERT_ELM_SIGNATURE_R,
            .offset = 664,
            .fieldLen = 32,  // leading 0 in case MS bit is set, do not want negative number for signature
    },
    {  // signature_S
            .elementId = CERT_ELM_SIGNATURE_S,
            .offset = 698,
            .fieldLen = 33,  // leading 0 in case MS bit is set, do not want negative number for signature
    },
};
#endif

/*
 * The signer cert templates:
 */

#ifdef DEV_ROOT_OF_TRUST
unsigned char signer_cert_template[] = {
 0x30, 0x82, 0x01, 0xDC, 0x30, 0x82, 0x01, 0x82, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x11,/*(serialnum-17)*/ 0x7F,
 0xEA, 0xC6, 0x75, 0xC0, 0xBA, 0x33, 0x38, 0xB9, 0xA6, 0xB7, 0x8D, 0xF4, 0xD1, 0x18, 0x06, 0x01,
 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x36, 0x31, 0x0E,
 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x05, 0x57, 0x53, 0x4C, 0x4E, 0x41, 0x31, 0x24,
 0x30, 0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1B,/*(signer_common_name-27)*/ 0x57, 0x53, 0x4C, 0x4E, 0x41, 0x20, 0x44,
 0x65, 0x76, 0x65, 0x6C, 0x6F, 0x70, 0x6D, 0x65, 0x6E, 0x74, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20,
 0x43, 0x41, 0x20, 0x31, 0x30, 0x20, 0x17, 0x0D,/*(notbefore_date-13)*/ 0x31, 0x36, 0x31, 0x31, 0x32, 0x34, 0x31, 0x35,
 0x30, 0x30, 0x30, 0x30, 0x5A, 0x18, 0x0F,/*(expire_date-15)*/ 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32,
 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, 0x30, 0x3F, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04,
 0x0A, 0x0C, 0x05, 0x57, 0x53, 0x4C, 0x4E, 0x41, 0x31, 0x2D, 0x30, 0x2B, 0x06, 0x03, 0x55, 0x04,
 0x03, 0x0C, 0x24,/*(subject_common_name-36)*/ 0x57, 0x53, 0x4C, 0x4E, 0x41, 0x20, 0x44, 0x65, 0x76, 0x65, 0x6C, 0x6F, 0x70,
 0x6D, 0x65, 0x6E, 0x74, 0x20, 0x43, 0x41, 0x20, 0x31, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x65, 0x72,
 0x20, 0x32, 0x20, 0x30, 0x30, 0x30, 0x33, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42,
 0x00, 0x04,/*(pub_key-64)*/ 0xB7, 0x24, 0xDA, 0x49, 0x7B, 0x97, 0x19, 0xD1, 0xB2, 0xA6, 0x83, 0x0C, 0x1F, 0x32,
 0xA8, 0xDE, 0x06, 0x08, 0x24, 0x46, 0x0B, 0xF6, 0x46, 0x9F, 0x41, 0xEB, 0x0F, 0xAC, 0xF6, 0x0E,
 0xAA, 0x9F, 0x5F, 0x09, 0x19, 0x15, 0x66, 0x02, 0xA6, 0x4B, 0x26, 0x04, 0x67, 0x96, 0xC2, 0x00,
 0x77, 0x8B, 0x92, 0x1B, 0xDA, 0xF3, 0xD7, 0x47, 0x2E, 0x18, 0xFD, 0xF2, 0x2C, 0x78, 0x2E, 0xAF,
 0xEF, 0x65, 0xA3, 0x66, 0x30, 0x64, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF,
 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D,
 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x02, 0x84, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D,
 0x0E, 0x04, 0x16, 0x04, 0x14,/*(subj_keyid-20)*/ 0xC5, 0x17, 0x55, 0x64, 0x12, 0x9E, 0x0B, 0x77, 0x4E, 0xB3, 0xC4,
 0x88, 0x11, 0xAF, 0x55, 0x7A, 0x3A, 0x4D, 0xE8, 0x65, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23,
 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,/*(auth_keyid-20)*/ 0xD7, 0x5C, 0xEE, 0x23, 0x8C, 0xE0, 0x06, 0xD8, 0x79, 0x12,
 0xCA, 0xDA, 0x26, 0x20, 0x34, 0xE8, 0x23, 0x81, 0xA0, 0xD7, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86,
 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,/*(sign_bitstring-0)*/ 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21,/*(signature_R-33)*/ 0x00, 0xFA, 0x5B,
 0x98, 0xF3, 0xBB, 0xD2, 0x4A, 0x0F, 0x61, 0x6D, 0x38, 0xF6, 0xB9, 0x23, 0xA6, 0x4B, 0x92, 0x64,
 0x4C, 0x00, 0x02, 0x9B, 0xA1, 0xF2, 0x2F, 0x6A, 0x33, 0x9A, 0xBF, 0x10, 0x22, 0x70, 0x02, 0x20,/*(signature_S-32)*/
 0x33, 0x49, 0x7A, 0xFE, 0x6A, 0xC9, 0xB6, 0x65, 0x0D, 0xCE, 0xEC, 0xC0, 0xE3, 0x35, 0xD1, 0x62,
 0x5B, 0x10, 0x8B, 0x8F, 0x23, 0x10, 0x92, 0xFB, 0xF4, 0x54, 0xAB, 0x65, 0xAE, 0xBB, 0x04, 0x13
};

/*
off: 15, len: 17, name: serialnum
off: 73, len: 27, name: signer_common_name
off: 104, len: 13, name: notbefore_date
off: 119, len: 15, name: expire_date
off: 163, len: 36, name: subject_common_name
off: 226, len: 64, name: pub_key
off: 341, len: 20, name: subj_keyid
off: 374, len: 20, name: auth_keyid
off: 406, len: 0, name: sign_bitstring
off: 413, len: 33, name: signature_R
off: 448, len: 32, name: signature_S
 */


// for the device cert, will have similar defines for the signer cert
static CERT_ELEMENT signer_cert_elements[CERT_ELM_MAX] =
{
    {  // Serial Number
        .elementId = CERT_ELM_SERIALNUM,
        .offset = 15,
        .fieldLen = 16,
    },
    {  // Really the issuer comon name, Ignored for the factory ca
        // cert
        .elementId = CERT_ELM_SIGNER_COMMON_NAME,
        .offset = 0,
        .fieldLen = 0,
    },
    {  // Not before date
        .elementId = CERT_ELM_NOT_BEFORE_DATE,
        .offset = 104,
        .fieldLen = 13,
    },
    {   // expire date
        .elementId = CERT_ELM_EXPIRE_DATE,
        .offset = 119,
        .fieldLen = 15,
    },
    {  // subject_common_name
        // Need to add the signer id to this common name
        .elementId = CERT_ELM_SUBJECT_COMMON_NAME,
        .offset = 163,
        .fieldLen = 36,
    },
    {  // public key
        .elementId = CERT_ELM_PUBLIC_KEY,
        .offset = 226,
        .fieldLen = 64,
    },
    {  // auth_keyid
        // Use the hard-coded value in the template
        .elementId = CERT_ELM_AUTH_KEY_ID,
        .offset = 0,
        .fieldLen = 0,
    },
    {  // subj_keyid
        .elementId = CERT_ELM_SUBJECT_KEY_ID,  // device does not have a subject key id
        .offset = 341,
        .fieldLen = 20,
    },
    {  // offset to the BIT STRING start of the signature block
        .elementId = CERT_ELM_SIG_BITSTRING_START,
        .offset = 406,
        .fieldLen = 0,
    },
    {  // signature_R
        .elementId = CERT_ELM_SIGNATURE_R,
        .offset = 413,
        .fieldLen = 33,  // leading 0 in case MS bit is set, do not want negative number for signature
    },
    {  // signature_S
        .elementId = CERT_ELM_SIGNATURE_S,
        .offset = 448,
        .fieldLen = 32,  // leading 0 in case MS bit is set, do not want negative number for signature
    },
};

#else

static const uint8_t signer_cert_template[] = {
    0x30, 0x82, 0x03, 0x08, 0x30, 0x82, 0x02, 0xAD, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,/*(serialnum-16)*/ 0x4E,
    0xB9, 0x6A, 0xB7, 0xA9, 0xD0, 0x38, 0x94, 0x29, 0x05, 0x2A, 0x21, 0x87, 0x11, 0xEB, 0x48, 0x30,
    0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x81, 0x80, 0x31, 0x0B,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x43, 0x61, 0x6C, 0x69, 0x66, 0x6F, 0x72, 0x6E, 0x69, 0x61,
    0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x09, 0x53, 0x61, 0x6E, 0x20, 0x44,
    0x69, 0x65, 0x67, 0x6F, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x07, 0x4C,
    0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C,
    0x0B, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x20, 0x42, 0x43, 0x53, 0x31, 0x20, 0x30, 0x1E,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x17,/*(signer_common_name-23)*/ 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x20, 0x4D,
    0x61, 0x6E, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 0x72, 0x65, 0x72, 0x20, 0x4D, 0x43, 0x30, 0x20,
    0x17, 0x0D,/*(notbefore_date-13)*/ 0x31, 0x37, 0x30, 0x36, 0x32, 0x32, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x18,
    0x0F,/*(expire_date-15)*/ 0x32, 0x30, 0x35, 0x32, 0x30, 0x38, 0x31, 0x38, 0x32, 0x33, 0x34, 0x34, 0x34, 0x30, 0x5A,
    0x30, 0x81, 0x87, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
    0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x43, 0x61, 0x6C, 0x69, 0x66,
    0x6F, 0x72, 0x6E, 0x69, 0x61, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x09,
    0x53, 0x61, 0x6E, 0x20, 0x44, 0x69, 0x65, 0x67, 0x6F, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55,
    0x04, 0x0A, 0x0C, 0x07, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06,
    0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0B, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x20, 0x42, 0x43,
    0x53, 0x31, 0x27, 0x30, 0x25, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1E,/*(subject_common_name-30)*/ 0x4C, 0x65, 0x67, 0x72,
    0x61, 0x6E, 0x64, 0x20, 0x46, 0x61, 0x63, 0x74, 0x6F, 0x72, 0x79, 0x20, 0x53, 0x69, 0x67, 0x6E,
    0x65, 0x72, 0x20, 0x4D, 0x43, 0x20, 0x41, 0x30, 0x37, 0x38, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
    0x07, 0x03, 0x42, 0x00, 0x04,/*(pub_key-64)*/ 0xBF, 0x65, 0x61, 0x86, 0x91, 0xE2, 0x53, 0xCB, 0x16, 0x40, 0x7F,
    0x8A, 0x01, 0x3D, 0x42, 0x13, 0x02, 0x75, 0x94, 0x73, 0x46, 0x05, 0xC5, 0x05, 0xF1, 0x9B, 0xFE,
    0x14, 0x28, 0x52, 0x4B, 0x4F, 0xB9, 0xCA, 0x9B, 0x08, 0x8D, 0xB7, 0x58, 0x08, 0xD4, 0x5B, 0x12,
    0x74, 0x5E, 0x17, 0xA7, 0xD4, 0xDD, 0xB4, 0x69, 0x0E, 0xA0, 0xF6, 0xA6, 0xAB, 0xE1, 0xA5, 0x44,
    0x01, 0x10, 0x4B, 0xC3, 0xD9, 0xA3, 0x81, 0xFD, 0x30, 0x81, 0xFA, 0x30, 0x1D, 0x06, 0x03, 0x55,
    0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14,/*(subj_keyid-20)*/ 0xA1, 0x1F, 0x24, 0x86, 0x80, 0x34, 0x13, 0x31, 0xD9, 0x01,
    0x7D, 0xDE, 0xD3, 0x43, 0x52, 0x29, 0xF7, 0x32, 0xB7, 0xF6, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D,
    0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,/*(auth_keyid-20)*/ 0x12, 0x5D, 0xD8, 0x18, 0xB3, 0xE9, 0x29, 0x3B, 0x4D,
    0x34, 0x7B, 0x84, 0x36, 0x15, 0x4D, 0xF7, 0xCD, 0x4D, 0xD1, 0xD1, 0x30, 0x12, 0x06, 0x03, 0x55,
    0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00, 0x30,
    0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30,
    0x81, 0x93, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x81, 0x8B, 0x30, 0x81, 0x88, 0x30, 0x81, 0x85,
    0xA0, 0x32, 0xA0, 0x30, 0x86, 0x2E, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x70, 0x6B,
    0x69, 0x2E, 0x6C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x2E, 0x75, 0x73, 0x2F, 0x6C, 0x65, 0x67,
    0x72, 0x61, 0x6E, 0x64, 0x2D, 0x62, 0x63, 0x73, 0x2F, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73,
    0x2E, 0x63, 0x72, 0x6C, 0xA2, 0x4F, 0xA4, 0x4D, 0x30, 0x4B, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A,
    0x0C, 0x07, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55,
    0x04, 0x0B, 0x0C, 0x0B, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E, 0x64, 0x20, 0x42, 0x43, 0x53, 0x31,
    0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0B, 0x4C, 0x65, 0x67, 0x72, 0x61, 0x6E,
    0x64, 0x20, 0x42, 0x43, 0x53, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03,
    0x02,/*(sign_bitstring-0)*/ 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21,/*(signature_R-33)*/ 0x00, 0xF6, 0xD8, 0xE1, 0xA8, 0x48, 0xB7, 0x61,
    0xE0, 0x42, 0xD8, 0xC8, 0x6A, 0x2F, 0xC3, 0xA7, 0x20, 0x3E, 0x9E, 0x2C, 0x58, 0x9B, 0x67, 0x0F,
    0x35, 0x6E, 0xFB, 0x70, 0x05, 0x85, 0x41, 0xAA, 0x9D, 0x02, 0x21,/*(signature_S-33)*/ 0x00, 0xCE, 0x72, 0x7B, 0xB8,
    0x22, 0x9E, 0x91, 0x1C, 0x54, 0x3B, 0xE1, 0xB5, 0xBE, 0x78, 0x14, 0xDC, 0xDF, 0x34, 0xDA, 0xE6,
    0x09, 0x8D, 0x1A, 0x10, 0x8E, 0xDD, 0x18, 0x43, 0xE6, 0xAB, 0x57, 0x22
};

/*

 NOTE: The issuer/signer common name isn't modified for the factory CA.
off: 151, len: 23, name: signer_common_name
off: 178, len: 13, name: notbefore_date

 NOTE: The expire date is hardcoded to 35 years.
off: 193, len: 15, name: expire_date
off: 316, len: 30, name: subject_common_name
off: 373, len: 64, name: pub_key
off: 454, len: 20, name: subj_keyid
off: 487, len: 20, name: auth_keyid
off: 705, len: 0, name: sign_bitstring
off: 712, len: 33, name: signature_R
off: 747, len: 33, name: signature_S

 */


// for the device cert, will have similar defines for the signer cert
static CERT_ELEMENT signer_cert_elements[CERT_ELM_MAX] =
{
    {  // Serial Number
            .elementId = CERT_ELM_SERIALNUM,
            .offset = 15,
            .fieldLen = 16,
    },
    {  // Really the issuer comon name, Ignored for the factory ca
            // cert
            .elementId = CERT_ELM_SIGNER_COMMON_NAME,
            .offset = 0,
            .fieldLen = 0,
    },
    {  // Not before date
            .elementId = CERT_ELM_NOT_BEFORE_DATE,
            .offset = 178,
            .fieldLen = 13,
    },
    {   // expire date
            // For the factory CA's the expire date is
            // hard coded.
            .elementId = CERT_ELM_EXPIRE_DATE,
            .offset = 0,
            .fieldLen = 0,
    },
    {  // subject_common_name
            // Need to add the signer id to this common name
            .elementId = CERT_ELM_SUBJECT_COMMON_NAME,
            .offset = 316,
            .fieldLen = 30,
    },
    {  // public key
            .elementId = CERT_ELM_PUBLIC_KEY,
            .offset = 373,
            .fieldLen = 64,
    },
    {  // auth_keyid
            // Use the hard-coded value in the template
            .elementId = CERT_ELM_AUTH_KEY_ID,
            .offset = 0,
            .fieldLen = 0,
    },
    {  // subj_keyid
            .elementId = CERT_ELM_SUBJECT_KEY_ID,  // device does not have a subject key id
            .offset = 454,
            .fieldLen = 20,
    },
    {  // offset to the BIT STRING start of the signature block
            .elementId = CERT_ELM_SIG_BITSTRING_START,
            .offset = 705,
            .fieldLen = 0,
    },
    {  // signature_R
            .elementId = CERT_ELM_SIGNATURE_R,
            .offset = 712,
            .fieldLen = 33,  // leading 0 in case MS bit is set, do not want negative number for signature
    },
    {  // signature_S
            .elementId = CERT_ELM_SIGNATURE_S,
            .offset = 747,
            .fieldLen = 33,  // leading 0 in case MS bit is set, do not want negative number for signature
    },

};
#endif


/* ECC slot storage are different for certain devices - adjust at runtime */

/**
 * @brief  The slot numbers for the offical product are defined in legrand_eccdev_config.h.
 *         These are the numbers for the ECC508A devices that contain the official
 *         Legrand root of trust.
 *         However during the initial development efforts, a small batch of ECC508As
 *         were created with a "Dev" root of trust.  These chips were primarily for
 *         testing and development.  But the slot numbers for various keys are
 *         different.  These slot old "Dev" slot numbers are comment out below.
 *         There are still here just in case someone runs into an older "Dev" ECC508A.
 */
static uint8_t Slot_Device_Private_Key = SLOT_DEVICE_PRIVATE_KEY;
static uint8_t Slot_MAC_Address = SLOT_MAC_ADDRESS;
static uint8_t Slot_Top_Level_Public_Keys = SLOT_TOPLEVEL_PUBLIC_KEYS;
static uint8_t Slot_Factory_CA_Public_Key = SLOT_FACTORY_CA_PUBLIC_KEY;
static uint8_t Slot_Factory_CA_Compressed_Cert = SLOT_FACTORY_CA_COMPRESSED_CERT;
static uint8_t Slot_Device_Compressed_Cert = SLOT_DEVICE_COMPRESSED_CERT;
static uint8_t Slot_Current_Pan_Encryption_Key = SLOT_CURRENT_PAN_ENC_KEY;
static uint8_t Slot_Application_Data = SLOT_APPLICATION_DATA;

/*
static uint8_t Slot_Device_ECDHE_HMAC = 2;
static uint8_t Slot_Device_ECDHE_Key = 3;
static uint8_t Slot_Device_Private_Key_Alternate = 5;
static uint8_t Slot_Secure_Boot_Key = 6;
static uint8_t Slot_Encrypted_Read_Write_Key = 7;
static uint8_t Factory_CA_Compressed_Cert_Alternate = 12;
static uint8_t Slot_Factory_CA_Compressed_Cert_Alternate = 13;
static uint8_t Slot_Device_Compressed_Cert_Alternate = 14;
*/

/* forward prototypes for static functions */
static bool lg_set_ecc_signature(
    CERT_ELEMENT * signElement,
    uint8_t * sigBuff,
    uint32_t * sigEncodedLen);
static bool lg_store_ecc_signature(
    uint8_t * certBuf,
    const uint32_t bufLen,
    uint32_t * adjCertBufLen,
    CERT_ELEMENT * certElements,
    uint32_t numElements);

/**
 * read the ECC508A slot
 *
 * @param slotNum - slot 0..15 of the ECC508A
 * @param buffer - buffer to put data from the slot
 * @param buflen - size of the buffer
 *
 * @return 0 if successful reading, -1 if not successful
 */
static ATCA_STATUS lg_read_data_slot(
    uint8_t slotNum,
    uint8_t * buffer,
    uint16_t buflen)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t dataBlock[ATCA_BLOCK_SIZE] = { 0 };
    uint8_t blockNum = 0;
    uint32_t cnt = 0;
    int copyCount = 0;
    uint32_t numBlocks = 0;

    // Figure out the number of blocks we need to read and then
    // round up.
    numBlocks = buflen / ATCA_BLOCK_SIZE;

    // round up if necessary
    if (buflen % ATCA_BLOCK_SIZE) {
        numBlocks++;
    }
    // Read slot data in 32 byte blocks.
    // The last block may have less than 32 bytes.  For example, for 72 byte slots
    // the first two reads will read a full 32 bytes, the last read will only return
    // 8 bytes.  However you still need to request 32 bytes.
    for (cnt = 0; cnt < numBlocks; cnt++, blockNum++) {
        status =
            atcab_read_zone(ATCA_ZONE_DATA, slotNum, blockNum, 0, dataBlock,
            sizeof(dataBlock));
        if (status != ATCA_SUCCESS) {
            break;
        }
        copyCount = buflen < sizeof(dataBlock) ? buflen : sizeof(dataBlock);
        memcpy(buffer, dataBlock, copyCount);
        buflen -= ATCA_BLOCK_SIZE;
        buffer += ATCA_BLOCK_SIZE;
    }

    return status;
}

/**
 * Write data into data zone with a given byte offset and length.
 * Offset and length must be multiples of a word (4 bytes).
 *
 * @param slotNum - slot 0..15 of the ECC508A
 * @param buffer - buffer to put data from the slot
 * @param buflen - size of the buffer
 *
 * @return 0 if successful reading, -1 if not successful
 */
static ATCA_STATUS lg_write_data_slot(
    uint8_t slot,
    uint8_t * buffer,
    uint8_t buflen)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    const size_t offset_bytes = 0;

    status = atcab_write_bytes_zone(
        ATCA_ZONE_DATA,
        slot,
        offset_bytes,
        buffer,
        buflen);

    return status;
}

/*
 * SHA256(subject public key [64 bytes] + encoded dates [3 bytes])
 * Two upper most significant byte is  set to 01
 *
 * @return true if successful, false if not
 */
bool lg_generate_serialnum(
    uint8_t * serialNumber,
    const uint8_t * devicePublicKey,
    const uint8_t * date)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    // 64 byte public key (X & Y) + 3 byte encoded date
    uint8_t sha_input[ECC_P256_PUBLIC_KEYLEN + CET_ENCODED_DATE_LEN] = { 0 };
    uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE] = { 0 };

    memcpy(sha_input, devicePublicKey, ECC_P256_PUBLIC_KEYLEN);
    memcpy(&sha_input[ECC_P256_PUBLIC_KEYLEN], date, CET_ENCODED_DATE_LEN);
    // create sha 256
    status =
        atcac_sw_sha2_256(sha_input,
        ECC_P256_PUBLIC_KEYLEN + CET_ENCODED_DATE_LEN, digest);
    if (status != ATCA_SUCCESS) {
        return false;
    }
    memcpy(serialNumber, digest, CERT_SERIAL_NUM_LEN);
    // set most significant byte to 01
    serialNumber[0] &= 0x7F;
    serialNumber[0] |= 0x40;

    return true;
}

/**
 * Initilized the certificate template
 *
 * @param elements - list of #CERT_ELEMENT
 * @param numElements - number of elements in the list
 *
 * @return true if successful, false if not
 */
bool lg_init_template(
    CERT_ELEMENT * elements,
    uint32_t numElements)
{
    uint32_t cnt = 0;

    if (elements) {
        // initialize the value pointer and len
        for (cnt = 0; cnt < numElements; cnt++, elements++) {
            elements->value = NULL;
            elements->valueLen = 0;
        }
        return true;
    }

    return false;
}

/**
 * Read the compressed certificate
 *
 * @param compCert - place to put the results of reading the certificate
 * @param certType - type of certificate to read
 *
 * @return true if successful, false if not
 */
bool lg_read_compressed_cert(
    COMPRESSED_CERT * compCert,
    CERT_TYPE certType)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t slotNum = 0;

    slotNum =
        certType ==
        CERT_DEVICE ? Slot_Device_Compressed_Cert :
        Slot_Factory_CA_Compressed_Cert;
    status =
        lg_read_data_slot(slotNum, (uint8_t *) compCert, sizeof(COMPRESSED_CERT));
    if (status == ATCA_SUCCESS) {
        return true;
    }

    return false;
}

/**
 * Read the MAC address from trusted non-volatile memory
 *
 * @param macAddBuf - place to put the results of reading the MAC address
 * @param bufLen - size of the buffer
 *
 * @return true if successful, false if not
 */
bool lg_get_mac_address(
    uint8_t * mac_buffer,
    uint32_t mac_buffer_len)
{
    /* The Data block must be at least ATCA_BLOCK_SIZE bytes.
       We can't guarantee how many bytes the caller is requesting */
    uint8_t data_block[72] = { 0 };
    ATCA_STATUS status = ATCA_SUCCESS;

    status = lg_read_data_slot(Slot_MAC_Address,
        data_block, sizeof(data_block));
    if (status == ATCA_SUCCESS) {
        if (mac_buffer_len > sizeof(data_block)) {
            mac_buffer_len = sizeof(data_block);
        }
        memcpy(mac_buffer, data_block, mac_buffer_len);
        return true;
    }

    return false;
}

/**
 * Read the slot data from trusted non-volatile memory
 *
 * @param key_buffer - place to put the results of reading the slot data
 * @param key_buffer_len - size of the buffer
 *
 * @return true if successful, false if not
 */
bool lg_get_pan_key(
    uint8_t * key_buffer,
    uint32_t key_buffer_len)
{
    /* The Data block must be at least ATCA_BLOCK_SIZE bytes.
       We can't guarantee how many bytes the caller is requesting */
    uint8_t data_block[72] = { 0 };
    ATCA_STATUS status = ATCA_SUCCESS;

    status = lg_read_data_slot(Slot_Current_Pan_Encryption_Key,
        data_block, sizeof(data_block));
    if (status == ATCA_SUCCESS) {
        if (key_buffer_len > sizeof(data_block)) {
            key_buffer_len = sizeof(data_block);
        }
        memcpy(key_buffer, data_block, key_buffer_len);
        return true;
    }

    return false;
}

/**
 * Write the slot data from trusted non-volatile memory
 *
 * @param key_buffer - place to put the results of reading the slot data
 * @param key_buffer_len - size of the buffer
 *
 * @return true if successful, false if not
 */
bool lg_store_pan_key(
    uint8_t * key_buffer,
    uint32_t key_buffer_len)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    status = lg_write_data_slot(Slot_Current_Pan_Encryption_Key,
        key_buffer, key_buffer_len);
    if (status == ATCA_SUCCESS) {
        return true;
    }

    return false;
}

/**
 * Read the slot data from trusted non-volatile memory
 *
 * @param buffer - place to put the results of reading the slot data
 * @param buffer_len - size of the buffer
 *
 * @return true if successful, false if not
 */
bool lg_get_application_data(
    uint8_t * buffer,
    uint32_t buffer_len)
{
    /* The Data block must be at least ATCA_BLOCK_SIZE bytes.
       We can't guarantee how many bytes the caller is requesting */
    uint8_t data_block[72] = { 0 };
    ATCA_STATUS status = ATCA_SUCCESS;

    status = lg_read_data_slot(Slot_Application_Data,
        data_block, sizeof(data_block));
    if (status == ATCA_SUCCESS) {
        if (buffer_len > sizeof(data_block)) {
            buffer_len = sizeof(data_block);
        }
        memcpy(buffer, data_block, buffer_len);
        return true;
    }

    return false;
}

/**
 * Write the slot data from trusted non-volatile memory
 *
 * @param buffer - place to put the results of reading the slot data
 * @param buffer_len - size of the buffer
 *
 * @return true if successful, false if not
 */
bool lg_store_application_data(
    uint8_t * buffer,
    uint32_t buffer_len)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    status = lg_write_data_slot(Slot_Application_Data,
        buffer, buffer_len);
    if (status == ATCA_SUCCESS) {
        return true;
    }

    return false;
}

/**
 * Read a public key from the ECC508A
 *
 * @param publicKeyBuf - place to put the results of reading the key
 * @param keyBufLen - size of the buffer
 * @param certType = type of key (CERT_SIGNER or CERT_DEVICE) to read
 *
 * @return true if successful, false if not
 */
bool lg_get_publickey_version(
    uint8_t * version_buffer,
    uint32_t version_buffer_len)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t slot_buffer[256+4] = { 0 };

    status =
        lg_read_data_slot(Slot_Factory_CA_Public_Key, slot_buffer,
        sizeof(slot_buffer));
    if (status == ATCA_SUCCESS) {
        if (version_buffer_len >= 4) {
            version_buffer_len = 4;
        }
        memcpy(version_buffer, slot_buffer+256, version_buffer_len);
        return true;
    }

    return false;
}

/**
 * Read a public key from the ECC508A
 *
 * @param publicKeyBuf - place to put the results of reading the key
 * @param keyBufLen - size of the buffer
 * @param certType = type of key (CERT_SIGNER or CERT_DEVICE) to read
 *
 * @return true if successful, false if not
 */
bool lg_get_publickey(
    uint8_t * publicKeyBuf,
    uint32_t keyBufLen,
    CERT_TYPE certType)
{
    ATCA_STATUS status = ATCA_SUCCESS;
#ifdef DEV_ROOT_OF_TRUST
    uint8_t slot_buffer[72] = { 0 };
#endif

    // sanity check
    if (keyBufLen >= ECC_P256_PUBLIC_KEYLEN) {
        if (certType == CERT_SIGNER) {
#ifdef DEV_ROOT_OF_TRUST
            status =
                lg_read_data_slot(Slot_Factory_CA_Public_Key, slot_buffer,
                sizeof(slot_buffer));
            if (status == ATCA_SUCCESS) {
                /* slot is stored with 4 zeros padding in front */
                memcpy(publicKeyBuf, slot_buffer+4, 32);
                /* slot is stored with 4 zeros padding in front */
                memcpy(publicKeyBuf+32, slot_buffer+4+32+4, 32);
                return true;
            }
#else
            // the factory signer cert is stored in a slot
            status =
                lg_read_data_slot(Slot_Factory_CA_Public_Key, publicKeyBuf,
                keyBufLen);
            if (status == ATCA_SUCCESS) {
                return true;
            }
#endif
        } else if (certType == CERT_DEVICE) {
            // get the public key for the private key in this slot
            status = atcab_get_pubkey(Slot_Device_Private_Key, publicKeyBuf);
            if (status == ATCA_SUCCESS) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Read the Microchip public key from the ECC508A
 *
 * @param pubKeyBuf - place to put the results of reading the key
 * @param bufLen - size of the buffer
 *
 * @return true if successful, false if not
 */
bool lg_get_microchip_pubkey(
    uint8_t * pubKeyBuf,
    uint32_t bufLen)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t publicKeys[PUBLIC_KEYS_SIZE] = { 0 };

    // sanity check
    if (bufLen >= ECC_P256_PUBLIC_KEYLEN) {
        // read the public keys from the slot
        status =
            lg_read_data_slot(Slot_Top_Level_Public_Keys, publicKeys,
            (uint8_t) sizeof(publicKeys));
        if (status == ATCA_SUCCESS) {
            // the microchip mfg ca key is located after the Legand root and
            // intermediate keys.
            memcpy(pubKeyBuf, publicKeys + (ECC_P384_PUBLIC_KEYLEN * 2),
                ECC_P256_PUBLIC_KEYLEN);
            return true;
        }
    }

    return false;
}

/**
 * Read the signer common name from the ECC508A
 *
 * @param certTemplateBuf - place to put the results of reading the template
 * @param signerCNBuffer - place to put the results of reading the signer name
 * @param bufLen - size of the buffer
 * @param signerId - place to put the signer ID
 * @param signerCNElem - place to put signer Certificate Name element
 *
 * @return true if successful, false if not
 */
bool lg_get_signer_common_name(
    uint8_t * certTemplateBuf,
    uint8_t * signerCNBuffer,
    const uint32_t bufLen,
    uint8_t signerId[2],
    CERT_ELEMENT * signerCNElem)
{
    int signerStrLen = 0;
    char tempBuf[10] = { 0 };

    // init buf to 0, insures returned string is NULL terminated
    memset(signerCNBuffer, 0, bufLen);
    // lets read the common name from the template
    memcpy(signerCNBuffer, certTemplateBuf + signerCNElem->offset,
        signerCNElem->fieldLen);
    // The format of the signer common name is:
    //    "Something Something blahh  0709" where 0709 is the signer id.
    // We just need to replace the last digits with the new signer id
    // Parse out the last digits and replace with the new signer id
    //
    signerStrLen = signerCNElem->fieldLen - 1;
    // skip any trailing space
    // = signerCNBuffer + signerStrLen;
    while (signerStrLen > 0 && !isxdigit(signerCNBuffer[signerStrLen])) {
        signerStrLen--;
    }
    // went too far!!
    if (signerStrLen <= 0) {
        return false;
    }
    // should be at the end of the signer id
    // move to the beginning of the signer id
    // skip any trailing space
    while (signerStrLen > 0 && isxdigit(signerCNBuffer[signerStrLen])) {
        signerStrLen--;
    }
    // went too far!!
    if (signerStrLen <= 0) {
        return false;
    }
    // since we're pointing to a space, move back to
    // beginning of signer id number
    signerStrLen++;
    // copy new signer id into buffer
    snprintf(tempBuf, sizeof(tempBuf), "%02X%02X", signerId[0], signerId[1]);
    memcpy(signerCNBuffer + signerStrLen, tempBuf, strlen(tempBuf));

    return true;
}

/**
 * creates the subject or authority key id from the input data by
 * hashing the input data
 * 04 + public key
 *
 * @param inputKeyBuf - place to put the results of encoding the key
 * @param inputBufLen - size of the buffer
 * @param keyIdBuf - place to put the Key ID
 * @param keyIdBufLen - size of the Key ID buffer
 *
 * @return true if successful, false if not
 */
bool lg_generate_key_id(
    const uint8_t * inputKeyBuf,
    const uint32_t inputBufLen,
    uint8_t * keyIdBuf,
    uint32_t keyIdBufLen)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    // bounds check
    if ((inputBufLen != ECC_P256_PUBLIC_KEYLEN) ||
        (keyIdBufLen != CERT_KEY_ID_LEN)) {
        return false;
    }
    status = atcacert_get_key_id(inputKeyBuf, keyIdBuf);
    if (status == ATCA_SUCCESS) {
        return true;
    }

    return false;
}

/**
 * Encode valid and exiration dates
 *
 * @param compDates - place to put the results of encoding the dates
 * @param validFromDate - the valid from date
 * @param validDateLen - size of the valid from date
 * @param expireDate - the expire date
 * @param expireDateLen - size of the expire date
 *
 * @return true if successful, false if not
 */
bool lg_convert_dates(
     enum cert_type_id type,
    uint8_t * compDates,
    uint8_t * validFromDate,
    size_t * validDateLen,
    uint8_t * expireDate,
    size_t * expireDateLen)
{
    int status = 0;
    atcacert_date_format_t datefmt;
    atcacert_tm_utc_t issue_date = { 0 };
    atcacert_tm_utc_t expire_date = { 0 };

    status =
        atcacert_date_dec_compcert(compDates, DATEFMT_RFC5280_GEN, &issue_date,
        &expire_date);

    if (status != ATCACERT_E_SUCCESS) {
        return false;
    }


    // issued date is in RFC5280 format UTC
    status = atcacert_date_enc( DATEFMT_RFC5280_UTC, &issue_date,
                       validFromDate, validDateLen);

    if(status != ATCACERT_E_SUCCESS) {
        return false;
    }


    // The expiration date will differ between device and signer cert
    datefmt = (type == CERT_DEVICE) ? DATEFMT_RFC5280_UTC : DATEFMT_RFC5280_GEN;


    // expire date, Generalized date for factory signers, UTC for devices
    status = atcacert_date_enc( datefmt, &expire_date,
                       expireDate, expireDateLen);


    if(status != ATCACERT_E_SUCCESS) {
        return false;
    }


    return true;
}

/**
 * Encode the certificate length
 *
 * @param certBegin - certificate data
 * @param bufLen - size of the certificate data
 * @param tag - sequence tag used to validate where encoding happens
 * @param certlength - length to be encoded
 *
 * @return true if successful, false if not
 */
static bool leg_set_length(
    uint8_t * certBegin,
    const uint32_t tag,
    const uint16_t certlength)
{
    // sanity check, buffer should be pointing to sequence tag
    if (*certBegin++ != tag) {
        return -1;
    }
    // next three bytes are the length.
    // since these certs are almost ways > 128, have to encode lengh into
    // three bytes
    *certBegin++ = 0x82;        // len, 0x80 == multiple bytes, 0x2 == number of bytes

    *certBegin++ = (uint8_t) (certlength >> 8);
    *certBegin = (uint8_t) (certlength & 0xFF);

    return true;
}

/**
 * Store the certicate values
 *
 * @param certBuf - certificate data
 * @param bufLen - size of the certificate
 * @param certAdjLen - not really sure what certAdjLen is used for
 * @param certElements - list of certificate elements
 * @param numElements - number of elements in the list
 *
 * @return true if successful, false if not
 */
bool lg_store_cert_values(
    uint8_t * certBuf,
    const uint32_t bufLen,
    uint32_t * certAdjLen,
    CERT_ELEMENT * certElements,
    uint32_t numElements)
{
    uint32_t cnt = 0;
    CERT_ELEMENT *elemArrayBeg = certElements;
    bool status = false;

    // simply iterate through array updating the cert buffer
    for (cnt = 0; cnt < numElements; cnt++, certElements++) {

        // skip the R and S signatures, they are handled separately
        if (certElements->elementId == CERT_ELM_SIGNATURE_R ||
            certElements->elementId == CERT_ELM_SIGNATURE_S ||
            certElements->elementId == CERT_ELM_SIG_BITSTRING_START) {
            continue;
        }
        // sanity check, the value length should be the same as the field length
        // we are using fixed fields within the certificate.
        if (certElements->fieldLen != certElements->valueLen) {
            return false;
        }
        // If there's no offset and len, then this element should be skipped.
        // This is true for device certs, where there is no subject key id field.
        if (certElements->fieldLen == 0 && certElements->offset == 0) {
            continue;
        }

        // copy the dynamic value into the static cert
        memcpy(certBuf + certElements->offset, certElements->value,
            certElements->fieldLen);
    }

    // special handling for the signatures
    status =
        lg_store_ecc_signature(certBuf, bufLen, certAdjLen, elemArrayBeg,
        numElements);
    if (status) {
        // NOTE: The certAdjLen includes the beginning sequence and len
        // now fixup the entire cert length, subtract the beginning sequence
        // tag and length.  1 byte for sequence, 3 bytes for the length, total of
        // 4 bytes.
        status = leg_set_length(certBuf, 0x30, *certAdjLen - 4);
    }

    return status;
}

// debug/test signatures to test trimming
uint8_t sig1_padd[32] = {
    // Since the most significant bit in the first byte is
    // set, then padd with a leading 0 byte.
    0x9C, 0x92, 0x55, 0x1E, 0x8B, 0x85, 0x5E, 0x30, 0xEA, 0xA0, 0x9B, 0xC8,
        0x47, 0x3C, 0x79, 0x27,
    0xA4, 0x60, 0xE8, 0x16, 0x11, 0x93, 0x5D, 0x60, 0xC2, 0xD6, 0xD8, 0x34,
        0xBF, 0x99, 0xB5, 0xCF
};

uint8_t sig2_trim[32] = {
    // should trim one byte
    0x00, 0x55, 0xDD, 0x5A, 0xB5, 0x7E, 0x48, 0xF8, 0xEA, 0x59, 0xAB, 0xC6,
        0xE6, 0x09, 0x54, 0xE8,
    0x46, 0x25, 0x8C, 0xCA, 0x1E, 0x63, 0x25, 0xF4, 0xA4, 0x86, 0x55, 0x20,
        0xB0, 0xFA, 0x48, 0xAE
};

uint8_t sig3_trim[32] = {
    // should trim two bytes
    0x00, 0x00, 0x7F, 0x1E, 0x8B, 0x85, 0x5E, 0x30, 0xEA, 0xA0, 0x9B, 0xC8,
        0x47, 0x3C, 0x79, 0x27,
    0xA4, 0x60, 0xE8, 0x16, 0x11, 0x93, 0x5D, 0x60, 0xC2, 0xD6, 0xD8, 0x34,
        0xBF, 0x99, 0xB5, 0xCF
};

uint8_t sig4_trim[32] = {
    // No trimming
    0x00, 0x80, 0x7F, 0x1E, 0x8B, 0x85, 0x5E, 0x30, 0xEA, 0xA0, 0x9B, 0xC8,
        0x47, 0x3C, 0x79, 0x27,
    0xA4, 0x60, 0xE8, 0x16, 0x11, 0x93, 0x5D, 0x60, 0xC2, 0xD6, 0xD8, 0x34,
        0xBF, 0x99, 0xB5, 0xCF
};

uint8_t sig5_trim[32] = {
    // Trim one byte
    0x00, 0x00, 0x8F, 0x1E, 0x8B, 0x85, 0x5E, 0x30, 0xEA, 0xA0, 0x9B, 0xC8,
        0x47, 0x3C, 0x79, 0x27,
    0xA4, 0x60, 0xE8, 0x16, 0x11, 0x93, 0x5D, 0x60, 0xC2, 0xD6, 0xD8, 0x34,
        0xBF, 0x99, 0xB5, 0xCF
};

/**
 * Store the ECC signature
 *
 * @param certBuf - certificate data
 * @param bufLen - size of the certificate
 * @param adjCertBufLen - not really sure what adjCertBufLen is used for
 * @param certElements - list of certificate elements
 * @param numElements - number of elements in the list
 *
 * @return true if successful, false if not
 */
static bool lg_store_ecc_signature(
    uint8_t * certBuf,
    const uint32_t bufLen,
    uint32_t * adjCertBufLen,
    CERT_ELEMENT * certElements,
    uint32_t numElements)
{
    uint8_t *certSigLoc = NULL;
    uint32_t sigEncodedLen = 0;
    uint32_t totalSigLen = 0;
    uint8_t sigBuff[70] = { 0 };

    /*
       // some unit testing
       certElements[CERT_ELM_SIGNATURE_R].value = sig1_padd;
       lg_set_ecc_signature(&certElements[CERT_ELM_SIGNATURE_R], sigBuff, &sigEncodedLen);

       certElements[CERT_ELM_SIGNATURE_R].value = sig2_trim;
       lg_set_ecc_signature(&certElements[CERT_ELM_SIGNATURE_R], sigBuff, &sigEncodedLen);

       certElements[CERT_ELM_SIGNATURE_R].value = sig3_trim;
       lg_set_ecc_signature(&certElements[CERT_ELM_SIGNATURE_R], sigBuff, &sigEncodedLen);

       certElements[CERT_ELM_SIGNATURE_R].value = sig4_trim;
       lg_set_ecc_signature(&certElements[CERT_ELM_SIGNATURE_R], sigBuff, &sigEncodedLen);

       certElements[CERT_ELM_SIGNATURE_R].value = sig5_trim;
       lg_set_ecc_signature(&certElements[CERT_ELM_SIGNATURE_R], sigBuff, &sigEncodedLen);
     */

    // check if we need to pad or trim the R part of the signature
    lg_set_ecc_signature(&certElements[CERT_ELM_SIGNATURE_R], sigBuff,
        &sigEncodedLen);

    // certSigLoc should be pointing to the beginning of the R buffer,
    // after the INTGER tag and length
    certSigLoc = certBuf + certElements[CERT_ELM_SIGNATURE_R].offset;
    memcpy(certSigLoc, sigBuff, sigEncodedLen);
    *(certSigLoc - 1) = sigEncodedLen;
    totalSigLen = (sigEncodedLen + 2);  // 2 for the integer tag and len bytes
    // go to the new S location
    certSigLoc += sigEncodedLen;
    *certSigLoc = 0x02; // INTEGER TAG
    certSigLoc++;
    totalSigLen += 2;   // add the tag and len for the S part
    // check if we need to pad or trim the S part of the signature
    lg_set_ecc_signature(&certElements[CERT_ELM_SIGNATURE_S], sigBuff,
        &sigEncodedLen);
    // set the length of the S Signature
    *certSigLoc = sigEncodedLen;
    certSigLoc++;
    totalSigLen += sigEncodedLen;
    memcpy(certSigLoc, sigBuff, sigEncodedLen);
    // now fixup the SEQUENCE and BIT STRING
    //
    // The format of the BIT STRING section in the certificate signature
    // structure is
    //
    //   BIT STRING
    //   SEQUENCE
    //   INTEGER  R Sig
    //   INTEGET  S Signature
    //
    //   The bytes look like this:
    //
    //   0x03  BIT STRING tag
    //   xx    bit string length
    //   xx    bit stream trailing zeros byte
    //   0x30  SEQUENCE tag
    //   xx    sequence length
    //
    //
    certSigLoc = certBuf + certElements[CERT_ELM_SIG_BITSTRING_START].offset;
    // should be pointing to the BIT STRING type
    if (*certSigLoc != 0x03) {
        return false;
    }
    // update the BIT STRING len
    certSigLoc++;
    // need to include the BIT STRING leading byte
    // plus the sequnce tag and len
    *certSigLoc =
        totalSigLen + 1 /* leading byte */  +
        2 /* BIT STING tag and length */ ;
    // update the total certiticate lengh
    *adjCertBufLen =
        certElements[CERT_ELM_SIG_BITSTRING_START].offset + *certSigLoc +
        2 /* Sequence Tag and len */ ;
    // go past the bit stream tag and trailing zeros byte
    certSigLoc += 2;
    // should be pointing to the sequence tag
    if (*certSigLoc != 0x30) {
        return false;
    }
    // go the sequence length
    certSigLoc++;
    *certSigLoc = totalSigLen;

    return true;
}

/**
 * Encode the ECC signature
 *
 * @param signElement - signature element
 * @param sigBuff - buffer of the encoded signature data
 * @param sigEncodedLen - size of the encoded signature data
 *
 * @return true if successful, false if not
 */
static bool lg_set_ecc_signature(
    CERT_ELEMENT * signElement,
    uint8_t * sigBuff,
    uint32_t * sigEncodedLen)
{
    int trimByteCnt = 0;
    *sigEncodedLen = 0;

    // check if we need to add any padding bytes
    if (*signElement->value & 0x80) {
        // yest need to add padding byte
        *sigBuff = 0;
        sigBuff++;

        memcpy(sigBuff, signElement->value, signElement->valueLen);

        // add 1 to the length to account for the pad byte
        *sigEncodedLen = 1 + signElement->valueLen;
    } else {
        // do we need to trim?
        while (*(signElement->value + trimByteCnt) == 0 &&
            trimByteCnt < signElement->valueLen) {
            trimByteCnt++;
        }

        // went to far
        if (trimByteCnt == signElement->valueLen) {
            // error
            return false;
        }
        // check when to start triming
        if (*(signElement->value + trimByteCnt) & 0x80) {
            // need to decrement trim count, need at least 9 bits set
            // to zero before trimming preceeding byte
            if (trimByteCnt > 0)
                trimByteCnt--;

            memcpy(sigBuff, signElement->value + trimByteCnt,
                signElement->valueLen - trimByteCnt);
            *sigEncodedLen = signElement->valueLen - trimByteCnt;
        } else if (*(signElement->value + trimByteCnt) & 0x7F) {
            memcpy(sigBuff, signElement->value + trimByteCnt,
                signElement->valueLen - trimByteCnt);
            *sigEncodedLen = signElement->valueLen - trimByteCnt;
        } else {
            // no trimming needed
            memcpy(sigBuff, signElement->value, signElement->valueLen);
            *sigEncodedLen = signElement->valueLen;
        }
    }

    return true;
}

/** release (free) the global ATCADevice instance.
 *  This must be called in order to release or free up the interface.
 *
 *  @return true if successful
 */
bool lg_release_atca(
    void)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    status = atcab_release();
    if (status == ATCA_SUCCESS) {
        return true;
    }

    return false;
}

/** release (free) the global ATCADevice instance.
 *  This must be called in order to release or free up the interface.
 *
 *  @return true if successful
 */
bool lg_release_atcatls(
    void)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    status = atcab_release();
    if (status == ATCA_SUCCESS) {
        return true;
    }

    return false;
}

/** Determine if we are development or root-of-trust ECC508
 *
 *  @return true if successful
 */
static void lg_init_slots(void)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t data_block[ATCA_BLOCK_SIZE] = { 0 };
    bool slot_lock_status[16] = { false };
    unsigned i = 0;

    /* reading the MAC Address from a non-readable slot will give us
       an error, so we can detect and change the slot numbers */
    status = lg_read_data_slot(4, data_block, sizeof(data_block));
    if (status == ATCA_SUCCESS) {
        /* the lock status *should* give us an idea which config we have */
        for (i = 0; i < 16; i++) {
            atcab_is_slot_locked(i, &slot_lock_status[i]);
        }
        /* FIXME: fingerprint of root-of-trust ECC508 slots? */
    } else if (status == ATCA_EXECUTION_ERROR) {
        /* FIXME: use alternate mapping of slots for Dev RoT */
        Slot_Device_Compressed_Cert = 10;
        Slot_Factory_CA_Public_Key = 11;
        Slot_Factory_CA_Compressed_Cert = 12;
        Slot_MAC_Address = 13;
        Slot_Current_Pan_Encryption_Key = 14;
        Slot_Application_Data = 15;
    }
}

/** Called once for the life of the application and creates a global
 *  ATCADevice object used by Basic API.
 *
 *  @param[in] cfg is a pointer to an interface configuration.
 *   This is usually a predefined configuration found in atca_cfgs.h
 *
 *  @return true if successful
 */
bool lg_init_atca(
    ATCAIfaceCfg * cfg)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    status = atcab_init(cfg);
    if (status == ATCA_SUCCESS) {
        lg_init_slots();
        return true;
    }

    return false;
}

/** Initialize the ECC508 for use with the TLS API.  Like a constructor
 *
 *  @param[in] pCfg The ATCAIfaceCfg configuration that defines the HAL layer interface
 *
 *  @return ATCA_STATUS
 */
bool lg_init_atcatls(ATCAIfaceCfg* pCfg)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    status = atcatls_init(pCfg);
    if (status == ATCA_SUCCESS) {
        lg_init_slots();
        return true;
    }

    return false;
}

/**
 *
 * read the Factory Certificate from ECC508A
 *
 * @param certBuf
 * @param certBufLen
 * @param certAdjLen
 *
 * @return true if successful, false if not
 */
bool lg_factory_ca_read_certificate(
    uint8_t * certBuf,
    const uint32_t certBufLen,
    uint32_t * certAdjLen)
{
    uint32_t certTemplateLen = 0;
    COMPRESSED_CERT factoryCompCert = {{ 0 }};
    uint8_t signerPublicKey[ECC_P256_PUBLIC_KEYLEN] = { 0 };
    uint8_t serialNumber[CERT_SERIAL_NUM_LEN] = { 0 };;
    uint8_t factoryKeyId[CERT_KEY_ID_LEN] = { 0 };
    uint8_t validDate[CERT_MAX_DATE_LEN] = { 0 };
    uint8_t expireDate[CERT_MAX_DATE_LEN] = { 0 };
    uint8_t signerCommonName[MAX_COMMON_NAME] = { 0 };
    size_t validDateLen = 0, expireDateLen = 0;

    if (certBufLen < sizeof(signer_cert_template)) {
        /* bad parameter */
        return false;
    }
    // copy the template to the buffer provided
    memcpy(certBuf, signer_cert_template, sizeof(signer_cert_template));
    certTemplateLen = sizeof(signer_cert_template);

    // read compressed cert from slot
    // The compressed cert contiains information for:
    //  Signer id  - CERT_ELM_SIGNER_ID & CERT_ELM_SIGNER_COMMON_NAME
    //  Valid Dates - CERT_ELM_NOT_BEFORE_DATE & CERT_ELM_EXPIRE_DATE
    //  Serial number source - CERT_ELM_SERIALNUM
    //  ECC Signature, R & S components- CERT_ELM_SIGNATURE_R, CERT_ELM_SIGNATURE_S
    if (!lg_read_compressed_cert(&factoryCompCert, CERT_SIGNER)) {
        return false;
    }

    // Convert the date compressed format to the format used by
    // the certificate, which is UTC.
    validDateLen = expireDateLen = CERT_MAX_DATE_LEN;

    lg_convert_dates(CERT_SIGNER, factoryCompCert.dates, validDate, &validDateLen,
        expireDate, &expireDateLen);

    signer_cert_elements[CERT_ELM_NOT_BEFORE_DATE].value = validDate;
    signer_cert_elements[CERT_ELM_NOT_BEFORE_DATE].valueLen = validDateLen;

#ifdef DEV_ROOT_OF_TRUST
    // For the DEV RoT, use expire date from slot in ECC508
    signer_cert_elements[CERT_ELM_EXPIRE_DATE].value = expireDate;
    signer_cert_elements[CERT_ELM_EXPIRE_DATE].valueLen = expireDateLen;
#else
    // For the Factory CA certs, the hard coded expire date in the template is used.
#endif
    // set the common name for the signer
    // Just need to change the signer id number at the end of the string.
    lg_get_signer_common_name(certBuf, signerCommonName,
        sizeof(signerCommonName), factoryCompCert.signerid,
        &signer_cert_elements[CERT_ELM_SUBJECT_COMMON_NAME]);

    signer_cert_elements[CERT_ELM_SUBJECT_COMMON_NAME].value =
        signerCommonName;
    signer_cert_elements[CERT_ELM_SUBJECT_COMMON_NAME].valueLen =
        strlen((char *) signerCommonName);

    // get the R part of the signature
    signer_cert_elements[CERT_ELM_SIGNATURE_R].value =
        factoryCompCert.signature;
    signer_cert_elements[CERT_ELM_SIGNATURE_R].valueLen =
        ECC_P256_SIGNATURE_PART_SIZE;

    // get the S part of the signature
    signer_cert_elements[CERT_ELM_SIGNATURE_S].value =
        &factoryCompCert.signature[ECC_P256_SIGNATURE_PART_SIZE];
    signer_cert_elements[CERT_ELM_SIGNATURE_S].valueLen =
        ECC_P256_SIGNATURE_PART_SIZE;

    // get the public key - CERT_ELM_PUBLIC_KEY
    // The public key for the signer is stored in the ECC508A

    if (!lg_get_publickey(signerPublicKey, sizeof(signerPublicKey),
            CERT_SIGNER)) {
        return false;
    }

    signer_cert_elements[CERT_ELM_PUBLIC_KEY].value = signerPublicKey;
    signer_cert_elements[CERT_ELM_PUBLIC_KEY].valueLen =
        ECC_P256_PUBLIC_KEYLEN;

    // we use the 0xA format for the serial number.
    if (!lg_generate_serialnum(serialNumber, signerPublicKey,
            factoryCompCert.dates)) {
        return false;
    }

    signer_cert_elements[CERT_ELM_SERIALNUM].value = serialNumber;
    signer_cert_elements[CERT_ELM_SERIALNUM].valueLen = CERT_SERIAL_NUM_LEN;

    // CERT_ELM_AUTH_KEY_ID
    // The authority key id is the Microchip intermediate CA, this is
    // hard-coded.

    // Get the subject key id
    if (!lg_generate_key_id(signerPublicKey, sizeof(signerPublicKey),
            factoryKeyId, sizeof(factoryKeyId))) {
        return false;
    }
    // store subjectKeyID
    signer_cert_elements[CERT_ELM_SUBJECT_KEY_ID].value = factoryKeyId;

    // Subject and authority key ids are 20 bytes each
    signer_cert_elements[CERT_ELM_SUBJECT_KEY_ID].valueLen = CERT_KEY_ID_LEN;


    // now that we have all of the pieces, plug in the dynamic
    // fields into the static template
    if (!lg_store_cert_values(certBuf, certTemplateLen, certAdjLen,
            signer_cert_elements, CERT_ELM_MAX)) {
        return false;
    }

    return true;
}

/**
 *
 * read the Device Certificate from ECC508A
 *
 * @param certBuf
 * @param certBufLen
 * @param certAdjLen
 *
 * @return true if successful, false if not
 */
bool lg_device_read_certificate(
    uint8_t * certBuf,
    const uint32_t certBufLen,
    uint32_t * certAdjLen)
{
    COMPRESSED_CERT deviceCompCert = {{ 0 }};
    uint8_t macAddress[40] = { 0 };
    uint8_t devicePublicKey[ECC_P256_PUBLIC_KEYLEN] = { 0 };
    uint8_t signerPublicKey[ECC_P256_PUBLIC_KEYLEN] = { 0 };
    uint8_t signerCommonName[MAX_COMMON_NAME] = { 0 };
    uint8_t serialNumber[CERT_SERIAL_NUM_LEN] = { 0 };
    uint8_t validDate[CERT_MAX_DATE_LEN] = { 0 };
    uint8_t expireDate[CERT_MAX_DATE_LEN] = { 0 };
    uint8_t authorityKeyId[CERT_KEY_ID_LEN] = { 0 };
    size_t validDateLen = 0, expireDateLen = 0;
    uint32_t certTemplateLen = 0;


    if (certBufLen < sizeof(device_cert_template)) {
        return false;
    }
    // init device cert values
    lg_init_template(device_cert_elements, CERT_ELM_MAX);


    // copy the template to the buffer provided
    memcpy(certBuf, device_cert_template, sizeof(device_cert_template));

    certTemplateLen = sizeof(device_cert_template);

    // read compressed cert from slot
    // The compressed cert contiains information for:
    //  Signer id  - CERT_ELM_SIGNER_ID & CERT_ELM_SIGNER_COMMON_NAME
    //  Valid Dates - CERT_ELM_NOT_BEFORE_DATE & CERT_ELM_EXPIRE_DATE
    //  Serial number source - CERT_ELM_SERIALNUM
    //  ECC Signature, R & S components- CERT_ELM_SIGNATURE_R, CERT_ELM_SIGNATURE_S
    if (!lg_read_compressed_cert(&deviceCompCert, CERT_DEVICE) ) {
        return false;
    }
    // get the R part of the signature
    device_cert_elements[CERT_ELM_SIGNATURE_R].value =
        deviceCompCert.signature;
    device_cert_elements[CERT_ELM_SIGNATURE_R].valueLen =
        ECC_P256_SIGNATURE_PART_SIZE;

    // get the S part of the signature
    device_cert_elements[CERT_ELM_SIGNATURE_S].value =
        &deviceCompCert.signature[ECC_P256_SIGNATURE_PART_SIZE];
    device_cert_elements[CERT_ELM_SIGNATURE_S].valueLen =
        ECC_P256_SIGNATURE_PART_SIZE;

    // get the signer common name, add the signer id.
    lg_get_signer_common_name(certBuf, signerCommonName,
        sizeof(signerCommonName), deviceCompCert.signerid,
        &device_cert_elements[CERT_ELM_SIGNER_COMMON_NAME]);

    device_cert_elements[CERT_ELM_SIGNER_COMMON_NAME].value = signerCommonName;
    device_cert_elements[CERT_ELM_SIGNER_COMMON_NAME].valueLen =
        strlen((char *) signerCommonName);

    // Convert the date compressed format to the format used by
    // the certificate, which is UTC.
    validDateLen = expireDateLen = CERT_MAX_DATE_LEN;

#ifdef DEV_ROOT_OF_TRUST
    // for the he WSLNA dev trust chain, both the signer and device certs
    // use the Generalized time format for the expire date.
    // NOTE: We should rename CERT_SIGNER/DEVICE to CERT_EXPIRETM_GENERALIZED/UTCTIME
    lg_convert_dates(CERT_SIGNER, deviceCompCert.dates, validDate, &validDateLen,
        expireDate, &expireDateLen);
#else
    lg_convert_dates(CERT_DEVICE, deviceCompCert.dates, validDate, &validDateLen,
        expireDate, &expireDateLen);
#endif

    device_cert_elements[CERT_ELM_NOT_BEFORE_DATE].value = validDate;
    device_cert_elements[CERT_ELM_NOT_BEFORE_DATE].valueLen = validDateLen;

    device_cert_elements[CERT_ELM_EXPIRE_DATE].value = expireDate;
    device_cert_elements[CERT_ELM_EXPIRE_DATE].valueLen = expireDateLen;


    // get the mac address, used for the common name
    // the mac address is CERT_ELM_SUBJECT_COMMON_NAME
    //  <mac addr>.local
    if (!lg_get_mac_address(macAddress, sizeof(macAddress))) {
        return false;
    }

    strncat((char *) macAddress, ".local", strlen(".local"));

    // set the common name
    device_cert_elements[CERT_ELM_SUBJECT_COMMON_NAME].value = macAddress;
    device_cert_elements[CERT_ELM_SUBJECT_COMMON_NAME].valueLen =
        strlen((char *) macAddress);


    // get the public key - CERT_ELM_PUBLIC_KEY
    // The public key is generated from the private key
    if (!lg_get_publickey(devicePublicKey, sizeof(devicePublicKey),
            CERT_DEVICE)) {
        return false;
    }

    device_cert_elements[CERT_ELM_PUBLIC_KEY].value = devicePublicKey;
    device_cert_elements[CERT_ELM_PUBLIC_KEY].valueLen =
        ECC_P256_PUBLIC_KEYLEN;

    // get the signer's public key
    if (!lg_get_publickey(signerPublicKey, sizeof(signerPublicKey),
            CERT_SIGNER)) {
        return false;
    }
    // we use the 0xA format for the serial number.
    if (!lg_generate_serialnum(serialNumber, devicePublicKey,
            deviceCompCert.dates)) {
        return false;
    }

    device_cert_elements[CERT_ELM_SERIALNUM].value = serialNumber;
    device_cert_elements[CERT_ELM_SERIALNUM].valueLen = CERT_SERIAL_NUM_LEN;

    // CERT_ELM_AUTH_KEY_ID
    // the signer public key is used to generate the authority
    // key identifer for the device.
    if (!lg_generate_key_id(signerPublicKey, sizeof(signerPublicKey),
            authorityKeyId, sizeof(authorityKeyId))) {
        return false;
    }
    // store authorityKeyID
    device_cert_elements[CERT_ELM_AUTH_KEY_ID].value = authorityKeyId;

    // Subject and authority key ids are 20 bytes each
    device_cert_elements[CERT_ELM_AUTH_KEY_ID].valueLen = CERT_KEY_ID_LEN;

    // For device certs, the subject key id is not used.

    // now that we have all of the pieces, plug in the dynamic
    // fields into the static template
    if (!lg_store_cert_values(certBuf, certTemplateLen, certAdjLen,
            device_cert_elements, CERT_ELM_MAX)) {
        return false;
    }

    return true;
}

/**
 *
 * read the Public Certificate chain
 *
 * @return pointer to the PEM format certificates C string
 */
const unsigned char * lg_root_certificate_chain_pem(void)
{
    return legrand_root_chain_pem;
}

/**
 *
 * read the Public Certificate chain size
 *
 * @return size of the PEM format certificates C string in bytes
 */
size_t lg_root_certificate_chain_pem_size(void)
{
    return sizeof(legrand_root_chain_pem);
}
