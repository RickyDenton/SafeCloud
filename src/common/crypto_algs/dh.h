#ifndef SAFECLOUD_DH_H
#define SAFECLOUD_DH_H

/* Declarations of the OpenSSL DH utility functions used by the SafeCloud application */

#include <openssl/evp.h>

/**
 * @brief  Generates an ephemeral DH key pair using the DH standard parameters
 * @return A pointer to the generated ephemeral DH key pair
 */
EVP_PKEY* dhe_2048_keygen();

#endif //SAFECLOUD_DH_H
