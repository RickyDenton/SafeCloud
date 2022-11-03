#ifndef SAFECLOUD_DIGSIG_H
#define SAFECLOUD_DIGSIG_H

/* OpenSSL Digital Signatures Utility Functions Declarations */

/* ================================== INCLUDES ================================== */

// OpenSSL Headers
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/* =========================== FUNCTIONS DECLARATIONS =========================== */

/**
 * @brief             Digitally signs data of arbitrary size
 *                    using the SHA-256 hash-and-sign paradigm
 * @param signPrivKey The digital signature signer's private key
 * @param srcAddr     The initial address of the data to be signed
 * @param srcSize     The size of the data to be signed
 * @param sigAddr     The address where to write the resulting digital signature
 * @return            The resulting digital signature size
 * @note              This function assumes the "sigAddr" destination buffer to
 *                    be large enough to contain the resulting digital signature
 * @throws ERR_OSSL_EVP_MD_CTX_NEW  EVP_MD context creation failed
 * @throws ERR_OSSL_EVP_SIGN_INIT   EVP_MD signing initialization failed
 * @throws ERR_OSSL_EVP_SIGN_UPDATE EVP_MD signing update failed
 * @throws ERR_OSSL_EVP_SIGN_FINAL  EVP_MD signing final failed
 */
unsigned int digSigSign(EVP_PKEY* signPrivKey, unsigned char* srcAddr, size_t srcSize, unsigned char* sigAddr);


/**
 * @brief            Verifies a digital signature generated
 *                   via the SHA-256 hash-and-sign paradigm
 * @param signPubKey The digital signature signer's public key
 * @param srcAddr    The initial address of the data to be verified
 * @param srcSize    The size of the data to be verified
 * @param signAddr   The signature's initial address
 * @param signSize   The signature's size
 * @throws ERR_OSSL_EVP_MD_CTX_NEW    EVP_MD context creation failed
 * @throws ERR_OSSL_EVP_VERIFY_INIT   EVP_MD verification initialization failed
 * @throws ERR_OSSL_EVP_VERIFY_UPDATE EVP_MD verification update failed
 * @throws ERR_OSSL_EVP_VERIFY_FINAL  EVP_MD verification final failed
 * @throws ERR_OSSL_SIG_VERIFY_FAILED Signature Verification Failed
 */
void digSigVerify(EVP_PKEY* signPubKey, unsigned char* srcAddr, size_t srcSize, unsigned char* signAddr, size_t signSize);


#endif //SAFECLOUD_DIGSIG_H