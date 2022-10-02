#ifndef SAFECLOUD_RSA_H
#define SAFECLOUD_RSA_H

/* OpenSSL RSA Utility Functions Declarations */

#include <openssl/evp.h>
#include <openssl/pem.h>





// TODO: Check if it is necessary to have a class
/*class RSA
 {

 };*/


/**
 * @brief            Digitally signs data of arbitrary size using the SHA-256 hash-and-sign paradigm
 * @param RSAPrivKey The actor's private RSA key to be used for signing the data
 * @param srcAddr    The initial address of the data to be signed
 * @param srcSize    The size of the data to be signed
 * @param sigAddr    The address where to write the resulting digital signature
 * @return           The resulting digital signature size (256 bit)
 * @note             It is assumed the destination buffer to be large enough
 *                   to hold the resulting digital signature (256 bit)
 * @throws ERR_OSSL_EVP_MD_CTX_NEW  EVP_MD context creation failed
 * @throws ERR_OSSL_EVP_SIGN_INIT   EVP_MD signing initialization failed
 * @throws ERR_OSSL_EVP_SIGN_UPDATE EVP_MD signing update failed
 * @throws ERR_OSSL_EVP_SIGN_FINAL  EVP_MD signing final failed
 */
unsigned int rsaDigSign(EVP_PKEY* RSAPrivKey, unsigned char* srcAddr, size_t srcSize, unsigned char* sigAddr);



#endif //SAFECLOUD_RSA_H
