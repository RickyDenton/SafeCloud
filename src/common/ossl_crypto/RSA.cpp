/* OpenSSL RSA Utility Functions Definitions */

#include "RSA.h"
#include "errlog.h"

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
unsigned int rsaDigSign(EVP_PKEY* RSAPrivKey, unsigned char* srcAddr, size_t srcSize, unsigned char* sigAddr)
 {
  EVP_MD_CTX* digSigCTX;  // Digital Signature signing context
  unsigned int sigSize;   // The resulting digital signature size (in this case it is always 256 bits)

  // Create the digital signature signing context
  digSigCTX = EVP_MD_CTX_new();
  if(!digSigCTX)
   THROW_SCODE(ERR_OSSL_EVP_MD_CTX_NEW,OSSL_ERR_DESC);

  // Initialize the digital signature signing context so to use the SHA-256 hash-and-sign paradigm
  if(EVP_SignInit(digSigCTX, EVP_sha256()) != 1)
   THROW_SCODE(ERR_OSSL_EVP_SIGN_INIT,OSSL_ERR_DESC);

  // Pass the address and size of the data to be signed
  if(EVP_SignUpdate(digSigCTX, srcAddr, srcSize) != 1)
   THROW_SCODE(ERR_OSSL_EVP_SIGN_UPDATE,OSSL_ERR_DESC);

  // Sign the data with the RSA private key and write
  // the resulting signature into the destination buffer
  if(EVP_SignFinal(digSigCTX, sigAddr, &sigSize, RSAPrivKey) != 1)
   THROW_SCODE(ERR_OSSL_EVP_SIGN_FINAL,OSSL_ERR_DESC);

  // Free the digital signature signing context
  EVP_MD_CTX_free(digSigCTX);

  // Return the resulting digital signature size
  return sigSize;
 }


/**
 * @brief Verifies a digital signature generated via the SHA-256 hash-and-sign paradigm
 * @param signCert The signature signer's certificate
 * @param srcAddr  The initial address of the data to be verified
 * @param srcSize  The size of the data to be verified
 * @param signAddr The signature's initial address
 * @param signSize The signature's size
 * @throws ERR_OSSL_EVP_MD_CTX_NEW    EVP_MD context creation failed
 * @throws ERR_OSSL_EVP_VERIFY_INIT   EVP_MD verification initialization failed
 * @throws ERR_OSSL_EVP_VERIFY_UPDATE EVP_MD verification update failed
 * @throws ERR_OSSL_EVP_VERIFY_FINAL  EVP_MD verification final failed
 * @throws ERR_OSSL_SIG_VERIFY_FAILED Signature Verification Failed
 */
void rsaDigVerify(X509* signCert, unsigned char* srcAddr, size_t srcSize, unsigned char* signAddr, size_t signSize)
 {
  EVP_MD_CTX* digVerCTX;  // Digital Signature verification context

  // Create the digital signature verification context
  digVerCTX = EVP_MD_CTX_new();
  if(!digVerCTX)
   THROW_SCODE(ERR_OSSL_EVP_MD_CTX_NEW,OSSL_ERR_DESC);

  // Initialize the digital signature verification context so to use the SHA-256 hash-and-sign paradigm
  if(EVP_VerifyInit(digVerCTX, EVP_sha256()) != 1)
   THROW_SCODE(ERR_OSSL_EVP_VERIFY_INIT,OSSL_ERR_DESC);

  // Pass the address and size of the data to be verified
  if(EVP_VerifyUpdate(digVerCTX, srcAddr, srcSize) != 1)
   THROW_SCODE(ERR_OSSL_EVP_VERIFY_UPDATE,OSSL_ERR_DESC);

  // Actually verify the signature using the signer's public key
  int verFinalRet = EVP_VerifyFinal(digVerCTX, signAddr, signSize, X509_get_pubkey(signCert));

  // Internal EVP_VerifyFinal error
  if(verFinalRet == -1)
   THROW_SCODE(ERR_OSSL_EVP_VERIFY_FINAL,OSSL_ERR_DESC);

  // Signature verification failed
  if(verFinalRet == 0)
   THROW_SCODE(ERR_OSSL_SIG_VERIFY_FAILED,OSSL_ERR_DESC);

  // At this point the signature was successfully verified (verFinalRet ==1)

  // Free the digital signature verification context
  EVP_MD_CTX_free(digVerCTX);
 }