/* OpenSSL Digital Signatures Utility Functions Definitions */

/* ================================== INCLUDES ================================== */
#include "DigSig.h"
#include "errlog.h"

/* ============================ FUNCTIONS DEFINITIONS ============================ */

/**
 * @brief             Digitally signs data of arbitrary size using the SHA-256 hash-and-sign paradigm
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
unsigned int digSigSign(EVP_PKEY* signPrivKey, unsigned char* srcAddr, size_t srcSize, unsigned char* sigAddr)
 {
  EVP_MD_CTX* digSigCTX;  // Digital Signature signing context
  unsigned int sigSize;   // The resulting digital signature size

  // Create the digital signature signing context
  digSigCTX = EVP_MD_CTX_new();
  if(!digSigCTX)
   THROW_SCODE_EXCP(ERR_OSSL_EVP_MD_CTX_NEW, OSSL_ERR_DESC);

  // Initialize the digital signature signing context so to use the SHA-256 hash-and-sign paradigm
  if(EVP_SignInit(digSigCTX, EVP_sha256()) != 1)
   THROW_SCODE_EXCP(ERR_OSSL_EVP_SIGN_INIT, OSSL_ERR_DESC);

  // Pass the address and size of the data to be signed
  if(EVP_SignUpdate(digSigCTX, srcAddr, srcSize) != 1)
   THROW_SCODE_EXCP(ERR_OSSL_EVP_SIGN_UPDATE, OSSL_ERR_DESC);

  // Sign the data with the provided private key and write
  // the resulting signature into the destination buffer
  if(EVP_SignFinal(digSigCTX, sigAddr, &sigSize, signPrivKey) != 1)
   THROW_SCODE_EXCP(ERR_OSSL_EVP_SIGN_FINAL, OSSL_ERR_DESC);

  // Free the digital signature signing context
  EVP_MD_CTX_free(digSigCTX);

  // Return the resulting digital signature size
  return sigSize;
 }


/**
 * @brief            Verifies a digital signature generated via the SHA-256 hash-and-sign paradigm
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
void digSigVerify(EVP_PKEY* signPubKey, unsigned char* srcAddr, size_t srcSize, unsigned char* signAddr, size_t signSize)
 {
  EVP_MD_CTX* digVerCTX;  // Digital Signature verification context

  // Create the digital signature verification context
  digVerCTX = EVP_MD_CTX_new();
  if(!digVerCTX)
   THROW_SCODE_EXCP(ERR_OSSL_EVP_MD_CTX_NEW, OSSL_ERR_DESC);

  // Initialize the digital signature verification context so to use the SHA-256 hash-and-sign paradigm
  if(EVP_VerifyInit(digVerCTX, EVP_sha256()) != 1)
   THROW_SCODE_EXCP(ERR_OSSL_EVP_VERIFY_INIT, OSSL_ERR_DESC);

  // Pass the address and size of the data to be verified
  if(EVP_VerifyUpdate(digVerCTX, srcAddr, srcSize) != 1)
   THROW_SCODE_EXCP(ERR_OSSL_EVP_VERIFY_UPDATE, OSSL_ERR_DESC);

  // Verify the digital signature
  int verFinalRet = EVP_VerifyFinal(digVerCTX, signAddr, signSize, signPubKey);

    // EVP_VerifyFinal internal error
    if(verFinalRet == -1)
     THROW_SCODE_EXCP(ERR_OSSL_EVP_VERIFY_FINAL, OSSL_ERR_DESC);

    // Signature verification failed
    if(verFinalRet == 0)
     THROW_SCODE_EXCP(ERR_OSSL_SIG_VERIFY_FAILED, OSSL_ERR_DESC);

  // At this point the digital signature is valid (verFinalRet ==1)

  // Free the digital signature verification context
  EVP_MD_CTX_free(digVerCTX);
 }