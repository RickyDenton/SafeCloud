/* Station-to-Station-Modified (STSM) Key Exchange Protocol Base Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "STSMMgr.h"
#include "errlog.h"
#include <string.h>

/* ============================== PROTECTED METHODS ============================== */
#include <functional>





// TODO
/*void STSMMgr::sendSTSMErrorMsg(STSMMsg& stsmErrMsg, STSMMsgType errCode, const void(*send)(void))
 {
  stsmErrMsg.header.len = 24;
  stsmErrMsg.header.type = errCode;
  send();
 }*/

void STSMMgr::sendSTSMErrorMsg(STSMMsg& stsmErrMsg, STSMMsgType errCode, ConnMgr& connMgr)
 {
  stsmErrMsg.header.len = 24;
  stsmErrMsg.header.type = errCode;
  connMgr.sendData();
 }





// TODO
void STSMMgr::checkSTSMError(STSMMsgType msgType)
 {
  switch(msgType)
   {
    // Valid protocol message
    case CLIENT_HELLO:
    case SRV_AUTH:
    case CLI_AUTH:
    case SRV_OK:
     return;

    // Parameters error
    case MALFORMED_MSG:
     THROW_SCODE(ERR_STSM_MALFORMED_MSG);

    case CHALLENGE_FAILED:
     THROW_SCODE(ERR_STSM_CHALLENGE_FAILED);

    case CERT_REJECTED:
     THROW_SCODE(ERR_STSM_CERT_REJECTED);

    case LOGIN_FAILED:
     THROW_SCODE(ERR_STSM_LOGIN_FAILED);

    default:
     THROW_SCODE(ERR_STSM_UNKNOWN_TYPE,"(" + std::to_string(msgType) + ")");
   }
 }



/**
 * @brief  Generates an ephemeral DH key pair on 2048 bit using the set of standard DH parameters
 * @return The address of the EVP_PKEY structure holding the newly generated ephemeral DH key pair
 */
EVP_PKEY* STSMMgr::DHE_2048_Keygen()
 {
  EVP_PKEY*     DHParams;          // Used to store default DH parameters
  EVP_PKEY_CTX* DHGenCtx;          // DH key generation context
  EVP_PKEY*     DHEKey = nullptr;  // The resulting actor's ephemeral DH key pair

  /* ----------------- DH 2048 Default Parameters Initialization ----------------- */

  // Allocate an EVP_PKEY structure for storing the default DH parameters
  DHParams = EVP_PKEY_new();
  if(DHParams == nullptr)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_NEW,OSSL_ERR_DESC);

  // Initialize the previous EVP_PKEY structure with the default DH parameters
  if(EVP_PKEY_assign(DHParams, EVP_PKEY_DHX, DH_get_2048_256()) != 1)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_ASSIGN,OSSL_ERR_DESC);

  /* ------------------- Ephemeral DH 2048 Key Pair Generation ------------------- */

  // Create a key generation context using the previously initialized DH default parameters
  DHGenCtx = EVP_PKEY_CTX_new(DHParams, nullptr);
  if(!DHGenCtx)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_CTX_NEW,OSSL_ERR_DESC);

  // Initialize the key generation context
  if(EVP_PKEY_keygen_init(DHGenCtx) != 1)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_KEYGEN_INIT,OSSL_ERR_DESC);

  // Generate an ephemeral DH 2048 key pair
  if(EVP_PKEY_keygen(DHGenCtx, &DHEKey) != 1)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_KEYGEN,OSSL_ERR_DESC);

  // Free the EVP_PKEY structure containing the default
  // DH parameters and the key generation context
  // TODO: Check, it should be right
  EVP_PKEY_free(DHParams);
  EVP_PKEY_CTX_free(DHGenCtx);

  // Return the actor's ephemeral DH 2048 key pair
  return DHEKey;
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief                   STSMMgr object constructor
 * @param myRSALongPrivKey  The actor's long-term RSA private key
 * @note The constructor initializes the actor's ephemeral DH 2048 key pair
 */
STSMMgr::STSMMgr(EVP_PKEY* myRSALongPrivKey) : _myRSALongPrivKey(myRSALongPrivKey), _myDHEKey(DHE_2048_Keygen()), _otherDHEPubKey(nullptr)
 {}


/**
 * @brief STSMMgr object destructor, which safely deletes its sensitive attributes
 */
STSMMgr::~STSMMgr()
 {
  // Deallocate both actors' ephemeral keys
  EVP_PKEY_free(_myDHEKey);
  EVP_PKEY_free(_otherDHEPubKey);

  // NOTE: The actor's long-term RSA private key must NOT be
  //       deleted, as it may be reused across multiple connections
 }