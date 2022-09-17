/* Implementation of the base class used by client and server in the Station-To-Station-Modified (STSM) key exchange protocol */

/* ================================== INCLUDES ================================== */
#include "STSMData.h"
#include "defaults.h"
#include "OpenSSL/dh.h"
#include "utils.h"

/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* ------------------------ Constructors and Destructor ------------------------ */

/**
 * @brief STSMData object constructor
 * @param myRSALongPrivKey A pointer to the user's long-term RSA private key
 */
STSMData::STSMData(EVP_PKEY* myRSALongPrivKey) : _myRSALongPrivKey(myRSALongPrivKey), _myDHEKey(dhe_2048_keygen()), _otherDHEPubKey(nullptr), _iv(nullptr), _ivSize(IV_SIZE)
 {}


/**
 * @brief STSMData object destructor, which safely deletes its sensitive attributes
 * @note  If the STSM handshake was successful no sensitive data is deleted by this destructor, as:
 *        - The RSA long-term private key may still be of use by the actor
 *        - The actor's private key is deleted as soon as no longer required in the protocol
 *        - The Session key and IV were returned to the caller
 *          (also see the STSMServerData and the STSMClientData classes for more information)
 */
STSMData::~STSMData()
 {
  // Deallocate both actors' ephemeral keys
  EVP_PKEY_free(_myDHEKey);
  EVP_PKEY_free(_otherDHEPubKey);

  // Safely erase the IV value
  safeFree(reinterpret_cast<void*&>(_iv), _ivSize);
 }