/* Station-to-Station-Modified (STSM) Key Exchange Protocol Base Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "STSMMgr.h"
#include "crypto_algs/dh.h"
#include <string.h>

/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* ------------------------ Constructors and Destructor ------------------------ */

// TODO: Check arguments' value and throw an exception if wrong?
/**
 * @brief                   STSMMgr object constructor
 * @param csk               The connection socket on which to perform the STSM protocol
 * @param name              The client's username
 * @param buf               The buffer used for sending and receiving STSM messages
 * @param bufSize           The STSM buffer size of implicit STSM_BUF_SIZE >= 4MB
 * @param myRSALongPrivKey  The actor's long-term RSA private key
 * @param iv                The initialization vector of implicit IV_SIZE = 12 bytes (96 bit, AES_GCM)
 * @param skey              The symmetric key of implicit SKEY_SIZE = 16 bytes (128 bit, AES_GCM)
 */
STSMMgr::STSMMgr(int csk, char* name, unsigned char* buf, unsigned int bufSize, EVP_PKEY* myRSALongPrivKey, unsigned char* iv, unsigned char* skey)
                 : _csk(csk), _name(name), _buf(buf), _bufInd(0), _bufSize(bufSize), _myRSALongPrivKey(myRSALongPrivKey), _myDHEKey(dhe_2048_keygen()), _otherDHEPubKey(nullptr), _iv(iv), _skey(skey)
 {}


/**
 * @brief STSMMgr object destructor, which safely deletes its sensitive attributes
 * @note  If the STSM handshake was successful only STSM buffer is safely deleted, as:
 *        - The actor's ephemeral private key is deleted as soon as no longer required by the protocol
 *        - The "_myRSALongPrivKey", "_iv", "_skey" and "_name" values are of further use for the caller
 */
STSMMgr::~STSMMgr()
 {
  // Deallocate both actors' ephemeral keys
  EVP_PKEY_free(_myDHEKey);
  EVP_PKEY_free(_otherDHEPubKey);

  // Safely erase the STSM buffer
  #pragma optimize("", off)
   memset(_buf, 0, _bufSize);
  #pragma optimize("", on)
 }