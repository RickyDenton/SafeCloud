/* Station-to-Station-Modified (STSM) Key Exchange Protocol Client Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "CliSTSMMgr.h"



/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* ------------------------ Constructors and Destructor ------------------------ */


// TODO: Check arguments' value and throw an exception if wrong?
/**
 * @brief                   CliSTSMMgr object constructor
 * @param myRSALongPrivKey  The actor's long-term RSA private key
 * @param iv                The initialization vector of implicit IV_SIZE = 12 bytes (96 bit, AES_GCM)
 * @param skey              The symmetric key of implicit SKEY_SIZE = 16 bytes (128 bit, AES_GCM)
 * @param buf               The buffer used for sending and receiving STSM messages
 * @param bufSize           The STSM buffer size of implicit STSM_BUF_SIZE >= 4MB
 * @param name              The client's username
 * @param cliStore          The client's X.509 certificate store used for validating the server's signature
 */
CliSTSMMgr::CliSTSMMgr(int csk, char* name, unsigned char* buf, unsigned int bufSize, EVP_PKEY* myRSALongPrivKey, unsigned char* iv, unsigned char* skey, X509_STORE* cliStore)
                      : STSMMgr(csk,name,buf,bufSize,myRSALongPrivKey,iv,skey), _stsmCliState(INIT), _cliStore(cliStore)
 {}