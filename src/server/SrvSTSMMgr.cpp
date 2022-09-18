/* Station-to-Station-Modified (STSM) Key Exchange Protocol Server Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvSTSMMgr.h"

/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* ------------------------ Constructors and Destructor ------------------------ */


// TODO: Check arguments' value and throw an exception if wrong?
/**
 * @brief                   SrvSTSMMgr object constructor
 * @param myRSALongPrivKey  The actor's long-term RSA private key
 * @param iv                The initialization vector of implicit IV_SIZE = 12 bytes (96 bit, AES_GCM)
 * @param skey              The symmetric key of implicit SKEY_SIZE = 16 bytes (128 bit, AES_GCM)
 * @param buf               The buffer used for sending and receiving STSM messages
 * @param bufSize           The STSM buffer size of implicit STSM_BUF_SIZE >= 4MB
 * @param name              Where to write the client's username on a successful handshake
 * @param cliStore          The server's X.509 certificate
 */
SrvSTSMMgr::SrvSTSMMgr(int csk, char* name, unsigned char* buf, unsigned int bufSize, EVP_PKEY* myRSALongPrivKey, unsigned char* iv, unsigned char* skey, X509* srvCert)
  : STSMMgr(csk,name,buf,bufSize,myRSALongPrivKey,iv,skey), _stsmSrvState(WAITING_CLI_HELLO), _srvCert(srvCert)
 {}