/* Station-To-Station-Modified (STSM) key exchange protocol server class implementation */


/* ================================== INCLUDES ================================== */
#include "STSMSrvData.h"
#include "OpenSSL/dh.h"

/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* ------------------------ Constructors and Destructor ------------------------ */

/**
 * @brief                  STSMSrvData object constructor
 * @param myRSALongPrivKey A pointer to the client's long-term RSA private key
 * @param srvCert          A pointer to the server's certificate
 */
STSMSrvData::STSMSrvData(EVP_PKEY* myRSALongPrivKey, X509* srvCert) : STSMData(myRSALongPrivKey), _stsmSrvState(WAITING_CLI_HELLO), _srvCert(srvCert)
 {}