/* Station-To-Station-Modified (STSM) key exchange protocol client class implementation */

/* ================================== INCLUDES ================================== */
#include "STSMCliData.h"
#include "OpenSSL/dh.h"

/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* ------------------------ Constructors and Destructor ------------------------ */

/**
 * @brief                  STSMCliData Data object constructor
 * @param myRSALongPrivKey A pointer to the client's long-term RSA private key
 * @param cliStore         A pointer to the client's X.509 store
 */
STSMCliData::STSMCliData(EVP_PKEY* myRSALongPrivKey, X509_STORE* cliStore) : STSMData(myRSALongPrivKey), _stsmCliState(INIT), _cliStore(cliStore)
 {}