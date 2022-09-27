/* Station-to-Station-Modified (STSM) Key Exchange Protocol Client Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSTSMMgr.h"



/* =============================== PRIVATE METHODS =============================== */



/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief                  CliSTSMMgr object constructor
 * @param myRSALongPrivKey The client's long-term RSA key pair
 * @param cliConnMgr       The parent CliConnMgr instance managing this object
 * @param cliStore         The client's X.509 certificates store
 */
CliSTSMMgr::CliSTSMMgr(EVP_PKEY* myRSALongPrivKey, CliConnMgr& cliConnMgr, X509_STORE* cliStore)
                      : STSMMgr(myRSALongPrivKey), _stsmCliState(INIT), _cliConnMgr(cliConnMgr), _cliStore(cliStore)
 {}


/* ============================ OTHER PUBLIC METHODS ============================ */

void CliSTSMMgr::startSTSM()
 {
  std::cout << "CliSTSMMgr: STARTING STSM" << std::endl;
 }
