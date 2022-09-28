/* Station-to-Station-Modified (STSM) Key Exchange Protocol Server Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvSTSMMgr.h"
#include "ConnMgr/STSMMgr/STSMMsg.h"
#include "../SrvConnMgr.h"
#include "errlog.h"

/* =============================== PRIVATE METHODS =============================== */

// TODO
void SrvSTSMMgr::recv_client_hello()
 {
  // TODO REMOVE
  std::cout << "In RECV_CLIENT_HELLO" << std::endl;

  // Interpret the connection manager's primary buffer as a 'CLIENT_HELLO' STSM message
  STSM_Client_Hello* cliHello = reinterpret_cast<STSM_Client_Hello*>(_srvConnMgr._priBuf);

  // Set the expected message length
  uint16_t expLen = sizeof(STSM_Client_Hello);

  // Ensure the type and length of the message to be as expected
  if(cliHello->header.type != CLIENT_HELLO)
   {
    // TODO REMOVE
    std::cout << "NOT A CLIENT HELLO MESSAGE" << std::endl;
    sendSTSMErrorMsg((STSMMsg&)cliHello, MALFORMED_MSG, (ConnMgr&)_srvConnMgr);
   }
  if(cliHello->header.len != expLen)
   {
    // TODO REMOVE
    std::cout << "NOT A CLIENT HELLO MESSAGE" << std::endl;
    sendSTSMErrorMsg((STSMMsg&)cliHello, MALFORMED_MSG, (ConnMgr&)_srvConnMgr);
   }

   // Set the IV
  _srvConnMgr._iv = new IVMgr(cliHello->iv);


  // TODO Debug
  // Print the message's contents
  std::cout << "cliHello.header.len = " << cliHello->header.len << std::endl;
  std::cout << "cliHello.header.type = " << cliHello->header.type << std::endl;
  std::cout << "cliHello.iv.iv_high = " << cliHello->iv.iv_high << std::endl;
  std::cout << "cliHello.iv.iv_low = " << cliHello->iv.iv_low << std::endl;


  /* Client public key setup */

  // Write the client's ephemeral DH public key into a BIO
  BIO* cliPubDHBio = BIO_new_mem_buf(cliHello->cliPubKey, -1);

  // Initialize the client's ephemeral DH public key structure
  _otherDHEPubKey = EVP_PKEY_new();

  _otherDHEPubKey = PEM_read_bio_PUBKEY(cliPubDHBio, NULL,NULL, NULL);



  // TODO: Remove (but save because useful)
  // Print the client's public key
  BIO* bp = BIO_new_fp(stdout, BIO_NOCLOSE);
  if(!EVP_PKEY_print_public(bp, _otherDHEPubKey, 1, NULL))
   {
    std::cout << "error 5" << std::endl;
   }
  std::cout << bp <<std::endl;
  BIO_free(bp);



  // Free the BIO
  BIO_free(cliPubDHBio);
 }

void SrvSTSMMgr::recv_client_auth()
 {}




// TODO
void SrvSTSMMgr::checkSrvSTSMError()
 {
  try
   {
    checkSTSMError(((STSMMsg&&)(_srvConnMgr._priBuf)).header.type);
   }
  catch(sCodeException& excp)
   {
    // Substitute with more specific
    switch(excp.scode)
     {
      case ERR_STSM_MALFORMED_MSG:
       excp.scode = ERR_STSM_SRV_MALFORMED_MSG;
       break;

      case ERR_STSM_CHALLENGE_FAILED:
       excp.scode = ERR_STSM_SRV_CHALLENGE_FAILED;
       break;

      case ERR_STSM_CERT_REJECTED:
       excp.scode = ERR_STSM_SRV_CERT_REJECTED;
       break;

      case ERR_STSM_LOGIN_FAILED:
       excp.scode = ERR_STSM_SRV_LOGIN_FAILED;
       break;

      case ERR_STSM_UNKNOWN_TYPE:
       excp.scode = ERR_STSM_SRV_UNKNOWN_TYPE;
       break;

      default:
       break;
     }
    throw;
   }
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief                  SrvSTSMMgr object constructor
 * @param myRSALongPrivKey The server's long-term RSA key pair
 * @param srvConnMgr       The parent SrvConnMgr instance managing this object
 * @param srvCert          The server's X.509 certificate
 */
SrvSTSMMgr::SrvSTSMMgr(EVP_PKEY* myRSALongPrivKey, SrvConnMgr& srvConnMgr, X509* srvCert)
                       : STSMMgr(myRSALongPrivKey), _stsmSrvState(WAITING_CLI_HELLO), _srvConnMgr(srvConnMgr), _srvCert(srvCert)
 {}

/* ============================ OTHER PUBLIC METHODS ============================ */


// Returns true when switching to session mode
bool SrvSTSMMgr::STSMMsgHandler()
 {
  std::cout << "In STSMMsgHandler" << std::endl;

  // Ensure that the data received consists of a valid STSM message
  checkSrvSTSMError();

  // Call the appropriate STSM message handler depending on the current server STSM state
  if(_stsmSrvState == WAITING_CLI_HELLO)
   {
    recv_client_hello();
    return false;          // Connection must be maintained
   }
  else
   {
    recv_client_auth();
    return true;          // OK, STSM over
   }
 }

