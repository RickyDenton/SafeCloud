/* Station-to-Station-Modified (STSM) Key Exchange Protocol Server Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvSTSMMgr.h"
#include "ConnMgr/STSMMgr/STSMMsg.h"
#include "../SrvConnMgr.h"
#include "errlog.h"

/* =============================== PRIVATE METHODS =============================== */

/* ------------------------- Error Checking and Handling ------------------------- */

/**
 * @brief  Sends a STSM error message to the server and throws the
 *         associated exception on the client, aborting the connection
 * @param  errMsgType The STSM error message type to be sent to the server
 * @param  errDesc    An optional description of the error that has occurred
 * @throws ERR_STSM_SRV_CLI_INVALID_PUBKEY   The client has provided an invalid ephemeral public key
 * @throws ERR_STSM_SRV_CLI_CHALLENGE_FAILED The client has failed the STSM authentication challenge
 * @throws ERR_STSM_SRV_CLIENT_LOGIN_FAILED  Unrecognized username on the server
 * @throws ERR_STSM_UNEXPECTED_MESSAGE       Received an out-of-order STSM message
 * @throws ERR_STSM_MALFORMED_MESSAGE        Received a malformed STSM message
 * @throws ERR_STSM_UNKNOWN_STSMMSG_TYPE     Received a STSM message of unknown type
 * @throws ERR_STSM_UNKNOWN_STSMMSG_ERROR    Attempting to send an STSM error message of unknown type
 */
void SrvSTSMMgr::sendSrvSTSMErrMsg(STSMMsgType errMsgType,const char* errDesc = "")
 {
  // Interpret the associated connection manager's primary connection buffer as a STSMsg
  STSMMsg* errMsg = reinterpret_cast<STSMMsg*>(_srvConnMgr._priBuf);

  // Set the error message header's length and type
  errMsg->header.len = sizeof(STSMMsg);
  errMsg->header.type = errMsgType;

  // Send the STSM error message
  _srvConnMgr.sendMsg();

  // Throw the exception associated with the error message's type
  switch(errMsgType)
   {
    /* ------------------------ Error STSM Messages  ------------------------ */

    // The client has provided an invalid ephemeral public key
    case ERR_INVALID_PUBKEY:
     THROW_SCODE(ERR_STSM_SRV_CLI_INVALID_PUBKEY,errDesc);

    // The client has failed the STSM authentication challenge
    case ERR_CLI_CHALLENGE_FAILED:
     THROW_SCODE(ERR_STSM_SRV_CLI_CHALLENGE_FAILED,errDesc);

    // Unrecognized username on the server
    case ERR_CLIENT_LOGIN_FAILED:
     THROW_SCODE(ERR_STSM_SRV_CLIENT_LOGIN_FAILED,errDesc);

    // An out-of-order STSM message has been received
    case ERR_UNEXPECTED_MESSAGE:
     THROW_SCODE(ERR_STSM_UNEXPECTED_MESSAGE,errDesc);

    // A malformed STSM message has been received
    case ERR_MALFORMED_MESSAGE:
     THROW_SCODE(ERR_STSM_MALFORMED_MESSAGE,errDesc);

    // A STSM message of unknown type has been received
    case ERR_UNKNOWN_STSMMSG_TYPE:
     THROW_SCODE(ERR_STSM_UNKNOWN_STSMMSG_TYPE,errDesc);

    // Unknown error type
    default:
     THROW_SCODE(ERR_STSM_UNKNOWN_STSMMSG_ERROR,"(" + std::to_string(errMsgType) + ")");
   }
 }




/**
 * @brief  Verifies a received message to consists of the STSM handshake message
 *         appropriate for the current server's STSM state, throwing an error otherwise
 * @throws ERR_STSM_UNEXPECTED_MESSAGE       An out-of-order STSM message has been received
 * @throws ERR_STSM_MALFORMED_MESSAGE        STSM message type and size mismatch
 * @throws ERR_STSM_SRV_SRV_INVALID_PUBKEY   The client reported that the server's ephemeral public key is invalid
 * @throws ERR_STSM_SRV_SRV_CHALLENGE_FAILED The client reported the server failing the STSM authentication challenge
 * @throws ERR_STSM_SRV_SRV_CERT_REJECTED    The client rejected the server's X.509 certificate
 * @throws ERR_STSM_CLI_UNEXPECTED_MESSAGE   The client reported to have received an out-of-order STSM message
 * @throws ERR_STSM_CLI_MALFORMED_MESSAGE    The client reported to have received a malformed STSM message
 * @throws ERR_STSM_CLI_UNKNOWN_STSMMSG_TYPE The client reported to have received an STSM message of unknown type
 */
void SrvSTSMMgr::checkSrvSTSMMsg()
 {
  // Interpret the associated connection manager's primary buffer as a STSM message
  STSMMsg* stsmMsg = reinterpret_cast<STSMMsg*>(_srvConnMgr._priBuf);

  // Depending on the received STSM message's type
  switch(stsmMsg->header.type)
   {
    /* ------------- Server-valid received STSM message types  ------------- */

    // 'CLIENT_HELLO' message
    case CLIENT_HELLO:

     // This message can be received only in the 'WAITING_CLI_HELLO' STSM server state
     if(_stsmSrvState != WAITING_CLI_HELLO)
      sendSrvSTSMErrMsg(ERR_UNEXPECTED_MESSAGE,"'CLIENT_HELLO' in the 'WAITING_CLI_AUTH' state");

     // Ensure the message length to be equal to the size of a 'CLIENT_HELLO' message
     if(stsmMsg->header.len != sizeof(STSM_Client_Hello))
      sendSrvSTSMErrMsg(ERR_MALFORMED_MESSAGE,"'CLIENT_HELLO' message of unexpected length");

     // A valid 'CLIENT_HELLO' message has been received
     return;

    // 'CLI_AUTH' message
    case CLI_AUTH:

     // This message can be received only in the 'WAITING_CLI_AUTH' STSM client state
     if(_stsmSrvState != WAITING_CLI_AUTH)
      sendSrvSTSMErrMsg(ERR_UNEXPECTED_MESSAGE,"'CLI_AUTH' message in the 'WAITING_CLI_HELLO' state");

     // Ensure the message length to be equal to the size of a 'CLI_AUTH' message
     // TODO check if applicable
     if(stsmMsg->header.len != sizeof(CLI_AUTH))
      sendSrvSTSMErrMsg(ERR_MALFORMED_MESSAGE,"'CLI_AUTH' message of unexpected length");

     // A valid 'CLI_AUTH' message has been received
     return;

    /* ------------------------ Error STSM Messages  ------------------------ */

    // The client reported that the server's ephemeral public key is invalid
    case ERR_INVALID_PUBKEY:
     THROW_SCODE(ERR_STSM_SRV_SRV_INVALID_PUBKEY);

    // The client reported the server failing the STSM authentication challenge
    case ERR_SRV_CHALLENGE_FAILED:
     THROW_SCODE(ERR_STSM_SRV_SRV_CHALLENGE_FAILED);

    // The client rejected the server's X.509 certificate
    case ERR_SRV_CERT_REJECTED:
     THROW_SCODE(ERR_STSM_SRV_SRV_CERT_REJECTED);

    // The client reported to have received an out-of-order STSM message
    case ERR_UNEXPECTED_MESSAGE:
     THROW_SCODE(ERR_STSM_SRV_UNEXPECTED_MESSAGE);

    // The client reported to have received a malformed STSM message
    case ERR_MALFORMED_MESSAGE:
     THROW_SCODE(ERR_STSM_SRV_MALFORMED_MESSAGE);

    // The client reported to have received an STSM message of unknown type
    case ERR_UNKNOWN_STSMMSG_TYPE:
     THROW_SCODE(ERR_STSM_SRV_UNKNOWN_STSMMSG_TYPE);

    // Unknown Message
    default:
     sendSrvSTSMErrMsg(ERR_UNKNOWN_STSMMSG_TYPE);
   }
 }


/**
 * @brief  Parses the client's 'CLIENT_HELLO' message, setting their
 *         ephemeral DH public key and the IV to be used in the communication
 * @throws ERR_OSSL_BIO_NEW_FAILED O       OpenSSL BIO initialization failed
 * @throws ERR_OSSL_EVP_PKEY_NEW           EVP_PKEY struct creation failed
 * @throws ERR_STSM_SRV_CLI_INVALID_PUBKEY The client provided an invalid ephemeral DH public key
 */
void SrvSTSMMgr::recv_client_hello()
 {
  // Interpret the connection manager's primary buffer as a 'CLIENT_HELLO' STSM message
  STSM_Client_Hello* cliHelloMsg = reinterpret_cast<STSM_Client_Hello*>(_srvConnMgr._priBuf);

  /* ------------------ Client's ephemeral DH public key ------------------ */

  // Initialize a memory BIO to the client's ephemeral DH public key
  BIO* cliPubDHBio = BIO_new_mem_buf(cliHelloMsg->cliEDHPubKey, -1);
  if(cliPubDHBio == NULL)
   THROW_SCODE(ERR_OSSL_BIO_NEW_FAILED,OSSL_ERR_DESC);

  // Initialize the client's ephemeral DH public key structure
  _otherDHEPubKey = EVP_PKEY_new();
  if(_otherDHEPubKey == nullptr)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_NEW,OSSL_ERR_DESC);

  // Write the client's ephemeral DH public key from the memory BIO into the EVP_PKEY structure
  _otherDHEPubKey = PEM_read_bio_PUBKEY(cliPubDHBio, NULL,NULL, NULL);

  // Free the memory BIO
  BIO_free(cliPubDHBio);

  // Ensure the client's ephemeral DH public key to be valid
  if(_otherDHEPubKey == nullptr)
   sendSrvSTSMErrMsg(ERR_INVALID_PUBKEY,OSSL_ERR_DESC);

  /* ----------------------------- Random IV ----------------------------- */

  // Initialize the associated connection manager's IV to the client-provided value
  _srvConnMgr._iv = new IV(cliHelloMsg->iv);

  /* ------------------------------ Cleanup ------------------------------ */

  // Free the message in the connection manager's primary buffer
  _srvConnMgr.clearPriBuf();

  LOG_DEBUG("[" + *_srvConnMgr._name + "] STSM 1/4: Received 'CLIENT_HELLO' message")

  /*
  // LOG: Message contents and set IV
  std::cout << "cliHelloMsg->header.len = " << cliHelloMsg->header.len << std::endl;
  std::cout << "cliHelloMsg->header.type = " << cliHelloMsg->header.type << std::endl;
  std::cout << "cliHelloMsg->iv.iv_AES_CBC = " << cliHelloMsg->iv.iv_AES_CBC << std::endl;
  std::cout << "cliHelloMsg->iv.iv_AES_GCM = " << cliHelloMsg->iv.iv_AES_GCM << std::endl;
  std::cout << "cliHelloMsg->iv.iv_var = " << cliHelloMsg->iv.iv_var << std::endl;
  std::cout << "_srvConnMgr._iv->iv_AES_CBC = " << _srvConnMgr._iv->iv_AES_CBC << std::endl;
  std::cout << "_srvConnMgr._iv->iv_AES_CBC = " << _srvConnMgr._iv->iv_AES_GCM << std::endl;
  std::cout << "_srvConnMgr._iv->iv_var = " << _srvConnMgr._iv->iv_var << std::endl;
  */

  /*
  // LOG: Client's public key
  logOtherEDHPubKey();
  */
 }



void SrvSTSMMgr::recv_client_auth()
 {}


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

/**
 * @brief  Server STSM Message handler, processing a client STSM message
 *         stored in the associated connection manager's primary buffer
 * @return A boolean indicating  whether the key establishment phase has terminated and
 *         so the connection can switch to the session phase ('true') or not ('false')
 * @throws TODO
 */
bool SrvSTSMMgr::STSMMsgHandler()
 {
  // Verifies the received message to consist of the STSM handshake message
  // appropriate for the current server's STSM state, throwing an error otherwise
  checkSrvSTSMMsg();

  // Depending on the server's current state (and implicitly from
  // the previous check, the STSM message type that was received)
  if(_stsmSrvState == WAITING_CLI_HELLO)
   {
    // Parse the client's 'CLIENT_HELLO' message
    recv_client_hello();

    // Derive an AES_128 symmetric key from the server's
    // private and the client's public ephemeral DH keys
    deriveAES128Skey(_srvConnMgr._skey);

    // TODO: Send the 'SRV_AUTH' message


    // Inform the connection manager that the connection
    // is still in the key establishment phase
    return false;
   }
  else  // _stsmSrvState == WAITING_CLI_AUTH
   {
    recv_client_auth();

    // Inform the connection manager that key establishment has completed
    // successfully and so that the connection can now switch to the session phase
    return true;
   }
 }

