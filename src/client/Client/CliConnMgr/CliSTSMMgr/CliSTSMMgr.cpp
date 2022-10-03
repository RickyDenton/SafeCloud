/* Station-to-Station-Modified (STSM) Key Exchange Protocol Client Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSTSMMgr.h"
#include "../CliConnMgr.h"
#include "scode.h"
#include "errlog.h"
#include "ConnMgr/STSMMgr/STSMMsg.h"

/* =============================== PRIVATE METHODS =============================== */


/**
 * @brief  Sends a STSM error message to the server and throws the
 *         associated exception on the client, aborting the connection
 * @param  errMsgType The STSM error message type to be sent to the server
 * @param  errDesc    An optional description of the error that has occurred
 * @throws ERR_STSM_CLI_SRV_INVALID_PUBKEY   The server has provided an invalid ephemeral public key
 * @throws ERR_STSM_CLI_SRV_CHALLENGE_FAILED Server STSM authentication challenge failed
 * @throws ERR_STSM_CLI_SRV_CERT_REJECTED    The received server's certificate is invalid
 * @throws ERR_STSM_UNEXPECTED_MESSAGE       Received an out-of-order STSM message
 * @throws ERR_STSM_MALFORMED_MESSAGE        Received a malformed STSM message
 * @throws ERR_STSM_UNKNOWN_STSMMSG_TYPE     Received a STSM message of unknown type
 * @throws ERR_STSM_UNKNOWN_STSMMSG_ERROR    Attempting to send an STSM error message of unknown type
 */
void CliSTSMMgr::sendCliSTSMErrMsg(STSMMsgType errMsgType,const char* errDesc = "")
 {
  // Interpret the associated connection manager's primary connection buffer as a STSMsg
  STSMMsg* errMsg = reinterpret_cast<STSMMsg*>(_cliConnMgr._priBuf);

  // Set the error message header's length and type
  errMsg->header.len = sizeof(STSMMsg);
  errMsg->header.type = errMsgType;

  // Send the STSM error message
  _cliConnMgr.sendMsg();

  // Throw the exception associated with the error message's type
  switch(errMsgType)
   {
    /* ------------------------ Error STSM Messages  ------------------------ */

    // The server has provided an invalid ephemeral public key
    case ERR_INVALID_PUBKEY:
     THROW_SCODE(ERR_STSM_CLI_SRV_INVALID_PUBKEY,errDesc);

    // The server has failed the STSM authentication challenge
    case ERR_SRV_CHALLENGE_FAILED:
     THROW_SCODE(ERR_STSM_CLI_SRV_CHALLENGE_FAILED,errDesc);

    // The server provided an invalid X.509 certificate
    case ERR_SRV_CERT_REJECTED:
     THROW_SCODE(ERR_STSM_CLI_SRV_CERT_REJECTED,errDesc);

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

//

/**
 * @brief  1) Blocks the execution until a STSM message has been received
 *            in the associated connection manager's primary buffer\n
 *         2) Verifies the received message to consist of the STSM handshake message
 *            appropriate for the current client's STSM state, throwing an error otherwise
 * @throws ERR_STSM_UNEXPECTED_MESSAGE       An out-of-order STSM message has been received
 * @throws ERR_STSM_MALFORMED_MESSAGE        STSM message type and size mismatch
 * @throws ERR_STSM_CLI_CLI_INVALID_PUBKEY   The server reported that the client's ephemeral public key is invalid
 * @throws ERR_STSM_CLI_CLI_CHALLENGE_FAILED The server reported the client failing the STSM authentication challenge
 * @throws ERR_STSM_CLI_CLIENT_LOGIN_FAILED  The server did not recognize the client's username
 * @throws ERR_STSM_CLI_UNEXPECTED_MESSAGE   The server reported to have received an out-of-order STSM message
 * @throws ERR_STSM_CLI_MALFORMED_MESSAGE    The server reported to have received a malformed STSM message
 * @throws ERR_STSM_CLI_UNKNOWN_STSMMSG_TYPE The server reported to have received an STSM message of unknown type
 */
void CliSTSMMgr::recvCheckCliSTSMMsg()
 {
  // Receive a full message via the associated connection manager
  _cliConnMgr.recvMsg();

  // Interpret the associated connection manager's primary buffer as a STSM message
  STSMMsg* stsmMsg = reinterpret_cast<STSMMsg*>(_cliConnMgr._priBuf);

  // Depending on the received STSM message's type
  switch(stsmMsg->header.type)
   {
    /* ------------- Client-valid received STSM message types  ------------- */

    // 'SRV_AUTH' message
    case SRV_AUTH:

     // This message can be received only in the 'WAITING_SRV_AUTH' STSM client state
     if(_stsmCliState != WAITING_SRV_AUTH)
      sendCliSTSMErrMsg(ERR_UNEXPECTED_MESSAGE,"'SRV_AUTH'");

     // 'SRV_AUTH' messages are of variable size (the server's
     // certificate), no size validation can be performed

     // A valid 'SRV_AUTH' message has been received
     return;

    // 'SRV_OK' message
    case SRV_OK:

     // This message can be received only in the 'WAITING_SRV_OK' STSM client state
     if(_stsmCliState != WAITING_SRV_OK)
      sendCliSTSMErrMsg(ERR_UNEXPECTED_MESSAGE,"'SRV_OK'");

     // Ensure the message length to be equal to the size of a 'SRV_OK' message
     // TODO check if applicable
     if(stsmMsg->header.len != sizeof(SRV_OK))
      sendCliSTSMErrMsg(ERR_MALFORMED_MESSAGE,"'SRV_OK' message of unexpected length");

     // A valid 'SRV_OK' message has been received
     return;

    /* ------------------------ Error STSM Messages  ------------------------ */

    // The server reported that the client's ephemeral public key is invalid
    case ERR_INVALID_PUBKEY:
     THROW_SCODE(ERR_STSM_CLI_CLI_INVALID_PUBKEY);

    // The server reported the client failing the STSM authentication challenge
    case ERR_CLI_CHALLENGE_FAILED:
     THROW_SCODE(ERR_STSM_CLI_CLI_CHALLENGE_FAILED);

    // The server did not recognize the username in the STSM protocol
    case ERR_CLIENT_LOGIN_FAILED:
     THROW_SCODE(ERR_STSM_CLI_CLIENT_LOGIN_FAILED);

    // The server reported to have received an out-of-order STSM message
    case ERR_UNEXPECTED_MESSAGE:
     THROW_SCODE(ERR_STSM_CLI_UNEXPECTED_MESSAGE);

    // The server reported to have received a malformed STSM message
    case ERR_MALFORMED_MESSAGE:
     THROW_SCODE(ERR_STSM_CLI_MALFORMED_MESSAGE);

    // The server reported to have received an STSM message of unknown type
    case ERR_UNKNOWN_STSMMSG_TYPE:
     THROW_SCODE(ERR_STSM_CLI_UNKNOWN_STSMMSG_TYPE);

    // Unknown Message
    default:
     sendCliSTSMErrMsg(ERR_UNKNOWN_STSMMSG_TYPE);
   }
 }







void CliSTSMMgr::recv_srv_auth()
 {
  // Interpret the associated connection manager's primary connection buffer as a 'SRV_AUTH' message
  STSM_SRV_AUTH* stsmSrvAuth = reinterpret_cast<STSM_SRV_AUTH*>(_cliConnMgr._priBuf);

  /* ------------------ Server's ephemeral DH public key ------------------ */

  // Initialize a memory BIO to the server's ephemeral DH public key
  BIO* srvPubDHBIO = BIO_new_mem_buf(stsmSrvAuth->srvEDHPubKey, -1);
  if(srvPubDHBIO == NULL)
   THROW_SCODE(ERR_OSSL_BIO_NEW_FAILED,OSSL_ERR_DESC);

  // Initialize the server's ephemeral DH public key structure
  _otherDHEPubKey = EVP_PKEY_new();
  if(_otherDHEPubKey == nullptr)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_NEW,OSSL_ERR_DESC);

  // Write the server's ephemeral DH public key from the memory BIO into the EVP_PKEY structure
  _otherDHEPubKey = PEM_read_bio_PUBKEY(srvPubDHBIO, NULL, NULL, NULL);

  // Free the memory BIO
  BIO_free(srvPubDHBIO);

  // Ensure the server's ephemeral DH public key to be valid
  if(_otherDHEPubKey == nullptr)
   sendCliSTSMErrMsg(ERR_INVALID_PUBKEY,OSSL_ERR_DESC);

  /* ------------------ Shared symmetric key derivation ------------------ */

  // Derive the shared AES_128 symmetric key from the client's
  // private and the server's public ephemeral DH keys
  deriveAES128Skey(_cliConnMgr._skey);

  /* --------------- Server STSM Auth Fragment Verification --------------- */

/*  // Build the server's STSM authentication value into
  // the associated connection manager's secondary buffer
  writeMyEDHPubKey(&_cliConnMgr._priBuf[DH2048_PUBKEY_PEM_SIZE]);
  writeOtherEDHPubKey(&_cliConnMgr._priBuf[0]);*/

  logOtherEDHPubKey();

 }




/**
 * @brief  Sends the 'CLIENT_HELLO' STSM message to the SafeCloud server (1/4)
 * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
 * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the client's ephemeral DH public key into the BIO
 * @throws ERR_OSSL_BIO_READ_FAILED             Failed to read the client's ephemeral DH public key from the BIO
 * @throws ERR_OSSL_RAND_POLL_FAILED            RAND_poll() IV seed generation failed
 * @throws ERR_OSSL_RAND_BYTES_FAILED           RAND_bytes() IV bytes generation failed
 */
void CliSTSMMgr::send_client_hello()
 {
  // Interpret the associated connection manager's primary connection buffer as a 'CLIENT_HELLO' STSM message
  STSM_CLIENT_HELLO* cliHelloMsg = reinterpret_cast<STSM_CLIENT_HELLO*>(_cliConnMgr._priBuf);

  /* ------------------------ STSM Message Header ------------------------ */

  // Initialize the STSM message length and type
  cliHelloMsg->header.len = sizeof(STSM_CLIENT_HELLO);
  cliHelloMsg->header.type = CLIENT_HELLO;

  /* ------------------ Client's ephemeral DH public key ------------------ */

  // Write the client's ephemeral DH public key into the 'CLIENT_HELLO' message
  writeMyEDHPubKey(cliHelloMsg->cliEDHPubKey);

  /* ----------------------------- Random IV ----------------------------- */

  // Generate a random AES_GCM_128 IV for the connection
  _cliConnMgr._iv = new IV();

  // Copy the generated IV into the 'CLIENT_HELLO' message
  cliHelloMsg->iv = *_cliConnMgr._iv;

  // Increment the IV least significant variable part in the 'CLIENT_HELLO' message
  // (as the client's connection manager will increment its IV upon sending the message)
  cliHelloMsg->iv.incIV();

  /* -------------------------- Message Sending -------------------------- */

  // Send the 'CLIENT_HELLO' message to the server
  _cliConnMgr.sendMsg();

  LOG_DEBUG("STSM 1/4: Sent 'CLIENT_HELLO' message, awaiting server 'SRV_AUTH' message")

  /*
  // LOG: Message contents
  std::cout << "cliHelloMsg->header.len = " << cliHelloMsg->header.len << std::endl;
  std::cout << "cliHelloMsg->header.type = " << cliHelloMsg->header.type << std::endl;
  std::cout << "cliHelloMsg->iv.iv_AES_CBC = " << cliHelloMsg->iv.iv_AES_CBC << std::endl;
  std::cout << "cliHelloMsg->iv.iv_AES_GCM = " << cliHelloMsg->iv.iv_AES_GCM << std::endl;
  std::cout << "cliHelloMsg->iv.iv_var = " << cliHelloMsg->iv.iv_var << std::endl;
  */

  /*
  // LOG: Client's public key
  logMyEDHPubKey();
  */
 }


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

/**
 * @brief  Starts and executes the STSM client protocol, returning once a symmetric key has
 *         been established and the client is authenticated within the SafeCloud server
 * @throws TODO
 */
void CliSTSMMgr::startCliSTSM()
 {
  // Ensure that the STSM client protocol has
  // not already been started by this manager
  if(_stsmCliState != INIT)
   THROW_SCODE(ERR_STSM_CLI_ALREADY_STARTED);

  // Send the 'CLIENT_HELLO' STSM message to the SafeCloud server (1/4)
  send_client_hello();

  // Update the STSM client state
  _stsmCliState = WAITING_SRV_AUTH;

  // Block until the expected 'SRV_AUTH' message has been received
  recvCheckCliSTSMMsg();

  // Parse the server's 'SRV_AUTH' message
  recv_srv_auth();


 }