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
 * @throws ERR_STSM_CLI_SRV_INVALID_PUBKEY   The server has provided an invalid ephemeral public key
 * @throws ERR_STSM_CLI_SRV_CHALLENGE_FAILED Server STSM authentication challenge failed
 * @throws ERR_STSM_CLI_SRV_CERT_REJECTED    The received server's certificate is invalid
 * @throws ERR_STSM_UNEXPECTED_MESSAGE       Received an out-of-order STSM message
 * @throws ERR_STSM_MALFORMED_MESSAGE        Received a malformed STSM message
 * @throws ERR_STSM_UNKNOWN_STSMMSG_TYPE     Received a STSM message of unknown type
 * @throws ERR_STSM_UNKNOWN_STSMMSG_ERROR    Attempting to send a STSM error message of unknown type
 */
void CliSTSMMgr::sendCliSTSMErrMsg(STSMMsgType errMsgType)
 {
  // Interpret the associated connection manager's primary connection buffer as a STSMsg
  STSMMsg* errMsg = reinterpret_cast<STSMMsg*>(_cliConnMgr._priBuf);

  // Set the error message header's length and type
  errMsg->header.len = sizeof(STSMMsg);
  errMsg->header.type = errMsgType;

  // Send the error message
  _cliConnMgr.sendMsg();

  // Throw the exception associated with the error message type
  switch(errMsgType)
   {
    /* ------------------------ Error STSM Messages  ------------------------ */

    // The server has provided an invalid ephemeral public key
    case ERR_INVALID_PUBKEY:
     THROW_SCODE(ERR_STSM_CLI_SRV_INVALID_PUBKEY);

    // The server has failed the STSM authentication challenge
    case ERR_SRV_CHALLENGE_FAILED:
     THROW_SCODE(ERR_STSM_CLI_SRV_CHALLENGE_FAILED);

    // The server provided an invalid X.509 certificate
    case ERR_SRV_CERT_REJECTED:
     THROW_SCODE(ERR_STSM_CLI_SRV_CERT_REJECTED);

    // An out-of-order STSM message has been received
    case ERR_UNEXPECTED_MESSAGE:
     THROW_SCODE(ERR_STSM_UNEXPECTED_MESSAGE);

    // A malformed STSM message has been received
    case ERR_MALFORMED_MESSAGE:
     THROW_SCODE(ERR_STSM_MALFORMED_MESSAGE);

    // A STSM message of unknown type has been received
    case ERR_UNKNOWN_STSMMSG_TYPE:
     THROW_SCODE(ERR_STSM_UNKNOWN_STSMMSG_TYPE);

    // Unknown Message
    default:
     THROW_SCODE(ERR_STSM_UNKNOWN_STSMMSG_ERROR,"(" + std::to_string(errMsgType) + ")");
   }
 }


/**
 * @brief  1) Blocks the execution until a STSM message has been received in the associated connection manager's primary buffer\n
 *         2) Verifies the received message not to consist of a STSM error message, throwing the associated exception otherwise\n
 *         3) Verifies the received message to be of the appropriate type and length depending on the client's current STSM state
 * @throws ERR_STSM_UNEXPECTED_MESSAGE       An out-of-order STSM message has been received
 * @throws ERR_STSM_MALFORMED_MESSAGE        Mismatch between the STSM message type and size
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
  STSMMsg*stsmMsg = reinterpret_cast<STSMMsg*>(_cliConnMgr._priBuf);

  // Depending on the received STSM message's type
  switch(stsmMsg->header.type)
   {
    /* ------------- Client-valid received STSM message types  ------------- */

    // 'SRV_AUTH' message
    case SRV_AUTH:

     // This message can be received only in the 'WAITING_SRV_AUTH' STSM client state
     if(_stsmCliState != WAITING_SRV_AUTH)
      sendCliSTSMErrMsg(ERR_UNEXPECTED_MESSAGE);

     // Ensure the message length to be equal to the size of a 'SRV_AUTH' message
     if(stsmMsg->header.len != sizeof(STSM_SRV_AUTH))
      sendCliSTSMErrMsg(ERR_MALFORMED_MESSAGE);

     // A valid SRV_AUTH message was received
     return;

    // 'SRV_OK' message
    case SRV_OK:

     // This message can be received only in the 'WAITING_SRV_OK' STSM client state
     if(_stsmCliState != WAITING_SRV_OK)
      sendCliSTSMErrMsg(ERR_UNEXPECTED_MESSAGE);

     // Ensure the message length to be equal to the size of a 'SRV_OK' message
     if(stsmMsg->header.len != sizeof(SRV_OK))
      sendCliSTSMErrMsg(ERR_MALFORMED_MESSAGE);

     // A valid SRV_OK message was received
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
  STSM_Client_Hello* cliHelloMsg = reinterpret_cast<STSM_Client_Hello*>(_cliConnMgr._priBuf);

  /* --------------------- STSM Message Header ---------------------------- */

  // Initialize the STSM message length and type
  cliHelloMsg->header.len = sizeof(STSM_Client_Hello);
  cliHelloMsg->header.type = CLIENT_HELLO;

  /* -------------- Client's ephemeral DH public key --------------------- */

  // Initialize a memory BIO for storing the client's ephemeral DH public key
  BIO* myEDHPubKeyBIO = BIO_new(BIO_s_mem());
  if(myEDHPubKeyBIO == NULL)
   THROW_SCODE(ERR_OSSL_BIO_NEW_FAILED,OSSL_ERR_DESC);

  // Write the client's ephemeral DH public key to the BIO
  if(PEM_write_bio_PUBKEY(myEDHPubKeyBIO, _myDHEKey) != 1)
   THROW_SCODE(ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED,OSSL_ERR_DESC);

  // Write the client's ephemeral DH public key from the BIO into
  // the "cliEDHPubKey" field of the 'CLIENT_HELLO' message
  if(BIO_read(myEDHPubKeyBIO, cliHelloMsg->cliEDHPubKey, DH2048_PUBKEY_PEM_SIZE) <= 0)
   THROW_SCODE(ERR_OSSL_BIO_READ_FAILED,OSSL_ERR_DESC);

  // Free the memory BIO
  if(BIO_free(myEDHPubKeyBIO) != 1)
   LOG_SCODE(ERR_OSSL_BIO_FREE_FAILED,OSSL_ERR_DESC);

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

  // TODO Debug, remove
  std::cout << "cliHelloMsg.header.len = " << cliHelloMsg->header.len << std::endl;
  std::cout << "cliHelloMsg.header.type = " << cliHelloMsg->header.type << std::endl;
  std::cout << "cliHelloMsg.iv.iv_high = " << cliHelloMsg->iv.iv_high << std::endl;
  std::cout << "cliHelloMsg.iv.iv_low = " << cliHelloMsg->iv.iv_low << std::endl;

  // Log the client's public key
  logEDHPubKey(_myDHEKey);
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

  // TODO: From here
  // Block until the expected 'SRV_AUTH' message has been received
  //recvCheckCliSTSMMsg();
 }