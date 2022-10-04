/* Station-to-Station-Modified (STSM) Key Exchange Protocol Server Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvSTSMMgr.h"
#include "ConnMgr/STSMMgr/STSMMsg.h"
#include "../SrvConnMgr.h"
#include "errlog.h"
#include "ossl_crypto/DigSig.h"
#include "ossl_crypto/AES_128_CBC.h"

/* =============================== PRIVATE METHODS =============================== */

/* ------------------------- Error Checking and Handling ------------------------- */

/**
 * @brief  Sends a STSM error message to the server and throws the
 *         associated exception on the client, aborting the connection
 * @param  errMsgType The STSM error message type to be sent to the server
 * @param  errDesc    An optional description of the error that has occurred
 * @throws ERR_STSM_SRV_CLI_INVALID_PUBKEY  The client has provided an invalid ephemeral public key
 * @throws ERR_STSM_SRV_CLIENT_LOGIN_FAILED Unrecognized username on the server
 * @throws ERR_STSM_SRV_CLI_AUTH_FAILED     The client has failed the STSM authentication
 * @throws ERR_STSM_UNEXPECTED_MESSAGE      Received an out-of-order STSM message
 * @throws ERR_STSM_MALFORMED_MESSAGE       Received a malformed STSM message
 * @throws ERR_STSM_UNKNOWN_STSMMSG_TYPE    Received a STSM message of unknown type
 * @throws ERR_STSM_UNKNOWN_STSMMSG_ERROR   Attempting to send an STSM error message of unknown type
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

    // Unrecognized username on the server
    case ERR_CLIENT_LOGIN_FAILED:
     THROW_SCODE(ERR_STSM_SRV_CLIENT_LOGIN_FAILED,errDesc);

    // The client has failed the STSM authentication
    case ERR_CLI_AUTH_FAILED:
     THROW_SCODE(ERR_STSM_SRV_CLI_AUTH_FAILED, errDesc);

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
 * @throws ERR_STSM_SRV_SRV_CERT_REJECTED    The client rejected the server's X.509 certificate
 * @throws ERR_STSM_SRV_SRV_AUTH_FAILED      The client reported the server failing the STSM authentication
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
     if(stsmMsg->header.len != sizeof(STSM_CLIENT_HELLO))
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

    // The client rejected the server's X.509 certificate
    case ERR_SRV_CERT_REJECTED:
     THROW_SCODE(ERR_STSM_SRV_SRV_CERT_REJECTED);

    // The client reported the server failing the STSM authentication
    case ERR_SRV_AUTH_FAILED:
     THROW_SCODE(ERR_STSM_SRV_SRV_AUTH_FAILED);

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


/* ------------------------- 'CLIENT_HELLO' Message (1/4) ------------------------- */

/**
 * @brief  Parses the client's 'CLIENT_HELLO' STSM message (1/4), consisting of:\n
 *             1) Their ephemeral DH public key "Yc"\n
 *             2) The initial random IV to be used in the secure communication\n
 * @throws ERR_OSSL_BIO_NEW_FAILED         OpenSSL BIO initialization failed
 * @throws ERR_OSSL_EVP_PKEY_NEW           EVP_PKEY struct creation failed
 * @throws ERR_STSM_SRV_CLI_INVALID_PUBKEY The client provided an invalid ephemeral DH public key
 */
void SrvSTSMMgr::recv_client_hello()
 {
  // Interpret the connection manager's primary buffer as a 'CLIENT_HELLO' STSM message
  STSM_CLIENT_HELLO* cliHelloMsg = reinterpret_cast<STSM_CLIENT_HELLO*>(_srvConnMgr._priBuf);

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
  if(BIO_free(cliPubDHBio) != 1)
   LOG_SCODE(ERR_OSSL_BIO_FREE_FAILED,OSSL_ERR_DESC);

  // Ensure the client's ephemeral DH public key to be valid
  if(_otherDHEPubKey == nullptr)
   sendSrvSTSMErrMsg(ERR_INVALID_PUBKEY,OSSL_ERR_DESC);

  /* ----------------------------- Random IV ----------------------------- */

  // Initialize the associated connection manager's IV to the client-provided value
  _srvConnMgr._iv = new IV(cliHelloMsg->iv);

  /* ------------------------------ Cleanup ------------------------------ */

  LOG_DEBUG("[" + *_srvConnMgr._name + "] STSM 1/4: Received valid 'CLIENT_HELLO' message")

  /*
  // LOG: 'CLIENT_HELLO' message contents
  printf("CLIENT_HELLO' message contents: \n");
  std::cout << "cliHelloMsg->header.len = " << cliHelloMsg->header.len << std::endl;
  std::cout << "cliHelloMsg->header.type = " << cliHelloMsg->header.type << std::endl;
  std::cout << "cliHelloMsg->iv.iv_AES_CBC = " << cliHelloMsg->iv.iv_AES_CBC << std::endl;
  std::cout << "cliHelloMsg->iv.iv_AES_GCM = " << cliHelloMsg->iv.iv_AES_GCM << std::endl;
  std::cout << "cliHelloMsg->iv.iv_var = " << cliHelloMsg->iv.iv_var << std::endl;
  printf("\n");
  */

  /*
  // LOG: Client's ephemeral DH public key:
  printf("Client's ephemeral DH public key: \n");
  logOtherEDHPubKey();
  printf("\n");
  */
 }


/* --------------------------- 'SRV_AUTH' Message (2/4) --------------------------- */

/**
 * @brief Sends the 'SRV_AUTH' STSM message to the client (2/4), consisting of:\n
 *            1) The server's ephemeral DH public key "Ys"\n
 *            2) The server's STSM authentication proof, consisting of the concatenation
 *               of both actors' ephemeral public DH keys (STSM authentication value)
 *               signed with the server's long-term private RSA key and encrypted with
 *               the resulting shared symmetric session key "{<Yc,Ys>s}k"\n
 *            3) The server's certificate "srvCert"
 * @throws ERR_STSM_MY_PUBKEY_MISSING           The server's ephemeral DH public key is missing
 * @throws ERR_STSM_OTHER_PUBKEY_MISSING        The client's ephemeral DH public key is missing
 * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
 * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write an ephemeral DH public key into the BIO
 * @throws ERR_OSSL_BIO_READ_FAILED             Failed to read a cryptographic quantity from a BIO
 * @throws ERR_OSSL_EVP_MD_CTX_NEW              EVP_MD context creation failed
 * @throws ERR_OSSL_EVP_SIGN_INIT               EVP_MD signing initialization failed
 * @throws ERR_OSSL_EVP_SIGN_UPDATE             EVP_MD signing update failed
 * @throws ERR_OSSL_EVP_SIGN_FINAL              EVP_MD signing final failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE         The plaintext size is non-positive (probable overflow)
 * @throws ERR_OSSL_AES_128_CBC_PT_TOO_LARGE    The plaintext to encrypt is too large
 * @throws ERR_OSSL_EVP_CIPHER_CTX_NEW          EVP_CIPHER context creation failed
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT            EVP_CIPHER encrypt initialization failed
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE          EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL           EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
 * @throws ERR_OSSL_PEM_WRITE_BIO_X509          Failed to write the server's X.509 certificate to the BIO
 */
void SrvSTSMMgr::send_srv_auth()
 {
  // Interpret the associated connection manager's primary connection buffer as a 'SRV_AUTH' message
  STSM_SRV_AUTH* stsmSrvAuth = reinterpret_cast<STSM_SRV_AUTH*>(_srvConnMgr._priBuf);

  /* ------------------ Server's ephemeral DH public key ------------------ */

  // Write the server's ephemeral DH public key into the 'SRV_AUTH' message
  writeMyEDHPubKey(&stsmSrvAuth->srvEDHPubKey[0]);

  /* ----------------- Server's STSM Authentication Proof ----------------- */

  // Build the server's STSM authentication value, consisting of the concatenation of both actors'
  // ephemeral public DH keys "Yc||Ys", in the associated connection manager's secondary buffer
  writeOtherEDHPubKey(&_srvConnMgr._secBuf[0]);
  writeMyEDHPubKey(&_srvConnMgr._secBuf[DH2048_PUBKEY_PEM_SIZE]);

  // Sign the server's STSM authentication value using the server's long-term private RSA key
  //
  // NOTE: As the server's private RSA key is on 2048 bit, the resulting signature has an
  //       implicit size of 2048 bits = 256 bytes
  //
  digSigSign(_myRSALongPrivKey, &_srvConnMgr._secBuf[0],
             2 * DH2048_PUBKEY_PEM_SIZE, &_srvConnMgr._secBuf[2 * DH2048_PUBKEY_PEM_SIZE]);

  /*
  // LOG: Server's signed STSM authentication value
  printf("Server signed STSM authentication value: \n");
  for(int i=0; i < RSA2048_SIG_SIZE; i++)
   printf("%02x", _srvConnMgr._secBuf[2 * DH2048_PUBKEY_PEM_SIZE + i]);
  printf("\n");
  */

  // Encrypt the signed STSM authentication value as the server STSM authentication proof in the 'SRV_AUTH' message
  //
  // NOTE: Being the size of the signed STSM authentication value of 256 bytes an integer multiple of the
  //       AES block size, its encryption will always add a full padding block of 128 bits = 16 bytes,
  //       for an implicit size of the resulting STSM authentication proof of 256 + 16 = 272 bytes
  AES_128_CBC_Encrypt(_srvConnMgr._skey, reinterpret_cast<unsigned char*>(&(_srvConnMgr._iv->iv_AES_CBC)),
                      &_srvConnMgr._secBuf[2 * DH2048_PUBKEY_PEM_SIZE], RSA2048_SIG_SIZE, stsmSrvAuth->srvSTSMAuthProof);

  /* --------------------- Server's X.509 Certificate --------------------- */

  // Initialize a memory BIO for storing the server's X.509 certificate
  BIO* srvCertBIO = BIO_new(BIO_s_mem());
  if(srvCertBIO == NULL)
   THROW_SCODE(ERR_OSSL_BIO_NEW_FAILED,OSSL_ERR_DESC);

  // Write the server's X.509 certificate to the BIO
  if(PEM_write_bio_X509(srvCertBIO, _srvCert) != 1)
   THROW_SCODE(ERR_OSSL_PEM_WRITE_BIO_X509,OSSL_ERR_DESC);

  // Retrieve the certificate size
  int srvCertSize = BIO_pending(srvCertBIO);

  // Write the server's X.509 certificate from the BIO to the 'SRV_AUTH' message
  if(BIO_read(srvCertBIO, stsmSrvAuth->srvCert, srvCertSize) <= 0)
   THROW_SCODE(ERR_OSSL_BIO_READ_FAILED,OSSL_ERR_DESC);

  // Free the memory BIO
  if(BIO_free(srvCertBIO) != 1)
   LOG_SCODE(ERR_OSSL_BIO_FREE_FAILED,OSSL_ERR_DESC);

  /* ------------------ Message Finalization and Sending ------------------ */

  // Initialize the 'SRV_AUTH' message length and type
  stsmSrvAuth->header.len = sizeof(STSMMsgHeader) + DH2048_PUBKEY_PEM_SIZE + STSM_AUTH_PROOF_SIZE + srvCertSize;
  stsmSrvAuth->header.type = SRV_AUTH;

  // Send the 'SRV_AUTH' message to the client
  _srvConnMgr.sendMsg();

  LOG_DEBUG("[" + *_srvConnMgr._name + "] STSM 2/4: Sent 'SRV_AUTH' message, awaiting 'CLIENT_AUTH' message")

  /*
  // LOG: 'SRV_AUTH' message contents
  printf("'SRV_AUTH' message contents: \n");
  std::cout << "stsmSrvAuth->header.len = " << stsmSrvAuth->header.len << std::endl;
  std::cout << "stsmSrvAuth->header.type = " << stsmSrvAuth->header.type << std::endl;
  printf("\n");

  printf("Server's ephemeral DH public key: \n");
  logMyEDHPubKey();
  printf("\n");

  printf("Server's STSM authentication proof:\n");
  for(int i=0; i < STSM_AUTH_PROOF_SIZE ; i++)
   printf("%02x", stsmSrvAuth->srvSTSMAuthProof[i]);
  printf("\n");
  */
 }


/* --------------------------- 'CLI_AUTH' Message (3/4) --------------------------- */

void SrvSTSMMgr::recv_client_auth()
 {}

/* ---------------------------- 'SRV_OK' Message (4/4) ---------------------------- */

void SrvSTSMMgr::send_srv_ok()
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

    // Derive the shared AES_128 session key from the server's
    // private and the client's public ephemeral DH keys
    deriveAES128SKey(_srvConnMgr._skey);

    // In DEBUG_MODE, log the shared session key in hexadecimal
#ifdef DEBUG_MODE
  char skeyHex[33];
  for(int i = 0; i < AES_128_KEY_SIZE; i++)
   sprintf(skeyHex + 2 * i, "%.2x", _srvConnMgr._skey[i]);
  skeyHex[32] = '\0';

  LOG_DEBUG("[" + *_srvConnMgr._name + "] Shared session key: " + std::string(skeyHex));
#endif

    // Send the server's 'SRV_AUTH' message
    send_srv_auth();

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

