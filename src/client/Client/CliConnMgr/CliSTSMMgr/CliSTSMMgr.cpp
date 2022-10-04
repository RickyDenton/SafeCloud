/* Station-to-Station-Modified (STSM) Key Exchange Protocol Client Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSTSMMgr.h"
#include "../CliConnMgr.h"
#include "scode.h"
#include "errlog.h"
#include "ConnMgr/STSMMgr/STSMMsg.h"
#include "ossl_crypto/AES_128_CBC.h"
#include "ossl_crypto/DigSig.h"

/* =============================== PRIVATE METHODS =============================== */

/* ------------------------- Error Checking and Handling ------------------------- */

/**
 * @brief  Sends a STSM error message to the server and throws the
 *         associated exception on the client, aborting the connection
 * @param  errMsgType The STSM error message type to be sent to the server
 * @param  errDesc    An optional description of the error that has occurred
 * @throws ERR_STSM_CLI_SRV_INVALID_PUBKEY   The server has provided an invalid ephemeral public key
 * @throws ERR_STSM_CLI_SRV_CERT_REJECTED    The received server's certificate is invalid
 * @throws ERR_STSM_CLI_SRV_AUTH_FAILED      Server STSM authentication failed
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

    // The server provided an invalid X.509 certificate
    case ERR_SRV_CERT_REJECTED:
     THROW_SCODE(ERR_STSM_CLI_SRV_CERT_REJECTED,errDesc);

    // The server has failed the STSM authentication
    case ERR_SRV_AUTH_FAILED:
     THROW_SCODE(ERR_STSM_CLI_SRV_AUTH_FAILED, errDesc);

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
 * @brief  1) Blocks the execution until a STSM message has been received
 *            in the associated connection manager's primary buffer\n
 *         2) Verifies the received message to consist of the STSM handshake message
 *            appropriate for the current client's STSM state, throwing an error otherwise
 * @throws ERR_STSM_UNEXPECTED_MESSAGE       An out-of-order STSM message has been received
 * @throws ERR_STSM_MALFORMED_MESSAGE        STSM message type and size mismatch
 * @throws ERR_STSM_CLI_CLI_INVALID_PUBKEY   The server reported that the client's ephemeral public key is invalid
 * @throws ERR_STSM_CLI_CLIENT_LOGIN_FAILED  The server did not recognize the client's username
 * @throws ERR_STSM_CLI_CLI_AUTH_FAILED      The server reported the client failing the STSM authentication
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

    // The server did not recognize the username in the STSM protocol
    case ERR_CLIENT_LOGIN_FAILED:
     THROW_SCODE(ERR_STSM_CLI_CLIENT_LOGIN_FAILED);

    // The server reported the client failing the STSM authentication
    case ERR_CLI_AUTH_FAILED:
     THROW_SCODE(ERR_STSM_CLI_CLI_AUTH_FAILED);

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


/* ------------------------- 'CLIENT_HELLO' Message (1/4) ------------------------- */

/**
 * @brief  Sends the 'CLIENT_HELLO' STSM message to the SafeCloud server (1/4), consisting of:\n
 *             1) The client's ephemeral DH public key "Yc"\n
 *             2) The initial random IV to be used in the secure communication\n
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

  /* -------------------------- Message Sending -------------------------- */

  // Send the 'CLIENT_HELLO' message to the server
  _cliConnMgr.sendMsg();

  LOG_DEBUG("STSM 1/4: Sent 'CLIENT_HELLO' message, awaiting server 'SRV_AUTH' message")

  /*
  // LOG: 'CLIENT_HELLO' message contents:
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
  logMyEDHPubKey();
  printf("\n");
  */
 }


/* --------------------------- 'SRV_AUTH' Message (2/4) --------------------------- */

/**
 * @brief Validates the certificate provided by the server in the 'SRV_AUTH' message by:\n
 *           1) Verifying it to belong to the SafeCloud server by
 *              asserting its Common Name (CN) to be "SafeCloud"\n
 *           2) Verifying it against the client's X.509 certificates store
 * @param srvCert The server's certificate to be validated
 * @throws ERR_STSM_CLI_SRV_CERT_REJECTED The server's certificate is invalid
 * @throws ERR_OSSL_X509_STORE_CTX_NEW    X509_STORE context creation failed
 * @throws ERR_OSSL_X509_STORE_CTX_INIT   X509_STORE context initialization failed
 */
void CliSTSMMgr::validateSrvCert(X509* srvCert)
 {
  // Assert the server's certificate format to be valid
  if(!srvCert)
   sendCliSTSMErrMsg(ERR_SRV_CERT_REJECTED,OSSL_ERR_DESC);

  /* ---------- Server Certificate Common Name (CN) Verification ---------- */

  // Extract the certificate subject's full name
  X509_NAME* certSubjectName = X509_get_subject_name(srvCert);
  if(certSubjectName == NULL)
   sendCliSTSMErrMsg(ERR_SRV_CERT_REJECTED,OSSL_ERR_DESC);

  // Retrieve the index of the CN entry in the X509_NAME struct via its numerical index (nid)
  int nid = OBJ_txt2nid("CN");
  int index = X509_NAME_get_index_by_NID(certSubjectName, nid, -1);
  if(index == -1)
   sendCliSTSMErrMsg(ERR_SRV_CERT_REJECTED,OSSL_ERR_DESC);

  // Retrieve the CN entry from the X509_NAME struct via its index
  X509_NAME_ENTRY* certSubjectCN = X509_NAME_get_entry(certSubjectName, index);
  if(!certSubjectCN)
   sendCliSTSMErrMsg(ERR_SRV_CERT_REJECTED,OSSL_ERR_DESC);

  // Retrieve the CN entry value as an ASN1 string
  ASN1_STRING* subjectCN_ASN1 = X509_NAME_ENTRY_get_data(certSubjectCN);
  if(!subjectCN_ASN1)
   sendCliSTSMErrMsg(ERR_SRV_CERT_REJECTED,OSSL_ERR_DESC);

  // Convert the CN value from an ASN1 to a conventional C string
  const unsigned char* subjectCN = ASN1_STRING_get0_data(subjectCN_ASN1);
  if(!subjectCN)
   sendCliSTSMErrMsg(ERR_SRV_CERT_REJECTED,OSSL_ERR_DESC);

  // Verify the CN to be equal to "SafeCloud"
  if(memcmp(subjectCN,"SafeCloud",9) != 0)
   sendCliSTSMErrMsg(ERR_SRV_CERT_REJECTED,OSSL_ERR_DESC);

  /* ---------------- Server Certificate Store Verification ---------------- */

  // Create a X509 store verification context
  X509_STORE_CTX* srvCertVerCTX = X509_STORE_CTX_new();
  if(!srvCertVerCTX)
   THROW_SCODE(ERR_OSSL_X509_STORE_CTX_NEW,OSSL_ERR_DESC);

  // Initialize the store verification context passing
  // the client's X.509 store and the server's certificate
  if(X509_STORE_CTX_init(srvCertVerCTX, _cliStore, srvCert, NULL) != 1)
   THROW_SCODE(ERR_OSSL_X509_STORE_CTX_INIT,OSSL_ERR_DESC);

  // Verify the server's certificate against the client's store
  if(X509_verify_cert(srvCertVerCTX) != 1)
   sendCliSTSMErrMsg(ERR_SRV_CERT_REJECTED,OSSL_ERR_DESC);

  // Free the store verification context
  X509_STORE_CTX_free(srvCertVerCTX);

  // At this point the server's certificate is valid and, In DEBUG_MODE, log its issuer
#ifdef DEBUG_MODE
  char* certIssuer = X509_NAME_oneline(X509_get_issuer_name(srvCert), NULL, 0);
  LOG_DEBUG("The SafeCloud Server provided a valid certificate (issued by " + std::string(certIssuer) + ")")
#endif
 }


/**
 * @brief  Parses the server's 'SRV_AUTH' STSM message (2/4), consisting of:\n
 *            1) The server's ephemeral DH public key "Ys"\n
 *            2) The server's STSM authentication proof, consisting of the concatenation
 *               of both actors' ephemeral public DH keys (STSM authentication value)
 *               signed with the server's long-term private RSA key and encrypted with
 *               the resulting shared symmetric session key "{<Yc,Ys>s}k"\n
 *            3) The server's certificate "srvCert"
 * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
 * @throws ERR_OSSL_EVP_PKEY_NEW                EVP_PKEY struct creation failed
 * @throws ERR_STSM_SRV_CLI_INVALID_PUBKEY      The server provided an invalid ephemeral DH public key
 * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the server' public key into the memory BIO
 * @throws ERR_STSM_CLI_SRV_CERT_REJECTED       The server's certificate is invalid
 * @throws ERR_OSSL_X509_STORE_CTX_NEW          X509_STORE context creation failed
 * @throws ERR_OSSL_X509_STORE_CTX_INIT         X509_STORE context initialization failed
 * @throws ERR_STSM_MY_PUBKEY_MISSING           The server's ephemeral DH public key is missing
 * @throws ERR_STSM_OTHER_PUBKEY_MISSING        The client's ephemeral DH public key is missing
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE         The ciphertext size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_CIPHER_CTX_NEW          EVP_CIPHER context creation failed
 * @throws ERR_OSSL_EVP_DECRYPT_INIT            EVP_CIPHER decrypt initialization failed
 * @throws ERR_OSSL_EVP_DECRYPT_UPDATE          EVP_CIPHER decrypt update failed
 * @throws ERR_OSSL_EVP_DECRYPT_FINAL           EVP_CIPHER decrypt final failed
 * @throws ERR_STSM_MALFORMED_MESSAGE           Erroneous size of the server's signed STSM authentication value
 * @throws ERR_OSSL_EVP_MD_CTX_NEW              EVP_MD context creation failed
 * @throws ERR_OSSL_EVP_VERIFY_INIT             EVP_MD verification initialization failed
 * @throws ERR_OSSL_EVP_VERIFY_UPDATE           EVP_MD verification update failed
 * @throws ERR_OSSL_EVP_VERIFY_FINAL            EVP_MD verification final failed
 * @throws ERR_STSM_CLI_SRV_AUTH_FAILED         Server STSM authentication failed
 */
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
  if(BIO_free(srvPubDHBIO) != 1)
   LOG_SCODE(ERR_OSSL_BIO_FREE_FAILED,OSSL_ERR_DESC);

  // Ensure the server's ephemeral DH public key to be valid
  if(_otherDHEPubKey == nullptr)
   sendCliSTSMErrMsg(ERR_INVALID_PUBKEY,OSSL_ERR_DESC);

  /*
  // LOG: Server's ephemeral DH public key
  printf("Server's ephemeral DH public key: \n");
  logOtherEDHPubKey();
  printf("\n");
  */

  /* ------------------- Shared Session Key Derivation ------------------- */

  // Derive the shared AES_128 session key from the client's
  // private and the server's public ephemeral DH keys
  deriveAES128SKey(_cliConnMgr._skey);

  // In DEBUG_MODE, log the shared session key in hexadecimal
#ifdef DEBUG_MODE
  char skeyHex[33];
  for(int i = 0; i < AES_128_KEY_SIZE; i++)
   sprintf(skeyHex + 2 * i, "%.2x", _cliConnMgr._skey[i]);
  skeyHex[32] = '\0';

  LOG_DEBUG("Shared session key: " + std::string(skeyHex));
#endif

  /* ------------------ Server Certificate Verification ------------------ */

  // Initialize a memory BIO to the server's certificate
  // TODO: Check if len = -1 is correct as argument, otherwise pass the explicit size
  BIO* srvCertBIO = BIO_new_mem_buf(stsmSrvAuth->srvCert, -1);
  if(srvCertBIO == NULL)
   THROW_SCODE(ERR_OSSL_BIO_NEW_FAILED,OSSL_ERR_DESC);

  // Read the server's certificate into a X509 struct
  X509* srvCert = PEM_read_bio_X509(srvCertBIO, NULL, NULL, NULL);

  // Free the memory BIO
  if(BIO_free(srvCertBIO) != 1)
   LOG_SCODE(ERR_OSSL_BIO_FREE_FAILED,OSSL_ERR_DESC);

  // Validate the server's certificate
  validateSrvCert(srvCert);

  /* ------------ Server STSM Authentication Proof Verification ------------ */

  /*
  // LOG: Server's STSM authentication proof
  printf("Server's STSM authentication proof:\n");
  for(int i=0; i < STSM_AUTH_PROOF_SIZE ; i++)
   printf("%02x", stsmSrvAuth->srvSTSMAuthProof[i]);
  printf("\n");
  */

  // Build the server's STSM authentication value, consisting of the concatenation of both actors'
  // ephemeral public DH keys "Yc||Ys", in the associated connection manager's secondary buffer
  writeMyEDHPubKey(&_cliConnMgr._secBuf[0]);
  writeOtherEDHPubKey(&_cliConnMgr._secBuf[DH2048_PUBKEY_PEM_SIZE]);

  // Decrypt the server's STSM authentication proof in the associated connection manager's secondary buffer
  int decProofSize = AES_128_CBC_Decrypt(_cliConnMgr._skey, _cliConnMgr._iv, stsmSrvAuth->srvSTSMAuthProof,
                                         STSM_AUTH_PROOF_SIZE, &_cliConnMgr._secBuf[2 * DH2048_PUBKEY_PEM_SIZE]);

  // Assert the decrypted STSM authentication proof to be on RSA2048_SIG_SIZE = 256 bytes
  if(decProofSize != 256)
   sendCliSTSMErrMsg(ERR_MALFORMED_MESSAGE,"Decrypted server's STSM authentication proof of invalid size");

  /*
  // LOG: Server's signed STSM authentication value
  printf("Server signed STSM authentication value: \n");
  for(int i=0; i < RSA2048_SIG_SIZE; i++)
   printf("%02x", _cliConnMgr._secBuf[2 * DH2048_PUBKEY_PEM_SIZE + i]);
  printf("\n");
  */

  // Attempt to verify the server's signature on its STSM authentication value <Yc||Ys>s
  try
   { digSigVerify(X509_get_pubkey(srvCert), &_cliConnMgr._secBuf[0], 2 * DH2048_PUBKEY_PEM_SIZE,
                  &_cliConnMgr._secBuf[2 * DH2048_PUBKEY_PEM_SIZE], RSA2048_SIG_SIZE); }
  catch(sCodeException& digVerExcp)
   {
    // If the signature verification failed, inform the server that they
    // have failed the STSM authentication and abort the connection
    if(digVerExcp.scode == ERR_OSSL_SIG_VERIFY_FAILED)
     sendCliSTSMErrMsg(ERR_SRV_AUTH_FAILED);

    // Otherwise, rethrow the exception (which also aborts the connection)
    else
     throw;
   }

  /* ------------------------------ Cleanup ------------------------------ */

  // Free the server's certificate
  X509_free(srvCert);

  LOG_DEBUG("STSM 2/4: Received valid 'SRV_AUTH' message")
 }


/* --------------------------- 'CLI_AUTH' Message (3/4) --------------------------- */

void CliSTSMMgr::send_client_auth()
 {}


/* ---------------------------- 'SRV_OK' Message (4/4) ---------------------------- */

void CliSTSMMgr::recv_srv_ok()
 {}


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

  // TODO: From here, send the client's 'CLI_AUTH' message

  // Update the STSM client state
  //_stsmCliState = WAITING_SRV_OK;

 }