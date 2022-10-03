#ifndef SAFECLOUD_CLISTSMMGR_H
#define SAFECLOUD_CLISTSMMGR_H

/* Station-to-Station-Modified (STSM) Key Exchange Protocol Client Manager */

#include "ConnMgr/STSMMgr/STSMMgr.h"

// Forward Declaration
class CliConnMgr;

class CliSTSMMgr : public STSMMgr
 {
  private:

   // STSM Client States
   enum STSMCliState
    {
     // The client has yet to send its 'hello' message
     INIT,

     // The client has sent its 'hello' message and is awaiting the server's 'auth' message
     WAITING_SRV_AUTH,

     // The client has sent its 'auth' message and is awaiting the server 'ok' message
     WAITING_SRV_OK
    };

   /* ================================= ATTRIBUTES ================================= */
   enum STSMCliState _stsmCliState;  // Current client state in the STSM key exchange protocol
   CliConnMgr&       _cliConnMgr;    // The parent CliConnMgr instance managing this object
   X509_STORE*       _cliStore;      // The client's already-initialized X.509 certificate store used for validating the server's signature

   /* =============================== PRIVATE METHODS =============================== */

   /* ------------------------- Error Checking and Handling ------------------------- */

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
   void sendCliSTSMErrMsg(STSMMsgType errMsgType,const char* errDesc);

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
   void recvCheckCliSTSMMsg();





  void validateSrvCert(X509* srvCert);

  void recv_srv_auth();


   /**
    * @brief  Sends the 'CLIENT_HELLO' STSM message to the SafeCloud server (1/4)
    * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
    * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the client's ephemeral DH public key into the BIO
    * @throws ERR_OSSL_BIO_READ_FAILED             Failed to read the client's ephemeral DH public key from the BIO
    * @throws ERR_OSSL_RAND_POLL_FAILED            RAND_poll() IV seed generation failed
    * @throws ERR_OSSL_RAND_BYTES_FAILED           RAND_bytes() IV bytes generation failed
    */
   void send_client_hello();


  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief                  CliSTSMMgr object constructor
    * @param myRSALongPrivKey The client's long-term RSA key pair
    * @param cliConnMgr       A reference to the parent CliConnMgr object
    * @param cliStore         The client's X.509 certificates store
    */
   CliSTSMMgr(EVP_PKEY* myRSALongPrivKey, CliConnMgr& cliConnMgr, X509_STORE* cliStore);

   // Same destructor of the STSMMgr base class

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief  Starts and executes the STSM client protocol, returning once a symmetric key has
    *         been established and the client is authenticated within the SafeCloud server
    * @throws TODO
    */
   void startCliSTSM();
 };


#endif //SAFECLOUD_CLISTSMMGR_H
