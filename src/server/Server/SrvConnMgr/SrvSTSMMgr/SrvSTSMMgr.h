#ifndef SAFECLOUD_SRVSTSMMGR_H
#define SAFECLOUD_SRVSTSMMGR_H

/* Station-to-Station-Modified (STSM) Key Exchange Protocol Server Manager */

#include "ConnMgr/STSMMgr/STSMMgr.h"

// Forward Declaration
class SrvConnMgr;

class SrvSTSMMgr : public STSMMgr
 {
   private:

    // STSM Server States
    enum STSMSrvState
     {
      // The server has not yet received the client's 'hello' message
      WAITING_CLI_HELLO,

      // The server has sent its 'auth' message and is awaiting the client's one
      WAITING_CLI_AUTH
     };

    /* ================================= ATTRIBUTES ================================= */
    enum STSMSrvState _stsmSrvState;  // Current server state in the STSM key exchange protocol
    SrvConnMgr&       _srvConnMgr;    // The parent SrvConnMgr instance managing this object
    X509*             _srvCert;       // The server's X.509 certificate

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
    void sendSrvSTSMErrMsg(STSMMsgType errMsgType,const char* errDesc);

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
    void checkSrvSTSMMsg();


    void recv_client_hello();


    void recv_client_auth();


   public:

    /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

    /**
     * @brief                  SrvSTSMMgr object constructor
     * @param myRSALongPrivKey The server's long-term RSA key pair
     * @param srvConnMgr       The parent SrvConnMgr instance managing this object
     * @param srvCert          The server's X.509 certificate
     */
    SrvSTSMMgr(EVP_PKEY* myRSALongPrivKey, SrvConnMgr& srvConnMgr, X509* srvCert);

    // Same destructor of the STSMMgr base class

    /* ============================= OTHER PUBLIC METHODS ============================= */

    /**
     * @brief  Server STSM Message handler, processing a client STSM message
     *         stored in the associated connection manager's primary buffer
     * @return A boolean indicating  whether the key establishment phase has terminated and
     *         so the connection can switch to the session phase ('true') or not ('false')
     * @throws TODO
     */
    bool STSMMsgHandler();



  // TODO:
  //
  // NOTE: 1) All return the success of the operation TODO: exceptions?
  //       2) All check for the STSMError message before doing their thing
  //
  // bool rcvHello();
  // bool sendSrvAuth();
  // bool recvCliAuth();
  // bool sendSrvOK();
 };

#endif //SAFECLOUD_SRVSTSMMGR_H
