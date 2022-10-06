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
     * @throws ERR_STSM_SRV_CLI_INVALID_PUBKEY  The client has provided an invalid ephemeral public key
     * @throws ERR_STSM_SRV_CLIENT_LOGIN_FAILED Unrecognized username on the server
     * @throws ERR_STSM_SRV_CLI_AUTH_FAILED     The client has failed the STSM authentication
     * @throws ERR_STSM_UNEXPECTED_MESSAGE      Received an out-of-order STSM message
     * @throws ERR_STSM_MALFORMED_MESSAGE       Received a malformed STSM message
     * @throws ERR_STSM_UNKNOWN_STSMMSG_TYPE    Received a STSM message of unknown type
     * @throws ERR_STSM_UNKNOWN_STSMMSG_ERROR   Attempting to send an STSM error message of unknown type
     */
    void sendSrvSTSMErrMsg(STSMMsgType errMsgType,const char* errDesc);


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
    void checkSrvSTSMMsg();


    /* ------------------------- 'CLIENT_HELLO' Message (1/4) ------------------------- */

    /**
     * @brief  Parses the client's 'CLIENT_HELLO' STSM message (1/4), consisting of:\n
     *             1) Their ephemeral DH public key "Yc"\n
     *             2) The initial random IV to be used in the secure communication\n
     * @throws ERR_OSSL_BIO_NEW_FAILED O       OpenSSL BIO initialization failed
     * @throws ERR_OSSL_EVP_PKEY_NEW           EVP_PKEY struct creation failed
     * @throws ERR_STSM_SRV_CLI_INVALID_PUBKEY The client provided an invalid ephemeral DH public key
     */
    void recv_client_hello();


    /* --------------------------- 'SRV_AUTH' Message (2/4) --------------------------- */

    /**
     * @brief Sends the 'SRV_AUTH' STSM message to the client (2/4), consisting of:\n
     *            1) The server's ephemeral DH public key "Ys"\n
     *            2) The server's STSM authentication proof, consisting of the concatenation
     *               of both actors' ephemeral public DH keys (STSM authentication value)
     *               signed with the server's long-term private RSA key and encrypted with
     *               the resulting shared  session key "{<Yc||Ys>s}k"\n
     *            3) The server's certificate "srvCert"
     * @throws ERR_STSM_MY_PUBKEY_MISSING           The server's ephemeral DH public key is missing
     * @throws ERR_STSM_OTHER_PUBKEY_MISSING        The client's ephemeral DH public key is missing
     * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
     * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write an ephemeral DH public key into a BIO
     * @throws ERR_OSSL_BIO_READ_FAILED             Failed to read a cryptographic quantity from a BIO
     * @throws ERR_OSSL_EVP_MD_CTX_NEW              EVP_MD context creation failed
     * @throws ERR_OSSL_EVP_SIGN_INIT               EVP_MD signing initialization failed
     * @throws ERR_OSSL_EVP_SIGN_UPDATE             EVP_MD signing update failed
     * @throws ERR_OSSL_EVP_SIGN_FINAL              EVP_MD signing final failed
     * @throws ERR_NON_POSITIVE_BUFFER_SIZE         The signed server's STSM authentication value size is non-positive
     * @throws ERR_OSSL_AES_128_CBC_PT_TOO_LARGE    The signed server's STSM authentication value size is too large
     * @throws ERR_OSSL_EVP_CIPHER_CTX_NEW          EVP_CIPHER context creation failed
     * @throws ERR_OSSL_EVP_ENCRYPT_INIT            EVP_CIPHER encrypt initialization failed
     * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE          EVP_CIPHER encrypt update failed
     * @throws ERR_OSSL_EVP_ENCRYPT_FINAL           EVP_CIPHER encrypt final failed
     * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
     * @throws ERR_OSSL_PEM_WRITE_BIO_X509          Failed to write the server's X.509 certificate to the BIO
     */
    void send_srv_auth();


    /* --------------------------- 'CLI_AUTH' Message (3/4) --------------------------- */

    /**
     * @brief         Attempts to retrieve a client's long-term RSA public key from its ".pem" file
     * @param cliName The client's (candidate) name
     * @return        The client's long-term RSA public key
     * @throws ERR_LOGIN_PUBKEYFILE_NOT_FOUND   No public key file associated with such client name was found
     * @throws ERR_LOGIN_PUBKEYFILE_OPEN_FAILED Failed to open the client's public key file
     * @throws ERR_FILE_CLOSE_FAILED            Failed to close the client's public key file
     * @throws ERR_LOGIN_PUBKEY_INVALID         The contents of the client's public key file could not
     *                                          be interpreted as a valid RSA public key
     */
    static EVP_PKEY* getCliRSAPubKey(std::string& cliName);

    /**
     * @brief  Parses the client's 'CLI_AUTH' STSM message (3/4), consisting of:\n
     *            1) The client's name \n
     *            2) The client's STSM authentication proof, consisting of the concatenation
     *               of its name and both actors' ephemeral public DH keys (STSM authentication
     *               value) signed with the client's long-term private RSA key and encrypted
     *               with the resulting shared session key "{<name||Yc||Ys>s}k"\n
     * @throws ERR_STSM_SRV_CLIENT_LOGIN_FAILED Unrecognized client's username
     * @throws ERR_STSM_MY_PUBKEY_MISSING       The server's ephemeral DH public key is missing
     * @throws ERR_STSM_OTHER_PUBKEY_MISSING    The client's ephemeral DH public key is missing
     * @throws ERR_NON_POSITIVE_BUFFER_SIZE     The ciphertext size is non-positive (probable overflow)
     * @throws ERR_OSSL_EVP_CIPHER_CTX_NEW      EVP_CIPHER context creation failed
     * @throws ERR_OSSL_EVP_DECRYPT_INIT        EVP_CIPHER decrypt initialization failed
     * @throws ERR_OSSL_EVP_DECRYPT_UPDATE      EVP_CIPHER decrypt update failed
     * @throws ERR_OSSL_EVP_DECRYPT_FINAL       EVP_CIPHER decrypt final failed
     * @throws ERR_STSM_MALFORMED_MESSAGE       Erroneous size of the client's signed STSM authentication value
     * @throws ERR_OSSL_EVP_MD_CTX_NEW          EVP_MD context creation failed
     * @throws ERR_OSSL_EVP_VERIFY_INIT         EVP_MD verification initialization failed
     * @throws ERR_OSSL_EVP_VERIFY_UPDATE       EVP_MD verification update failed
     * @throws ERR_OSSL_EVP_VERIFY_FINAL        EVP_MD verification final failed
     * @throws ERR_STSM_SRV_CLI_AUTH_FAILED     Client STSM authentication failed
     */
    void recv_cli_auth();


    /* ---------------------------- 'SRV_OK' Message (4/4) ---------------------------- */

    /**
     * @brief Sends the 'SRV_OK' message to the client (4/4), consisting of
     *        just the notification that their authentication was successful
     *        and so that the connection can now switch to the session phase
     */
    void send_srv_ok();


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
     * @brief  Server STSM message handler, parsing a STSM message received from the
     *         client stored in the associated connection manager's primary buffer
     * @return A boolean indicating the associated connection manager whether the STSM
     *         key exchange protocol with the client has successfully completed and so
     *         connection can switch to the session phase ('true') or not ('false')
     * @throws All the STSM exceptions and most of the OpenSSL
     *         exceptions (see "execErrCode.h" for more details)
     */
    bool STSMMsgHandler();
 };


#endif //SAFECLOUD_SRVSTSMMGR_H
