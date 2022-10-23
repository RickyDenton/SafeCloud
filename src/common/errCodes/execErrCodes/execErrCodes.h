#ifndef SAFECLOUD_EXECERRCODES_H
#define SAFECLOUD_EXECERRCODES_H

/**
 * SafeCloud application execution error codes declarations
 *
 * These errors cause the TCP connection between the SafeCloud client and server, if present,
 * to be aborted (and the application to be terminated for errors of FATAL severity)
 */

/* ================================== INCLUDES ================================== */
#include <unordered_map>
#include "errCodes/errCodes.h"

/* ====================== SAFECLOUD EXECUTION ERROR CODES ====================== */

enum execErrCode : unsigned char
 {
  /* ------------------------ SERVER-SPECIFIC ERRORS ------------------------ */

  // Server Private Key File
  ERR_SRV_PRIVKFILE_NOT_FOUND,
  ERR_SRV_PRIVKFILE_OPEN_FAILED,
  ERR_SRV_PRIVK_INVALID,

  // Server Certificate
  ERR_SRV_CERT_OPEN_FAILED,
  ERR_SRV_CERT_INVALID,

  // Listening Socket
  ERR_LSK_INIT_FAILED,
  ERR_LSK_SO_REUSEADDR_FAILED,
  ERR_LSK_BIND_FAILED,
  ERR_LSK_LISTEN_FAILED,
  ERR_SRV_ALREADY_STARTED,
  ERR_LSK_CLOSE_FAILED,

  // Connection Sockets
  ERR_CSK_ACCEPT_FAILED,
  ERR_CSK_MAX_CONN,
  ERR_CSK_MISSING_MAP,
  ERR_CLI_DISCONNECTED,

  // STSM Server Errors
  ERR_STSM_SRV_CLI_INVALID_PUBKEY,
  ERR_STSM_SRV_SRV_INVALID_PUBKEY,
  ERR_STSM_SRV_SRV_AUTH_FAILED,
  ERR_STSM_SRV_SRV_CERT_REJECTED,
  ERR_STSM_SRV_CLIENT_LOGIN_FAILED,
  ERR_STSM_SRV_CLI_AUTH_FAILED,
  ERR_STSM_SRV_UNEXPECTED_MESSAGE,
  ERR_STSM_SRV_MALFORMED_MESSAGE,
  ERR_STSM_SRV_UNKNOWN_STSMMSG_TYPE,

  // Client Login
  ERR_LOGIN_PUBKEYFILE_NOT_FOUND,
  ERR_LOGIN_PUBKEYFILE_OPEN_FAILED,
  ERR_LOGIN_PUBKEY_INVALID,

  // Other
  ERR_SRV_PSELECT_FAILED,
  ERR_SESS_SRV_CLI_UNKNOWN_SESSMSG_TYPE,


  /* ------------------------ CLIENT-SPECIFIC ERRORS ------------------------ */

  // X.509 Store Creation
  ERR_CA_CERT_OPEN_FAILED,
  ERR_CA_CERT_INVALID,
  ERR_CA_CRL_OPEN_FAILED,
  ERR_CA_CRL_INVALID,
  ERR_STORE_INIT_FAILED,
  ERR_STORE_ADD_CACERT_FAILED,
  ERR_STORE_ADD_CACRL_FAILED,
  ERR_STORE_REJECT_REVOKED_FAILED,

  // Client Login
  ERR_LOGIN_PWD_EMPTY,
  ERR_LOGIN_PWD_TOO_LONG,
  ERR_LOGIN_PRIVKFILE_NOT_FOUND,
  ERR_LOGIN_PRIVKFILE_OPEN_FAILED,
  ERR_LOGIN_PRIVK_INVALID,
  ERR_DOWNDIR_NOT_FOUND,
  ERR_CLI_LOGIN_FAILED,

  // Connection socket
  ERR_CSK_INIT_FAILED,
  ERR_SRV_UNREACHABLE,
  ERR_CSK_CONN_FAILED,
  ERR_SRV_DISCONNECTED,

  // STSM Client errors
  ERR_STSM_CLI_ALREADY_STARTED,
  ERR_STSM_CLI_CLI_INVALID_PUBKEY,
  ERR_STSM_CLI_SRV_INVALID_PUBKEY,
  ERR_STSM_CLI_SRV_AUTH_FAILED,
  ERR_STSM_CLI_SRV_CERT_REJECTED,
  ERR_STSM_CLI_CLI_AUTH_FAILED,
  ERR_STSM_CLI_CLIENT_LOGIN_FAILED,
  ERR_STSM_CLI_UNEXPECTED_MESSAGE,
  ERR_STSM_CLI_MALFORMED_MESSAGE,
  ERR_STSM_CLI_UNKNOWN_STSMMSG_TYPE,

  // Other errors
  ERR_SESS_CLI_SRV_UNKNOWN_SESSMSG_TYPE,
  ERR_SESS_SRV_GRACEFUL_DISCONNECT,
  ERR_SESS_UNRECOVERABLE_INTERNAL_ERROR,

  /* --------------------- CLIENT-SERVER COMMON ERRORS --------------------- */

  // Server Connection Parameters
  ERR_SRV_ADDR_INVALID,
  ERR_SRV_PORT_INVALID,

  // Connection Sockets
  ERR_CSK_CLOSE_FAILED,
  ERR_CSK_RECV_FAILED,
  ERR_PEER_DISCONNECTED,
  ERR_SEND_FAILED,
  ERR_SEND_OVERFLOW,
  ERR_MSG_LENGTH_INVALID,

  // Files and Directories
  ERR_DIR_OPEN_FAILED,
  ERR_DIR_CLOSE_FAILED,

  ERR_FILE_OPEN_FAILED,
  ERR_FILE_READ_FAILED,
  ERR_FILE_WRITE_FAILED,
  ERR_FILE_DELETE_FAILED,
  ERR_FILE_TOO_LARGE,
  ERR_FILE_CLOSE_FAILED,
  ERR_FILE_UNEXPECTED_SIZE,


  // Client Login
  ERR_LOGIN_NAME_EMPTY,
  ERR_LOGIN_NAME_TOO_LONG,
  ERR_LOGIN_NAME_WRONG_FORMAT,
  ERR_LOGIN_NAME_INVALID_CHARS,
  ERR_LOGIN_WRONG_NAME_OR_PWD,

  // OpenSSL Errors
  ERR_OSSL_EVP_PKEY_NEW,
  ERR_OSSL_EVP_PKEY_ASSIGN,
  ERR_OSSL_EVP_PKEY_CTX_NEW,
  ERR_OSSL_EVP_PKEY_KEYGEN_INIT,
  ERR_OSSL_EVP_PKEY_KEYGEN,

  ERR_OSSL_RAND_POLL_FAILED,
  ERR_OSSL_RAND_BYTES_FAILED,

  ERR_OSSL_BIO_NEW_FAILED,
  ERR_OSSL_BIO_NEW_FP_FAILED,
  ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED,
  ERR_OSSL_EVP_PKEY_PRINT_PUBLIC_FAILED,
  ERR_OSSL_BIO_READ_FAILED,
  ERR_OSSL_BIO_FREE_FAILED,

  ERR_OSSL_EVP_PKEY_DERIVE_INIT,
  ERR_OSSL_EVP_PKEY_DERIVE_SET_PEER,
  ERR_OSSL_EVP_PKEY_DERIVE,

  ERR_OSSL_EVP_MD_CTX_NEW,
  ERR_OSSL_EVP_DIGEST_INIT,
  ERR_OSSL_EVP_DIGEST_UPDATE,
  ERR_OSSL_EVP_DIGEST_FINAL,

  ERR_OSSL_EVP_SIGN_INIT,
  ERR_OSSL_EVP_SIGN_UPDATE,
  ERR_OSSL_EVP_SIGN_FINAL,

  ERR_OSSL_AES_128_CBC_PT_TOO_LARGE,
  ERR_OSSL_EVP_CIPHER_CTX_NEW,
  ERR_OSSL_EVP_ENCRYPT_INIT,
  ERR_OSSL_EVP_ENCRYPT_UPDATE,
  ERR_OSSL_EVP_ENCRYPT_FINAL,

  ERR_OSSL_PEM_WRITE_BIO_X509,
  ERR_OSSL_X509_STORE_CTX_NEW,
  ERR_OSSL_X509_STORE_CTX_INIT,

  ERR_OSSL_EVP_VERIFY_INIT,
  ERR_OSSL_EVP_VERIFY_UPDATE,
  ERR_OSSL_EVP_VERIFY_FINAL,
  ERR_OSSL_SIG_VERIFY_FAILED,

  ERR_OSSL_EVP_DECRYPT_INIT,
  ERR_OSSL_EVP_DECRYPT_UPDATE,
  ERR_OSSL_EVP_DECRYPT_FINAL,

  ERR_OSSL_GET_TAG_FAILED,
  ERR_OSSL_SET_TAG_FAILED,


  // STSM Generic Errors
  ERR_STSM_UNEXPECTED_MESSAGE,
  ERR_STSM_MALFORMED_MESSAGE,
  ERR_STSM_UNKNOWN_STSMMSG_TYPE,
  ERR_STSM_UNKNOWN_STSMMSG_ERROR,
  ERR_STSM_MY_PUBKEY_MISSING,
  ERR_STSM_OTHER_PUBKEY_MISSING,

  // Objects Invalid States
  ERR_CONNMGR_INVALID_STATE,
  ERR_AESGCMMGR_INVALID_STATE,

  // Other errors
  ERR_MALLOC_FAILED,
  ERR_NON_POSITIVE_BUFFER_SIZE,
  ERR_SESS_UNKNOWN_SESSMSG_TYPE,

  // Unknown execution error
  ERR_EXEC_UNKNOWN
 };


/* ================== SAFECLOUD EXECUTION ERROR CODES INFO MAP ================== */

// Associates each SafeCloud execution error code with its severity level and human-readable description
static const std::unordered_map<execErrCode,errCodeInfo> execErrCodeInfoMap =
  {
    /* -------------------------- SERVER-SPECIFIC ERRORS -------------------------- */

    // Server Private Key File
    { ERR_SRV_PRIVKFILE_NOT_FOUND,    {FATAL,"The server RSA private key file was not found"} },
    { ERR_SRV_PRIVKFILE_OPEN_FAILED,  {FATAL,"Error in opening the server's RSA private key file"} },
    { ERR_SRV_PRIVK_INVALID,          {FATAL,"The contents of the server's private key file could not be interpreted as a valid RSA key pair"} },

    // Server Certificate
    { ERR_SRV_CERT_OPEN_FAILED,    {FATAL,"The server certificate file could not be opened"} },
    { ERR_SRV_CERT_INVALID,        {FATAL,"The server certificate file does not contain a valid X.509 certificate"} },

    // Listening Socket
    { ERR_LSK_INIT_FAILED,        {FATAL,"Listening Socket Initialization Failed"} },
    { ERR_LSK_SO_REUSEADDR_FAILED,{FATAL,"Failed to set the listening socket's SO_REUSEADDR option"} },
    { ERR_LSK_BIND_FAILED,        {FATAL,"Failed to bind the listening socket on the specified OS port"} },
    { ERR_LSK_LISTEN_FAILED,      {FATAL,"Failed to listen on the listening socket"} },
    { ERR_SRV_ALREADY_STARTED,    {CRITICAL,"The server has already started listening on its listening socket"} },
    { ERR_LSK_CLOSE_FAILED,       {FATAL,"Listening Socket Closing Failed"} },

    // Connection Sockets
    { ERR_CSK_ACCEPT_FAILED, {CRITICAL,"Failed to accept an incoming client connection"} },
    { ERR_CSK_MAX_CONN,      {WARNING, "Maximum number of client connections reached, an incoming client connection has been rejected"} },
    { ERR_CSK_MISSING_MAP,   {CRITICAL,"Connection socket with available input data is missing from the connections' map"} },
    { ERR_CLI_DISCONNECTED,  {WARNING, "Abrupt client disconnection"} },

    // STSM Server Errors
    { ERR_STSM_SRV_CLI_INVALID_PUBKEY,   {CRITICAL,"The client has provided an invalid ephemeral public key in the STSM protocol"} },
    { ERR_STSM_SRV_SRV_INVALID_PUBKEY,   {CRITICAL,"The client reported that the server provided an invalid ephemeral public key in the STSM protocol"} },
    { ERR_STSM_SRV_SRV_AUTH_FAILED,      {ERROR, "The client reported the server failing the STSM authentication"} },
    { ERR_STSM_SRV_SRV_CERT_REJECTED,    {ERROR,"The client rejected the server's X.509 certificate"} },
    { ERR_STSM_SRV_CLIENT_LOGIN_FAILED,  {ERROR,"Unrecognized username in the STSM protocol"} },
    { ERR_STSM_SRV_CLI_AUTH_FAILED,      {ERROR, "The client has failed the STSM authentication"} },
    { ERR_STSM_SRV_UNEXPECTED_MESSAGE,   {CRITICAL,"The client reported to have received an out-of-order STSM message"} },
    { ERR_STSM_SRV_MALFORMED_MESSAGE,    {ERROR,"The client reported to have received a malformed STSM message"} },
    { ERR_STSM_SRV_UNKNOWN_STSMMSG_TYPE, {ERROR,"The client reported to have received an STSM message of unknown type"} },

    // Client Login
    { ERR_LOGIN_PUBKEYFILE_NOT_FOUND,    {ERROR,   "The user RSA private key file was not found"} },
    { ERR_LOGIN_PUBKEYFILE_OPEN_FAILED,  {CRITICAL,"Error in opening the client's RSA public key file"} },
    { ERR_LOGIN_PUBKEY_INVALID,          {CRITICAL,"The contents of the client's RSA public key file do not represent a valid RSA public key"} },

    // Other
    { ERR_SRV_PSELECT_FAILED,                {FATAL,"Server pselect() failed"} },
    { ERR_SESS_SRV_CLI_UNKNOWN_SESSMSG_TYPE, {CRITICAL,"The client reported to have received a session message of unknown type"} },

    /* -------------------------- CLIENT-SPECIFIC ERRORS -------------------------- */

    // X.509 Store Creation
    { ERR_CA_CERT_OPEN_FAILED,         {FATAL,"The CA certificate file could not be opened"} },
    { ERR_CA_CERT_INVALID,             {FATAL,"The CA certificate file does not contain a valid X.509 certificate"} },
    { ERR_CA_CRL_OPEN_FAILED,          {FATAL,"The CA CRL file could not be opened"} },
    { ERR_CA_CRL_INVALID,              {FATAL,"The CA CRL file does not contain a valid X.509 certificate revocation list"} },
    { ERR_STORE_INIT_FAILED,           {FATAL,"Error in initializing the X.509 certificates store"} },
    { ERR_STORE_ADD_CACERT_FAILED,     {FATAL,"Error in adding the CA certificate to the X.509 store"} },
    { ERR_STORE_ADD_CACRL_FAILED,      {FATAL,"Error in adding the CA CRL to the X.509 store"} },
    { ERR_STORE_REJECT_REVOKED_FAILED, {FATAL,"Error in configuring the store so to reject revoked certificates"} },

    // Client Login
    { ERR_LOGIN_PWD_EMPTY,              {ERROR,   "The user-provided password is empty"} },
    { ERR_LOGIN_PWD_TOO_LONG,           {ERROR,   "The user-provided password is too long"} },
    { ERR_LOGIN_PRIVKFILE_NOT_FOUND,    {ERROR,   "The user RSA private key file was not found"} },
    { ERR_LOGIN_PRIVKFILE_OPEN_FAILED,  {ERROR,   "Error in opening the user's RSA private key file"} },
    { ERR_LOGIN_PRIVK_INVALID,          {ERROR,   "The contents of the user's private key file could not be interpreted as a valid RSA key pair"} },
    { ERR_DOWNDIR_NOT_FOUND,            {CRITICAL,"The client's download directory was not found"} },
    { ERR_CLI_LOGIN_FAILED,             {CRITICAL,"Maximum number of login attempts reached, please try again later"} },

    // Connection Socket
    { ERR_CSK_INIT_FAILED,   {FATAL,  "Connection socket creation failed"} },
    { ERR_SRV_UNREACHABLE,   {WARNING,"Failed to connect with the SafeCloud server"} },
    { ERR_CSK_CONN_FAILED,   {FATAL,  "Fatal error in connecting with the SafeCloud server"} },
    { ERR_SRV_DISCONNECTED,  {WARNING, "The server has abruptly disconnected"} },

    // STSM Client Errors
    { ERR_STSM_CLI_ALREADY_STARTED,      {CRITICAL,"The client has already started the STSM key exchange protocol"} },
    { ERR_STSM_CLI_CLI_INVALID_PUBKEY,   {CRITICAL,"The server reported that the client provided an invalid ephemeral public key in the STSM protocol"} },
    { ERR_STSM_CLI_SRV_INVALID_PUBKEY,   {CRITICAL,"The server has provided an invalid ephemeral public key in the STSM protocol"} },
    { ERR_STSM_CLI_SRV_AUTH_FAILED,      {CRITICAL,"The server has failed the STSM authentication"} },
    { ERR_STSM_CLI_SRV_CERT_REJECTED,    {ERROR,   "The server provided an invalid X.509 certificate"} },
    { ERR_STSM_CLI_CLIENT_LOGIN_FAILED,  {ERROR,   "The server did not recognize the username in the STSM protocol"} },
    { ERR_STSM_CLI_CLI_AUTH_FAILED,      {CRITICAL,"The server reported the client failing the STSM authentication"} },
    { ERR_STSM_CLI_UNEXPECTED_MESSAGE,   {FATAL,   "The server reported to have received an out-of-order STSM message"} },
    { ERR_STSM_CLI_MALFORMED_MESSAGE,    {FATAL,   "The server reported to have received a malformed STSM message"} },
    { ERR_STSM_CLI_UNKNOWN_STSMMSG_TYPE, {FATAL,   "The server reported to have received an STSM message of unknown type"} },

    // Other Errors
    { ERR_SESS_CLI_SRV_UNKNOWN_SESSMSG_TYPE, {CRITICAL,"The server reported to have received a session message of unknown type"} },
    { ERR_SESS_SRV_GRACEFUL_DISCONNECT,      {WARNING,"The server has gracefully disconnected"} },
    { ERR_SESS_UNRECOVERABLE_INTERNAL_ERROR, {CRITICAL,"Unrecoverable session internal error"} },

    /* ----------------------- CLIENT-SERVER COMMON ERRORS ----------------------- */

    // Server Endpoint Parameters
    {ERR_SRV_ADDR_INVALID,        {ERROR,"The SafeCloud Server IP address is invalid"} },
    {ERR_SRV_PORT_INVALID,         {ERROR,    "The SafeCloud Server port is invalid"} },

    // Connection sockets
    {ERR_CSK_CLOSE_FAILED,         {CRITICAL, "Connection Socket Close Failed"} },
    {ERR_CSK_RECV_FAILED,          {CRITICAL, "Error in receiving data from the connection socket"} },
    {ERR_PEER_DISCONNECTED,        {WARNING,  "Abrupt peer disconnection"} },
    {ERR_SEND_FAILED,              {FATAL,    "Error in sending data on the connection socket"} },
    {ERR_SEND_OVERFLOW,            {FATAL,    "Attempting to send() more bytes than the primary connection buffer size"} },
    {ERR_MSG_LENGTH_INVALID,       {FATAL,    "Received an invalid message length value"} },

    // Files and Directories
    {ERR_DIR_OPEN_FAILED,    {CRITICAL, "The directory was not found"} },
    {ERR_DIR_CLOSE_FAILED,   {CRITICAL, "Error in closing the directory"} },

    {ERR_FILE_OPEN_FAILED,     {CRITICAL, "The file was not found"} },
    {ERR_FILE_READ_FAILED,     {CRITICAL, "Error in reading from the file"} },
    {ERR_FILE_WRITE_FAILED,    {CRITICAL, "Error in writing to the file"} },
    {ERR_FILE_DELETE_FAILED,   {CRITICAL, "Error in deleting the file"} },
    {ERR_FILE_TOO_LARGE,       {CRITICAL, "The file is too large"} },
    {ERR_FILE_CLOSE_FAILED,    {CRITICAL, "Error in closing the file"} },
    {ERR_FILE_UNEXPECTED_SIZE, {CRITICAL, "An unexpected number of bytes were read from the file"} },





    // Client Login
    {ERR_LOGIN_NAME_EMPTY,         {ERROR,    "The user-provided name is empty"} },
    {ERR_LOGIN_NAME_TOO_LONG,      {ERROR,    "The user-provided name is too long"} },
    {ERR_LOGIN_NAME_WRONG_FORMAT,  {ERROR,    "The user-provided name is of invalid format"} },
    {ERR_LOGIN_NAME_INVALID_CHARS, {ERROR,    "The user-provided name contains invalid characters"} },
    {ERR_LOGIN_WRONG_NAME_OR_PWD,  {ERROR,    "Wrong username or password"} },

    // OpenSSL Errors
    {ERR_OSSL_EVP_PKEY_NEW,        {FATAL,    "EVP_PKEY struct creation failed"} },
    { ERR_OSSL_EVP_PKEY_ASSIGN,              {FATAL,"EVP_PKEY struct assignment failure"} },
    { ERR_OSSL_EVP_PKEY_CTX_NEW,             {FATAL,"EVP_PKEY context creation failed"} },
    { ERR_OSSL_EVP_PKEY_KEYGEN_INIT,         {FATAL,"EVP_PKEY key generation initialization failed"} },
    { ERR_OSSL_EVP_PKEY_KEYGEN,              {FATAL,"EVP_PKEY Key generation failed"} },

    { ERR_OSSL_RAND_POLL_FAILED,             {FATAL,"Could not generate a seed via the RAND_poll() function"} },
    { ERR_OSSL_RAND_BYTES_FAILED,            {FATAL,"Could not generate random bytes via the RAND_bytes() function"} },

    { ERR_OSSL_BIO_NEW_FAILED,               {FATAL,"OpenSSL Memory BIO Initialization Failed"} },
    { ERR_OSSL_BIO_NEW_FP_FAILED,            {CRITICAL,"OpenSSL File BIO Initialization Failed"} },
    { ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED,  {FATAL,    "Could not write the ephemeral DH public key to the designated memory BIO"} },
    { ERR_OSSL_EVP_PKEY_PRINT_PUBLIC_FAILED, {CRITICAL, "Could not write the ephemeral DH public key to the designated file BIO"} },
    { ERR_OSSL_BIO_READ_FAILED,              {FATAL,    "Could not read the OpenSSL BIO"} },
    { ERR_OSSL_BIO_FREE_FAILED,              {CRITICAL, "Could not free the OpenSSL BIO"} },

    { ERR_OSSL_EVP_PKEY_DERIVE_INIT,         {FATAL, "Key derivation context initialization failed"} },
    { ERR_OSSL_EVP_PKEY_DERIVE_SET_PEER,     {FATAL, "Failed to set the remote actor's public key in the key derivation context"} },
    { ERR_OSSL_EVP_PKEY_DERIVE,              {FATAL, "Shared secret derivation failed"} },

    { ERR_OSSL_EVP_MD_CTX_NEW,               {FATAL, "EVP_MD context creation failed"} },
    { ERR_OSSL_EVP_DIGEST_INIT,              {FATAL, "EVP_MD digest initialization failed"} },
    { ERR_OSSL_EVP_DIGEST_UPDATE,            {FATAL, "EVP_MD digest update failed"} },
    { ERR_OSSL_EVP_DIGEST_FINAL,             {FATAL, "EVP_MD digest final failed"} },

    { ERR_OSSL_EVP_SIGN_INIT,                {FATAL, "EVP_MD signing initialization failed"} },
    { ERR_OSSL_EVP_SIGN_UPDATE,              {FATAL, "EVP_MD signing update failed"} },
    { ERR_OSSL_EVP_SIGN_FINAL,               {FATAL, "EVP_MD signing final failed"} },

    { ERR_OSSL_AES_128_CBC_PT_TOO_LARGE,     {FATAL, "The plaintext to encrypt using AES_128_CBC is too large"} },
    { ERR_OSSL_EVP_CIPHER_CTX_NEW,           {FATAL, "EVP_CIPHER context creation failed"} },
    { ERR_OSSL_EVP_ENCRYPT_INIT,             {FATAL, "EVP_CIPHER encrypt initialization failed"} },
    { ERR_OSSL_EVP_ENCRYPT_UPDATE,           {FATAL, "EVP_CIPHER encrypt update failed"} },
    { ERR_OSSL_EVP_ENCRYPT_FINAL,            {FATAL, "EVP_CIPHER encrypt final failed"} },

    { ERR_OSSL_PEM_WRITE_BIO_X509,           {FATAL, "Could not write the server's X.509 certificate to the memory BIO"} },
    { ERR_OSSL_X509_STORE_CTX_NEW,           {FATAL, "X509_STORE context creation failed"} },
    { ERR_OSSL_X509_STORE_CTX_INIT,          {FATAL, "X509_STORE context initialization failed"} },

    { ERR_OSSL_EVP_VERIFY_INIT,                {FATAL, "EVP_MD verification initialization failed"} },
    { ERR_OSSL_EVP_VERIFY_UPDATE,              {FATAL, "EVP_MD verification update failed"} },
    { ERR_OSSL_EVP_VERIFY_FINAL,               {FATAL, "EVP_MD verification final failed"} },
    { ERR_OSSL_SIG_VERIFY_FAILED,              {CRITICAL,"Signature Verification Failed"} },

    { ERR_OSSL_EVP_DECRYPT_INIT,             {FATAL, "EVP_CIPHER decrypt initialization failed"} },
    { ERR_OSSL_EVP_DECRYPT_UPDATE,           {FATAL, "EVP_CIPHER decrypt update failed"} },
    { ERR_OSSL_EVP_DECRYPT_FINAL,            {FATAL, "EVP_CIPHER decrypt final failed"} },
    { ERR_OSSL_GET_TAG_FAILED,               {FATAL, "Failed to retrieve the encryption operation's AES_128_GCM tag"} },
    { ERR_OSSL_SET_TAG_FAILED,               {FATAL, "Failed to set the decryption operation's expected AES_128_GCM tag"} },


    // STSM Generic Errors
    {ERR_STSM_UNEXPECTED_MESSAGE,   {CRITICAL, "An out-of-order STSM message has been received"} },
    {ERR_STSM_MALFORMED_MESSAGE,    {CRITICAL, "A malformed STSM message has been received"} },
    {ERR_STSM_UNKNOWN_STSMMSG_TYPE, {CRITICAL, "A STSM message of unknown type has been received"} },
    {ERR_STSM_UNKNOWN_STSMMSG_ERROR,{FATAL,    "Attempting to send an STSM error message of unknown type"} },
    {ERR_STSM_MY_PUBKEY_MISSING,    {FATAL,    "The local actor's ephemeral DH public key is missing"} },
    {ERR_STSM_OTHER_PUBKEY_MISSING, {FATAL,    "The remote actor's ephemeral DH public key is missing"} },

    // Objects Invalid States
    {ERR_CONNMGR_INVALID_STATE,     {CRITICAL, "Invalid ConnMgr state"} },
    {ERR_AESGCMMGR_INVALID_STATE,   {CRITICAL, "Invalid AES_128_GCM manager state"} },

    // Other errors
    {ERR_MALLOC_FAILED,              {FATAL,"malloc() failed"} },
    {ERR_NON_POSITIVE_BUFFER_SIZE,   {FATAL,"A non-positive buffer size was passed (probable overflow)"} },
    {ERR_SESS_UNKNOWN_SESSMSG_TYPE,  {CRITICAL,"A session message of unknown type has been received"} },

    // Unknown execution error
    {ERR_EXEC_UNKNOWN,                          {CRITICAL, "Unknown Execution Error"} }
  };


/* =================== SAFECLOUD EXECUTION ERRORS EXCEPTION  =================== */

/**
 * @brief An exception class associated with an execution error code
 *        (execErrCode) and an optional additional description an reason
 */
class execErrExcp : public errExcp
 {
   public:

    /* ========================= Attributes ========================= */
    enum execErrCode exErrcode;  // The exception's execution error code (severity >= WARNING)

  /* ================= Constructors and Destructor ================= */

#ifdef DEBUG_MODE
  /* ------------------- DEBUG_MODE Constructors ------------------- */

  // execErrCode-only constructor (with implicit source file name and line)
  execErrExcp(const enum execErrCode exCode, std::string* srcFileName, const unsigned int line)
    : errExcp(srcFileName,line), exErrcode(exCode)
   {}

  // execErrCode + additional description constructor (with implicit source file name and line)
  execErrExcp(const enum execErrCode exCode, std::string* addDescr, std::string* srcFileName, const unsigned int line)
    : errExcp(addDescr,srcFileName,line), exErrcode(exCode)
   {}

  // execErrCode + additional description + reason constructor (with implicit source file name and line)
  execErrExcp(const enum execErrCode exCode, std::string* addDescr, std::string* errReason, std::string* srcFileName, const unsigned int line)
    : errExcp(addDescr,errReason, srcFileName,line), exErrcode(exCode)
   {}
#else
  /* ----------------- Non-DEBUG_MODE Constructors ----------------- */

  // execErrCode-only constructor
  explicit execErrExcp(const enum execErrCode execCode)
    : errExcp(), exErrcode(execCode)
   {}

  // execErrCode + additional description constructor
  execErrExcp(const enum execErrCode execCode, std::string* addDescr)
    : errExcp(addDescr), exErrcode(execCode)
   {}

  // execErrCode + additional description + reason constructor
  execErrExcp(const enum execErrCode execCode, std::string* addDescr, std::string* errReason)
    : errExcp(addDescr,errReason), exErrcode(execCode)
   {}
#endif
 };


/* ======================= EXECUTION ERRORS HANDLING MACROS ======================= */

/*
 * NOTE: The dynamic strings allocated in these macros are deallocated
 *       within the SafeCloud default error handler (handleErrCode() function)
 */

/* --------------------------- Execution Errors Logging --------------------------- */

/**
 * LOG_EXEC_CODE_ macros, calling the handleExecErrCode() function with the arguments passed to the LOG_EXEC_CODE macro:
 *  - 1 argument   -> execErrCode only
 *  - 2 arguments  -> execErrCode + additional description
 *  - 3 arguments  -> execErrCode + additional description + error reason
 *  - (DEBUG_MODE) -> The source file name and line number at which the exception is thrown
 */
#ifdef DEBUG_MODE
 #define LOG_EXEC_CODE_ONLY(execErrCode) handleExecErrCode(execErrCode,nullptr,nullptr,new std::string(__FILE__),__LINE__-1)
 #define LOG_EXEC_CODE_DSCR(execErrCode,dscr) handleExecErrCode(execErrCode,new std::string(dscr),nullptr,new std::string(__FILE__),__LINE__-1)
 #define LOG_EXEC_CODE_DSCR_REASON(execErrCode,dscr,reason) handleExecErrCode(execErrCode,new std::string(dscr),new std::string(reason),new std::string(__FILE__),__LINE__-1)
#else
#define LOG_EXEC_CODE_ONLY(execErrCode) handleExecErrCode(execErrCode,nullptr,nullptr)
 #define LOG_EXEC_CODE_DSCR(execErrCode,dscr) handleExecErrCode(execErrCode,new std::string(dscr),nullptr)
 #define LOG_EXEC_CODE_DSCR_REASON(execErrCode,dscr,reason) handleExecErrCode(execErrCode,new std::string(dscr),new std::string(reason))
#endif

/**
 * Substitutes the appropriate LOG_EXEC_CODE_ depending on the number of arguments passed to the LOG_EXEC_CODE variadic macro:
 *  - 1 argument  -> execErrCode only
 *  - 2 arguments -> execErrCode + additional description
 *  - 3 arguments -> execErrCode + additional description + error reason
 */
#define GET_LOG_EXEC_CODE_MACRO(_1,_2,_3,LOG_EXEC_CODE_MACRO,...) LOG_EXEC_CODE_MACRO
#define LOG_EXEC_CODE(...) GET_LOG_EXEC_CODE_MACRO(__VA_ARGS__,LOG_EXEC_CODE_DSCR_REASON,LOG_EXEC_CODE_DSCR,LOG_EXEC_CODE_ONLY)(__VA_ARGS__)


/* --------------------- Execution Error Exceptions Throwing --------------------- */

/**
 * THROW_EXEC_EXCP_ macros, passing their arguments to the matching execErrExcp exception constructor
 *  - 1 argument   -> execErrCode only
 *  - 2 arguments  -> execErrCode + additional description
 *  - 3 arguments  -> execErrCode + additional description + error reason
 *  - (DEBUG_MODE) -> The source file name and line number at which the execErrExcp has been thrown
 */
#ifdef DEBUG_MODE
#define THROW_EXEC_EXCP_CODE_ONLY(execErrCode) throw execErrExcp(execErrCode,new std::string(__FILE__),__LINE__-1)
 #define THROW_EXEC_EXCP_DSCR(execErrCode,dscr) throw execErrExcp(execErrCode,new std::string(dscr),new std::string(__FILE__),__LINE__-1)
 #define THROW_EXEC_EXCP_DSCR_REASON(execErrCode,dscr,reason) throw execErrExcp(execErrCode,new std::string(dscr),new std::string(reason),new std::string(__FILE__),__LINE__-1)
#else
#define THROW_EXEC_EXCP_CODE_ONLY(execErrCode) throw execErrExcp(execErrCode)
 #define THROW_EXEC_EXCP_DSCR(execErrCode,dscr) throw execErrExcp(execErrCode,new std::string(dscr))
 #define THROW_EXEC_EXCP_DSCR_REASON(execErrCode,dscr,reason) throw execErrExcp(execErrCode,new std::string(dscr),new std::string(reason))
#endif


/**
 * Substitutes the appropriate THROW_EXEC_EXCP_ macro depending on the number of arguments passed to the THROW_EXEC_EXCP variadic macro:
 *  - 1 argument  -> execErrCode only
 *  - 2 arguments -> execErrCode + additional description
 *  - 3 arguments -> execErrCode + additional description + error reason
 */
#define GET_THROW_EXEC_EXCP_MACRO(_1,_2,_3,THROW_EXEC_EXCP_MACRO,...) THROW_EXEC_EXCP_MACRO
#define THROW_EXEC_EXCP(...) GET_THROW_EXEC_EXCP_MACRO(__VA_ARGS__,THROW_EXEC_EXCP_DSCR_REASON,THROW_EXEC_EXCP_DSCR,THROW_EXEC_EXCP_CODE_ONLY)(__VA_ARGS__)


/* ============== EXECUTION ERRORS HANDLING FUNCTIONS DECLARATIONS ============== */

/**
 * @brief             Execution error codes handler, passing its information to the SafeCloud application default error handler
 * @param execErrCode The execution error code that has occurred
 * @param addDsc      The additional execution error description (optional)
 * @param reason      The execution error reason (optional)
 * @param srcFile     (DEBUG MODE ONLY) The source file where the execution error has occurred
 * @param lineNumber  (DEBUG MODE ONLY) The line number at which the execution error has occurred
 */
#ifdef DEBUG_MODE
void handleExecErrCode(execErrCode exeErrCode, const std::string* addDscr, const std::string* reason, const std::string* srcFile, unsigned int lineNumber);
#else
void handleExecErrCode(execErrCode exeErrCode,const std::string* addDscr,const std::string* reason);
#endif


/**
 * @brief            Execution error exceptions default handler, passing the exception's
 *                   information to the handleExecErrCode() execution code error handler
 * @param exeErrExcp The execErrExcp exception that was caught
 */
void handleExecErrException(const execErrExcp& exeErrExcp);


#endif //SAFECLOUD_EXECERRCODES_H