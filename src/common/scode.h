#ifndef SAFECLOUD_SCODE_H
#define SAFECLOUD_SCODE_H

/* SafeCloud application status codes definitions and descriptions */

#include <unordered_map>

/* ============================== TYPE DEFINITIONS ============================== */

// SafeCloud application status codes definitions
enum scode : unsigned char
 {
  // Operation Successful
  OK = 0,

  /* -------------------------- SERVER-SPECIFIC ERRORS -------------------------- */

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


  /* -------------------------- CLIENT-SPECIFIC ERRORS -------------------------- */

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



  /* ----------------------- CLIENT-SERVER COMMON ERRORS ----------------------- */

  // Server Connection Parameters
  ERR_SRV_ADDR_INVALID,
  ERR_SRV_PORT_INVALID,

  // Connection Sockets
  ERR_CSK_CLOSE_FAILED,
  ERR_CSK_RECV_FAILED,
  ERR_PEER_DISCONNECTED,

  // Files and Directories
  ERR_FILE_CLOSE_FAILED,
  ERR_TMPDIR_NOT_FOUND,
  ERR_TMPDIR_OPEN_FAILED,
  ERR_TMPFILE_DELETE_FAILED,

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



  // STSM Generic Errors
  ERR_STSM_UNEXPECTED_MESSAGE,
  ERR_STSM_MALFORMED_MESSAGE,
  ERR_STSM_UNKNOWN_STSMMSG_TYPE,
  ERR_STSM_UNKNOWN_STSMMSG_ERROR,
  ERR_STSM_MY_PUBKEY_MISSING,
  ERR_STSM_OTHER_PUBKEY_MISSING,

  // Other errors
  ERR_MALLOC_FAILED,
  ERR_NON_POSITIVE_BUFFER_SIZE,



  // Unknown error
  ERR_UNKNOWN
 };




// SafeCloud Severity Levels
enum severityLvl : unsigned char
 {
  FATAL,     // Unrecoverable error, the application must be terminated
  CRITICAL,  // Unrecoverable error
  ERROR,     // Recoverable error
  WARNING,   // Unexpected event
  INFO,      // Informational content
  DEBUG      // Debug content
 };


// Used for associating a severity level and a
// human-readable description to SafeCloud status codes
struct scodeInfo
 {
  enum severityLvl sev;   // The scode severity level (FATAL to INFO)
  const char*      dscr;  // The scode human-readable description
 };


/* =========================== GLOBAL STATIC VARIABLES =========================== */

// Associates each SafeCloud status code with its severity level and human-readable description
static const std::unordered_map<scode,scodeInfo> scodeInfoMap =
  {
    // Operation Successful
    { OK, {DEBUG,"Operation Successful"}},

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
    { ERR_SRV_PSELECT_FAILED,     {FATAL,"Server pselect() failed"} },

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
    { ERR_CSK_INIT_FAILED,   {FATAL,  "Connection Socket Creation Failed"} },
    { ERR_SRV_UNREACHABLE,   {WARNING,"Failed to connected with the server"} },
    { ERR_CSK_CONN_FAILED,   {FATAL,  "Fatal error in connecting with the server"} },
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

    /* ----------------------- CLIENT-SERVER COMMON ERRORS ----------------------- */

    // Server Endpoint Parameters
    { ERR_SRV_ADDR_INVALID,  {ERROR,"The SafeCloud Server IP address is invalid"} },
    { ERR_SRV_PORT_INVALID,  {ERROR,"The SafeCloud Server port is invalid"} },

    // Connection sockets
    { ERR_CSK_CLOSE_FAILED,  {CRITICAL,"Connection Socket Close Failed"} },
    { ERR_CSK_RECV_FAILED,   {CRITICAL,"Error in receiving data from the connection socket"} },
    { ERR_PEER_DISCONNECTED,  {WARNING,"Abrupt peer disconnection"} },


    // Files and Directories
    { ERR_FILE_CLOSE_FAILED,     {CRITICAL,"Error in closing the file"} },
    { ERR_TMPDIR_NOT_FOUND,      {CRITICAL,"The client's temporary directory was not found"} },
    { ERR_TMPDIR_OPEN_FAILED,    {CRITICAL,"Error in opening the temporary directory"} },
    { ERR_TMPFILE_DELETE_FAILED, {CRITICAL,"Error in deleting the temporary file"} },

    // Client Login
    { ERR_LOGIN_NAME_EMPTY,         {ERROR,"The user-provided name is empty"} },
    { ERR_LOGIN_NAME_TOO_LONG,      {ERROR,"The user-provided name is too long"} },
    { ERR_LOGIN_NAME_WRONG_FORMAT,  {ERROR,"The user-provided name is of invalid format"} },
    { ERR_LOGIN_NAME_INVALID_CHARS, {ERROR,"The user-provided name contains invalid characters"} },
    { ERR_LOGIN_WRONG_NAME_OR_PWD,  {ERROR,"Wrong username or password"} },

    // OpenSSL Errors
    { ERR_OSSL_EVP_PKEY_NEW,                 {FATAL,"EVP_PKEY struct creation failed"} },
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



    // STSM Generic Errors
    {ERR_STSM_UNEXPECTED_MESSAGE,   {CRITICAL, "An out-of-order STSM message has been received"} },
    {ERR_STSM_MALFORMED_MESSAGE,    {CRITICAL, "A malformed STSM message has been received"} },
    {ERR_STSM_UNKNOWN_STSMMSG_TYPE, {CRITICAL, "A STSM message of unknown type has been received"} },
    {ERR_STSM_UNKNOWN_STSMMSG_ERROR,{FATAL,    "Attempting to send an STSM error message of unknown type"} },
    {ERR_STSM_MY_PUBKEY_MISSING,    {FATAL,    "The local actor's ephemeral DH public key is missing"} },
    {ERR_STSM_OTHER_PUBKEY_MISSING, {FATAL,    "The remote actor's ephemeral DH public key is missing"} },


    // Other errors
    {ERR_MALLOC_FAILED,                    {FATAL,"malloc() failed"} },
    {ERR_NON_POSITIVE_BUFFER_SIZE,         {FATAL,"A non-positive buffer size was passed (probable overflow)"} },

    // Unknown
    {ERR_UNKNOWN,                          {CRITICAL, "Unknown Error"} }
  };


#endif //SAFECLOUD_SCODE_H