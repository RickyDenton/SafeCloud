#ifndef SAFECLOUD_SCODE_H
#define SAFECLOUD_SCODE_H

/* SafeCloud application status codes definitions and descriptions */

#include <unordered_map>

/* ============================== TYPE DEFINITIONS ============================== */

// SafeCloud application status codes definitions
enum scode
 {
  // Operation Successful
  OK = 0,

  /* -------------------------- SERVER-SPECIFIC ERRORS -------------------------- */

  // Listening Socket
  ERR_LSK_INIT_FAILED,
  ERR_LSK_OPT_FAILED,
  ERR_LSK_BIND_FAILED,
  ERR_LSK_LISTEN_FAILED,
  ERR_LSK_CLOSE_FAILED,

  // Connection Sockets
  ERR_CSK_ACCEPT_FAILED,
  ERR_CSK_MAX_CONN,

  // Clients
  ERR_CLI_CONN_ERROR,

  // Guests
  ERR_GST_ECONNRESET,

  // Users
  ERR_USR_ECONNRESET,

  // Other
  ERR_SELECT_FAILED,


  /* -------------------------- CLIENT-SPECIFIC ERRORS -------------------------- */

  // X.509 Store Creation
  ERR_CA_CERT_OPEN_FAILED,
  ERR_CA_CERT_CLOSE_FAILED,
  ERR_CA_CERT_INVALID,
  ERR_CA_CRL_OPEN_FAILED,
  ERR_CA_CRL_CLOSE_FAILED,
  ERR_CA_CRL_INVALID,
  ERR_STORE_INIT_FAILED,
  ERR_STORE_ADD_CACERT_FAILED,
  ERR_STORE_ADD_CACRL_FAILED,
  ERR_STORE_REJECT_REVOKED_FAILED,

  // Client Login
  ERR_LOGIN_PWD_TOO_LONG,
  ERR_LOGIN_PRIVKFILE_NOT_FOUND,
  ERR_LOGIN_PRIVKFILE_OPEN_FAILED,
  ERR_LOGIN_PRIVKFILE_CLOSE_FAILED,
  ERR_LOGIN_PRIVK_INVALID,
  ERR_DOWNDIR_NOT_FOUND,
  ERR_CLIENT_ALREADY_CONNECTED,

  // Connection socket
  ERR_CSK_INIT_FAILED,
  ERR_CSK_CONN_FAILED,
  ERR_SRV_ECONNRESET,
  ERR_CLIENT_ALREADY_LOGGED_IN,

  /* ----------------------- CLIENT-SERVER COMMON ERRORS ----------------------- */

  // Server Connection Parameters
  ERR_INVALID_SRV_ADDR,
  ERR_INVALID_SRV_PORT,

  // Connection Sockets
  ERR_CSK_CLOSE_FAILED,
  ERR_CSK_RECV_FAILED,

  // Files and Directories
  ERR_TMPDIR_NOT_FOUND,
  ERR_TMPDIR_OPEN_FAILED,
  ERR_TMPFILE_DELETE_FAILED,
  ERR_TMPDIR_CLOSE_FAILED,

  // Client Login
  ERR_LOGIN_NAME_TOO_LONG,
  ERR_LOGIN_NAME_WRONG_FORMAT,
  ERR_LOGIN_NAME_INVALID_CHARS,
  ERR_LOGIN_WRONG_NAME_OR_PWD,

  // Unknown error
  ERR_UNKNOWN = -1
 };


// SafeCloud Severity Levels
enum severityLvl
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

    // Listening Socket
    { ERR_LSK_INIT_FAILED,   {FATAL,"Listening Socket Creation Failed"} },
    { ERR_LSK_OPT_FAILED,    {FATAL,"Listening Socket Options Setting Failed"} },
    { ERR_LSK_BIND_FAILED,   {FATAL,"Listening Socket Binding Failed"} },
    { ERR_LSK_LISTEN_FAILED, {FATAL,"Listening Socket Listen Failed"} },
    { ERR_LSK_CLOSE_FAILED,  {FATAL,"Listening Socket Closing Failed"} },

    // Connection Sockets
    { ERR_CSK_ACCEPT_FAILED, {FATAL,"Connection Socket Accept Failed"} },
    { ERR_CSK_MAX_CONN,      {WARNING,"Maximum number of client connections reached, an incoming guest connection has been refused"} },

    // Other
    { ERR_SELECT_FAILED,     {FATAL,"Select Failed"} },

    /* -------------------------- CLIENT-SPECIFIC ERRORS -------------------------- */

    // Server Connection Parameters
    { ERR_INVALID_SRV_ADDR,            {ERROR,"The SafeCloud Server IP address is invalid"} },
    { ERR_INVALID_SRV_PORT,            {ERROR,"The SafeCloud Server port is invalid"} },

    // X.509 Store Creation
    { ERR_CA_CERT_OPEN_FAILED,         {FATAL,"The CA certificate file could not be opened"} },
    { ERR_CA_CERT_CLOSE_FAILED,        {FATAL,"The CA certificate file could not be closed"} },
    { ERR_CA_CERT_INVALID,             {FATAL,"The CA certificate file does not contain a valid X.509 certificate"} },
    { ERR_CA_CRL_OPEN_FAILED,          {FATAL,"The CA CRL file could not be opened"} },
    { ERR_CA_CRL_CLOSE_FAILED,         {FATAL,"The CA CRL file could not be opened"} },
    { ERR_CA_CRL_INVALID,              {FATAL,"The CA CRL file does not contain a valid X.509 certificate revocation list"} },
    { ERR_STORE_INIT_FAILED,           {FATAL,"Error in initializing the X.509 certificates store"} },
    { ERR_STORE_ADD_CACERT_FAILED,     {FATAL,"Error in adding the CA certificate to the X.509 store"} },
    { ERR_STORE_ADD_CACRL_FAILED,      {FATAL,"Error in adding the CA CRL to the X.509 store"} },
    { ERR_STORE_REJECT_REVOKED_FAILED, {FATAL,"Error in configuring the store so to reject revoked certificates"} },

    // Client Login
    { ERR_LOGIN_PWD_TOO_LONG,           {ERROR,"The user-provided password is too long"} },
    { ERR_LOGIN_PRIVKFILE_NOT_FOUND,    {ERROR,"The user RSA private key file was not found"} },
    { ERR_LOGIN_PRIVKFILE_OPEN_FAILED,  {ERROR,"Error in opening the user's RSA private key file"} },
    { ERR_LOGIN_PRIVKFILE_CLOSE_FAILED, {CRITICAL,"Error in closing the user's RSA private key file"} },
    { ERR_LOGIN_PRIVK_INVALID,          {CRITICAL,"The contents of the user's private key file could not be interpreted as a valid RSA key pair"} },
    { ERR_DOWNDIR_NOT_FOUND,            {CRITICAL,"The client's download directory was not found"} },
    { ERR_CLIENT_ALREADY_LOGGED_IN,     {ERROR,"The client is already locally logged in in the SafeCloud application"} },

    // Connection Socket
    { ERR_CSK_INIT_FAILED,          {FATAL,"Connection Socket Creation Failed"} },
    { ERR_CSK_CONN_FAILED,          {FATAL,"Fatal error in connecting with the server"} },
    { ERR_SRV_ECONNRESET,           {WARNING,"The Server abruptly closed the connection"} },
    { ERR_CLIENT_ALREADY_CONNECTED, {ERROR,"The client is already connected to the SafeCloud server"} },

    /* ----------------------- CLIENT-SERVER COMMON ERRORS ----------------------- */

    // Connection sockets
    { ERR_CSK_CLOSE_FAILED,  {FATAL,"Connection Socket Close Failed"} },
    { ERR_CSK_RECV_FAILED,   {FATAL,"Error in reading data from connection socket"} },

    // Files and Directories
    { ERR_TMPDIR_NOT_FOUND,      {CRITICAL,"The client's temporary directory was not found"} },
    { ERR_TMPDIR_OPEN_FAILED,    {CRITICAL,"Error in opening the temporary directory"} },
    { ERR_TMPFILE_DELETE_FAILED, {CRITICAL,"Error in deleting the temporary file"} },
    { ERR_TMPDIR_CLOSE_FAILED,   {CRITICAL,"Error in opening the temporary directory"} },

    // Client Login
    { ERR_LOGIN_NAME_TOO_LONG,      {ERROR,"The user-provided name is too long"} },
    { ERR_LOGIN_NAME_WRONG_FORMAT,  {ERROR,"The user-provided name is of invalid format"} },
    { ERR_LOGIN_NAME_INVALID_CHARS, {ERROR,"The user-provided name contains invalid characters"} },
    { ERR_LOGIN_WRONG_NAME_OR_PWD,  {ERROR,"Wrong username or password"} },

    // Unknown
    { ERR_UNKNOWN, {CRITICAL,"Unknown Error"} }
  };


#endif //SAFECLOUD_SCODE_H