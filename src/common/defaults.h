#ifndef SAFECLOUD_DEFAULTS_H
#define SAFECLOUD_DEFAULTS_H

/* SafeCloud Client and Server Default Parameters */

/* ============================= SERVER PARAMETERS ============================= */

/* ----------------------- Server Connection Parameters ----------------------- */

// The maximum number of pending client
// connections (listen() argument)
#define SRV_MAX_QUEUED_CONN 30

// The maximum number of concurrent client connections
// (select() limitation, 1024 (FD_SETSIZE) - 1 (Listening Socket))
#define SRV_MAX_CONN (FD_SETSIZE-1)

/* ----------------------- Server Files Paths Parameters ----------------------- */

// ------------------------ Server Cryptographic Files ------------------------ //
#define SRV_CRYPTO_DIR_PATH             "./crypto/"
#define SRV_PRIVK_PATH                  SRV_CRYPTO_DIR_PATH "SafeCloud_privk_clear.pem"
#define SRV_CERT_PATH                   SRV_CRYPTO_DIR_PATH "SafeCloud_cert.pem"

// ------------------------- Server Users Directories ------------------------- //
#define SRV_USERS_DIR_PATH               "./users/"
#define SRV_USER_HOME_PATH(username)     (SRV_USERS_DIR_PATH + username + "/")
#define SRV_USER_POOL_PATH(username)     SRV_USER_HOME_PATH(username) + "pool/"
#define SRV_USER_PUBK_DIR_PATH(username) SRV_USER_HOME_PATH(username) + "pubk/"
#define SRV_USER_PUBK_PATH(username)     SRV_USER_PUBK_DIR_PATH(username) + username + "_pubk.pem"
#define SRV_USER_TEMP_DIR_PATH(username) SRV_USER_HOME_PATH(username) + "temp/"


/* ============================= CLIENT PARAMETERS ============================= */

/* ----------------------- Client Connection Parameters ----------------------- */

// Maximum user login attempts after which the Client application shuts down
#define CLI_MAX_LOGIN_ATTEMPTS 3

/* ----------------------- Client Files Paths Parameters ----------------------- */

// ------------------------------ Client CA Files ------------------------------ //
#define CLI_CA_DIR_PATH                  "./CA/"
#define CLI_CA_CERT_PATH                 CLI_CA_DIR_PATH "BertCA_cert.pem"
#define CLI_CA_CRL_PATH                  CLI_CA_DIR_PATH "BertCA_crl.pem"

// ------------------------- Client Users Directories ------------------------- //
#define CLI_USERS_DIR_PATH                "./users/"
#define CLI_USER_HOME_PATH(username)      (CLI_USERS_DIR_PATH + username + "/")
#define CLI_USER_DOWN_PATH(username)      CLI_USER_HOME_PATH(username) + "downloads/"
#define CLI_USER_PRIVK_DIR_PATH(username) CLI_USER_HOME_PATH(username) + "privk/"
#define CLI_USER_PRIVK_PATH(username)     CLI_USER_PRIVK_DIR_PATH(username) + username + "_privk.pem"
#define CLI_USER_TEMP_DIR_PATH(username)  CLI_USER_HOME_PATH(username) + "temp/"


/* ====================== CLIENT-SERVER COMMON PARAMETERS ====================== */

/* ----------------------- Server Connection Parameters ----------------------- */
#define SRV_DEFAULT_IP   "127.0.0.1"  // The server's default IP address
#define SRV_DEFAULT_PORT 51234        // The server's default listening port
#define SRV_PORT_MIN     49152        // The minimum value for the server's listening port
                                      // (IANA standard for dynamic/private applications)

/* ------------------------ User Credentials Parameters ------------------------ */
#define CLI_NAME_MAX_LENGTH 30        // The username maximum length (`\0' not included)
#define CLI_PWD_MAX_LENGTH  30        // The user password maximum length (`\0' not included)

/* --------------------- Application Constraint Parameters --------------------- */
#define FILE_UPLOAD_MAX_SIZE 4294967295  // File upload maximum size (4GB - 1B, 2^32 - 1)


#endif //SAFECLOUD_DEFAULTS_H