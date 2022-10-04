#ifndef SAFECLOUD_DEFAULTS_H
#define SAFECLOUD_DEFAULTS_H

/* SafeCloud application default parameter values */

/* ============================= SHARED PARAMETERS ============================= */

// Connection Buffers
#define CONN_BUF_SIZE (4 * 1024 * 1024)   // 4 MB

// Client Object Parameters
#define CLI_NAME_MAX_LENGTH 30            // The username maximum length (`\0' not included)
#define CLI_PWD_MAX_LENGTH 30             // The user password maximum length (`\0' not included)

// Server Connection Parameters
#define SRV_DEFAULT_IP      "127.0.0.1"   // The server's default IP address
#define SRV_DEFAULT_PORT    51234         // The server's default listening port
#define SRV_PORT_MIN        49152         // The minimum value for the server's listening port (IANA standard for dynamic/private applications)


/* ============================= SERVER PARAMETERS ============================= */

/* ----------------------- Server Connection Parameters ----------------------- */

#define SRV_MAX_QUEUED_CONN 30            // The maximum number of incoming client connection requests before further are refused (listen() argument)
#define SRV_MAX_CONN        FD_SETSIZE-1  // The maximum number of concurrent client connections before further are rejected (select() limitation, 1024 (FD_SETSIZE) - 1 (Listening Socket))
#define SRV_PSELECT_TIMEOUT 1             // The server's pselect() timeout in seconds

/* -------------------------- Server Files Parameters -------------------------- */

// Server Cryptographic files
#define SRV_CRYPTO_DIR_PATH             "./crypto/"
#define SRV_PRIVK_PATH                  SRV_CRYPTO_DIR_PATH "SafeCloud_privk_clear.pem"
#define SRV_CERT_PATH                   SRV_CRYPTO_DIR_PATH "SafeCloud_cert.pem"

// User Files
#define SRV_USERS_DIR_PATH               "./users/"
#define SRV_USER_HOME_PATH(username)     SRV_USERS_DIR_PATH + username + "/"
#define SRV_USER_POOL_PATH(username)     SRV_USER_HOME_PATH(username) + "pool/"
#define SRV_USER_PUBK_DIR_PATH(username) SRV_USER_HOME_PATH(username) + "pubk/"
#define SRV_USER_PUBK_PATH(username)     SRV_USER_PUBK_DIR_PATH(username) + username + "_pubk.pem"
#define SRV_USER_TEMP_DIR_PATH(username) SRV_USER_HOME_PATH(username) + "temp/"


/* ============================= CLIENT PARAMETERS ============================= */

/* -------------------------- Client Files Parameters -------------------------- */

// Client Login
#define CLI_MAX_LOGIN_ATTEMPTS 3

// CA Files
#define CLI_CA_DIR_PATH                  "./CA/"
#define CLI_CA_CERT_PATH                 CLI_CA_DIR_PATH "BertCA_cert.pem"
#define CLI_CA_CRL_PATH                  CLI_CA_DIR_PATH "BertCA_crl.pem"

// Users Files
#define CLI_USERS_DIR_PATH                "./users/"
#define CLI_USER_HOME_PATH(username)      CLI_USERS_DIR_PATH + username + "/"
#define CLI_USER_DOWN_PATH(username)      CLI_USER_HOME_PATH(username) + "downloads/"
#define CLI_USER_PRIVK_DIR_PATH(username) CLI_USER_HOME_PATH(username) + "privk/"
#define CLI_USER_PRIVK_PATH(username)     CLI_USER_PRIVK_DIR_PATH(username) + username + "_privk.pem"
#define CLI_USER_TEMP_DIR_PATH(username)  CLI_USER_HOME_PATH(username) + "temp/"


#endif //SAFECLOUD_DEFAULTS_H
