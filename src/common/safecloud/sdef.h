#ifndef SAFECLOUD_SDEF_H
#define SAFECLOUD_SDEF_H

/* SafeCloud application default parameters */

// #define DEBUG // TODO: REMOVE

/* ============================= SERVER PARAMETERS ============================= */
#define SRV_DEFAULT_IP   "127.0.0.1"     // The server's default IP address
#define SRV_PORT_MIN        49152        // The minimum value for the server's listening port (IANA standard for dynamic/private applications)
#define SRV_PORT_MAX        65534        // The maximum value for the server's listening port (IANA standard for dynamic/private applications)
#define SRV_DEFAULT_PORT    51234        // The server's default listening port
#define SRV_MAX_QUEUED_CONN 30           // The maximum number of incoming connection requests before further are refused (listen() argument)
#define SRV_MAX_CONN        FD_SETSIZE-1 // The maximum number of client connections before further are closed upon acceptance (select() limitation, 1024 (FD_SETSIZE) - 1 (Listening Socket))

/* ============================= CLIENT PARAMETERS ============================= */
#define CLI_NAME_MAX_LENGTH 30   // The maximum client name length (`\0' not included)

#endif //SAFECLOUD_SDEF_H
