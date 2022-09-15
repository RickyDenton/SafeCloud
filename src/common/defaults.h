#ifndef SAFECLOUD_DEFAULTS_H
#define SAFECLOUD_DEFAULTS_H

/* SafeCloud application default parameter values */

// Enable for DEBUG mode
// TODO: Make as a run configuration
#define DEBUG

/* ============================= SERVER PARAMETERS ============================= */
#define SRV_DEFAULT_IP      "127.0.0.1"   // The server's default IP address
#define SRV_PORT_MIN        49152         // The minimum value for the server's listening port (IANA standard for dynamic/private applications)
#define SRV_DEFAULT_PORT    51234         // The server's default listening port
#define SRV_MAX_QUEUED_CONN 30            // The maximum number of incoming client connection requests before further are refused (listen() argument)
#define SRV_MAX_CONN        FD_SETSIZE-1  // The maximum number of concurrent client connections before further are rejected (select() limitation, 1024 (FD_SETSIZE) - 1 (Listening Socket))

/* ============================= CLIENT PARAMETERS ============================= */
#define USERNAME_MAX_LENGTH 30            // The maximum username length (`\0' not included)


#endif //SAFECLOUD_DEFAULTS_H
