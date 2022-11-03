#ifndef SAFECLOUD_STSMMSG_H
#define SAFECLOUD_STSMMSG_H

/* STSM Messages Definitions */

/* ================================== INCLUDES ================================== */
#include "defaults.h"
#include "SafeCloudApp/ConnMgr/IV/IV.h"

/* ======================= STSM MESSAGE TYPES DEFINITIONS ======================= */
enum STSMMsgType : uint8_t
 {
  /*
   * STSM handshake messages exchanged between client
   * and server within a normal STSM execution
   */
  CLIENT_HELLO,  // 1/4) Client -> Server
  SRV_AUTH,      // 2/4) Server -> Client
  CLI_AUTH,      // 3/4) Client -> Server
  SRV_OK,        // 4/4) Server -> Client

  /*
   * STSM Error messages, sent by one party to the other upon
   * erroneous conditions in the STSM handshake (causing both
   * the sending and the receiving party to abort the connection)
   */

  // The server received a STSM message from the client after
  // the predefined maximum delay from its previous message
  ERR_CLI_TIMEOUT,

  // A peer has received an invalid EDH public key (possibly
  // sent by the server after receiving the 'CLI_HELLO' message
  // or by the client after receiving the 'SRV_AUTH' message)
  ERR_INVALID_PUBKEY,

  // The server failed the STSM authentication (possibly sent
  // by the client after receiving the 'SRV_AUTH' message)
  ERR_SRV_AUTH_FAILED,

  // The client rejected the server's certificate (possibly
  // sent by the client after receiving the 'SRV_AUTH' message)
  ERR_SRV_CERT_REJECTED,

  // Unrecognized client username on the server (possibly sent
  // by the server after receiving the 'CLI_AUTH' message)
  ERR_CLIENT_LOGIN_FAILED,

  // The client failed the STSM authentication (possibly sent
  // by the server after receiving the 'CLI_AUTH' message)
  ERR_CLI_AUTH_FAILED,

  // An out-of-order STSM message was received (any)
  ERR_UNEXPECTED_MESSAGE,

  // A malformed STSM message was received (any)
  ERR_MALFORMED_MESSAGE,

  // An STSM message of unknown type was received (any)
  ERR_UNKNOWN_STSMMSG_TYPE
 };


/* ========================= STSM MESSAGES DEFINITIONS ========================= */

// The size in bytes of a PEM-encoded DH public key on 2048-bit
#define DH2048_PUBKEY_PEM_SIZE 1194

// The size in bytes of an RSA-2048 digital signature
#define RSA2048_SIG_SIZE 256

// The size in bytes of an STSM authentication proof, which is constant
// due to the size of an RSA-2048 digital signature (256 bytes) being
// a multiple of the AES block size, leading in turn to a full padding
// block of 128 bits = 16 bytes being always added in its encryption
#define STSM_AUTH_PROOF_SIZE 272

// STSM Message header
struct STSMMsgHeader
 {
  uint16_t    len;   // Total STSM message length in bytes (header included)
  STSMMsgType type;  // STSM message type
 };

/* ----------------------------- Base STSM message ----------------------------- */

// Base STSM Message, comprised of a STSM header only (mainly
// used for sending and receiving STSM error messages)
struct STSMMsg
 {
  public:
   STSMMsgHeader header;
 };

/* ----------------------- 'CLIENT_HELLO' Message (1/4) ----------------------- */

// Implicit header.type ='CLIENT_HELLO'
struct STSM_CLIENT_HELLO_MSG : public STSMMsg
 {
  public:

  // The client's ephemeral DH 2048-bit public key in PEM format
   unsigned char cliEDHPubKey[DH2048_PUBKEY_PEM_SIZE];

   // The initial random IV to be used in the secure communication
   IV iv;
 };

/* ------------------------- 'SRV_AUTH' Message (2/4) ------------------------- */

// Implicit header.type ='SRV_AUTH'
struct STSM_SRV_AUTH_MSG : public STSMMsg
 {
  // The server's ephemeral DH 2048-bit public key in PEM format
  unsigned char srvEDHPubKey[DH2048_PUBKEY_PEM_SIZE];

  // The server's STSM authentication proof
  unsigned char srvSTSMAuthProof[STSM_AUTH_PROOF_SIZE];

  // The server's X.509 certificate (of variable size in general)
  unsigned char srvCert[];
 };

/* ------------------------- 'CLI_AUTH' Message (3/4) ------------------------- */

// Implicit header.type ='CLI_AUTH'
struct STSM_CLI_AUTH_MSG : public STSMMsg
 {
  // The client's name
  unsigned char cliName[CLI_NAME_MAX_LENGTH + 1];

  // The client's STSM authentication proof
  unsigned char cliSTSMAuthProof[STSM_AUTH_PROOF_SIZE];
 };

/* -------------------------- 'SRV_OK' Message (4/4) -------------------------- */

// Implicit header.type ='SRV_OK'
struct STSM_SRV_OK_MSG : public STSMMsg
 {};


#endif //SAFECLOUD_STSMMSG_H