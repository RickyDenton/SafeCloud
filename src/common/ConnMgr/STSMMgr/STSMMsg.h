#ifndef SAFECLOUD_STSMMSG_H
#define SAFECLOUD_STSMMSG_H

/* STSM Messages definitions */

/* ================================== INCLUDES ================================== */
#include <cstdint>
#include "defaults.h"
#include "ConnMgr/IV/IV.h"
#include <unordered_map>


/* ======================= STSM MESSAGE TYPES DEFINITIONS ======================= */

// STSM Message Types
enum STSMMsgType : uint8_t
 {
  /*
   * STSM handshake messages, exchanged between client
   * and server within a normal STSM execution
   */
  CLIENT_HELLO,  // 1/4) client -> server
  SRV_AUTH,      // 2/4) server -> client
  CLI_AUTH,      // 3/4) client -> server
  SRV_OK,        // 4/4) server -> client

  /*
   * STSM error messages, which are sent by one party to the other upon an erroneous
   * condition in the STSM handshake (and cause both parties to abort the connection)
   */

  // A peer has received an invalid EDH public key (possibly
  // sent by the server after receiving the 'CLI_HELLO' message
  // or by the client after receiving the 'SRV_AUTH' message)
  ERR_INVALID_PUBKEY,

  // The server failed its STSM challenge (possibly sent
  // by the client after receiving the 'SRV_AUTH' message)
  ERR_SRV_CHALLENGE_FAILED,

  // The client rejected the server's certificate (possibly
  // sent by the client after receiving the 'SRV_AUTH' message)
  ERR_SRV_CERT_REJECTED,

  // The client failed its STSM challenge (possibly sent
  // by the server after receiving the 'CLI_AUTH' message)
  ERR_CLI_CHALLENGE_FAILED,

  // Unrecognized username on the server (raised by
  // the client after receiving the 'CLI_AUTH' message)
  ERR_CLIENT_LOGIN_FAILED,

  // An out-of-order STSM message was received (any)
  ERR_UNEXPECTED_MESSAGE,

  // A malformed STSM message was received (any)
  ERR_MALFORMED_MESSAGE,

  // An unknown STSM message type was received (any)
  ERR_UNKNOWN_STSMMSG_TYPE
 };


/* ========================= STSM MESSAGES FIELDS SIZES ========================= */

// The size in bytes of a PEM-encoded DH 2048-bit public key
#define DH2048_PUBKEY_PEM_SIZE 1194

// The size in bits of an RSA digital signature
// generated using the SHA-256 hash-and-sign paradigm
#define RSA_SHA256_SIG_SIZE 256

// TODO: Add in the description somewhere
// An STSM authentication fragment consists of the AES_128_CBC encrypted
// digital signature of an actor's STSM authentication value ({<Ys||Yc>s}k
// for the server and {<name||Ys||Yc>c}k for the client),

// TODO: Possibly rewrite better
// The size in bits of an STSM authentication fragment, which is constant due to
// the fact that, being the size of an RSA digital signature on 256 bits an integer
// multiple of the AES block size of 128 bit, encrypting it always adds a full
// padding block of 128 bit, for a resulting ciphertext size of 256 + 128 = 384 bits
#define STSM_AUTH_SIZE 272


/* ========================= STSM MESSAGES DEFINITIONS ========================= */

/* ---------------------- Base STSM message (header only) ---------------------- */

// STSM Message header
struct STSMMsgHeader
 {
  uint16_t    len;   // Total STSM message length (header included)
  STSMMsgType type;  // STSM message type
 };

// STSM base message (mainly used for sending STSM error messages)
struct STSMMsg
 {
  public:
   STSMMsgHeader header; // STSM header
 };

/* ----------------------- 'CLIENT_HELLO' Message (1/4) ----------------------- */

// Implicit header STMMsgType: 'CLIENT_HELLO'
struct STSM_CLIENT_HELLO : public STSMMsg
 {
  public:

  // The client's ephemeral DH 2048-bit public key in PEM format
   unsigned char cliEDHPubKey[DH2048_PUBKEY_PEM_SIZE];

   // The starting IV value to be used by the server
   IV iv;
 };


/* ------------------------- 'SRV_AUTH' Message (2/4) ------------------------- */

struct STSM_SRV_AUTH : public STSMMsg
 {
  // The server's ephemeral DH 2048-bit public key in PEM format
  unsigned char srvEDHPubKey[DH2048_PUBKEY_PEM_SIZE];

  // The server's STSM authentication
  unsigned char srvSTSMAuth[STSM_AUTH_SIZE];

  // The server's X.509 certificate of variable size
  unsigned char srvCert[];
 };



// TODO

struct STSM_SRV_OK : public STSMMsg
 {};



#endif //SAFECLOUD_STSMMSG_H
