#ifndef SAFECLOUD_STSMMSG_H
#define SAFECLOUD_STSMMSG_H

#include <cstdint>
#include "defaults.h"
#include "ConnMgr/IVMgr/IVMgr.h"

/* Messages between client and server exchanged in the STSM protocol */

// STSM Message Type
enum STSMMsgType : uint8_t
 {
  // Protocol messages
  CLIENT_HELLO,
  SRV_AUTH,
  CLI_AUTH,
  SRV_OK,

  // Error messages (all shut down the connection)
  MALFORMED_MSG,
  CHALLENGE_FAILED,
  CERT_REJECTED,
  LOGIN_FAILED,
  UNKNOWN_TYPE
 };


// STSM Message Header
struct STSMMsgHeader
 {
  uint16_t    len;   // Total message length (header included)
  STSMMsgType type;  // Message Type
 };


// Generic STSM Message
struct STSMMsg
 {
  public:
   STSMMsgHeader header;
 };



#define DH2048_PUBKEY_PEM_SIZE 1194

// Client Hello Message
struct STSM_Client_Hello : public STSMMsg
 {
  public:
   unsigned char cliPubKey[DH2048_PUBKEY_PEM_SIZE];
   IVMgr iv;
 };




#endif //SAFECLOUD_STSMMSG_H
