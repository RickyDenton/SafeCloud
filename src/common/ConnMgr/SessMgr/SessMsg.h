#ifndef SAFECLOUD_SESSMSG_H
#define SAFECLOUD_SESSMSG_H

/* SafeCloud Session Messages Definitions */

/* ================================== INCLUDES ================================== */
#include <cstdint>

/* ================ SAFECLOUD SESSION MESSAGE TYPES DEFINITIONS ================ */
enum SessMsgType : uint8_t
 {
  /*
   * Session messages exchanged between the SafeCloud
   * client and server within a nominal execution
   */
  FILE_UPLOAD_REQ,    // File upload request    Client -> Server
  FILE_DOWNLOAD_REQ,  // File download request  Client -> Server
  FILE_DELETE_REQ,    // File delete request    Client -> Server
  FILE_RENAME_REQ,    // File rename request    Client -> Server
  FILE_LIST_REQ,      // File list request      Client -> Server
  CONFIRM,            // Operation confirmation Client -> Server
  CANCEL,             // Cancel the operation   Client -> Server

  FILE_EXISTS,      // A file with such name exists          Server -> Client
  FILE_NOT_EXISTS,  // A file with such name does not exist  Client -> Server

  OK,               // Operation completed successfully Client <-> Server


  /*
   * Session Error messages, sent by one party to the other upon
   * erroneous conditions in the Session messages' exchange (causing
   * both the sending and the receiving party to reset the session state)
   */

  // An unexpected session message was received (any)
  ERR_UNEXPECTED_SESS_MESSAGE,

  // A malformed session message was received (any)
  ERR_MALFORMED_SESS_MESSAGE,

  // A session message of unknown msgType was received (any)
  ERR_UNKNOWN_SESSMSG_TYPE
 };

/* ================== SAFECLOUD SESSION MESSAGES DEFINITIONS ================== */

// Base Session Message
struct __attribute__((packed)) SessMsg
 {
  uint16_t    msgLen;   // Total Session message length
  SessMsgType msgType;  // Session Message Type
 };

// Session Message Wrapper
struct SessMsgWrapper
 {
  uint16_t  wrapLen;                    // Total session message wrapper length in bytes
  // Session Message is encrypted here
  char      tag[AES_128_GCM_TAG_SIZE];  // AES_128_GCM Integrity Tag (16 bytes)
 };

/* ------------------------ 'FILE_UPLOAD_REQ' Message ------------------------ */

// Implicit msgType = 'FILE_UPLOAD_REQ'
struct __attribute__((packed)) SessMsgUploadReq : public SessMsg
 {
   // The size in bytes of the file to be uploaded
   uint32_t fileSize;

   // The name of the target file to be uploaded (placeholder, variable size)
   unsigned char fileName;
 };

#endif //SAFECLOUD_SESSMSG_H
