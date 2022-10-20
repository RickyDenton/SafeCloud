#ifndef SAFECLOUD_SESSMSG_H
#define SAFECLOUD_SESSMSG_H

/* SafeCloud Session Messages Definitions */

/* ================================== INCLUDES ================================== */
#include <cstdint>

/* ================ SAFECLOUD SESSION MESSAGE TYPES DEFINITIONS ================ */
enum SessMsgType : uint8_t
 {
  /* ---------------------- Payload Session Message Types ---------------------- */
  FILE_UPLOAD_REQ,    // File upload request                       (Client -> Server)
  FILE_DOWNLOAD_REQ,  // File download request                     (Client -> Server)
  FILE_DELETE_REQ,    // File delete request                       (Client -> Server)
  FILE_RENAME_REQ,    // File rename request                       (Client -> Server)
  FILE_EXISTS,        // A file with such name already exists      (Client <- Server)
  POOL_INFO,          // Number of files in the storage pool       (Client <- Server)

  /* -------------- Signaling Session Message Types (No Payload) -------------- */

  /* ---- Non-error Signaling Session Messages ---- */
  FILE_LIST_REQ,       // Storage pool contents list request       (Client -> Server)
  FILE_NOT_EXISTS,     // A file with such name does not exist     (Client <- Server)
  NEW_FILENAME_EXISTS, // A file with the new name already exists  (Client <- Server)
  CONFIRM,             // Session operation confirmation           (Client -> Server)
  CANCEL,              // Session operation cancellation           (Client -> Server)
  COMPLETED,           // Session operation completion             (Client <-> Server)
  BYE,                 // Peer graceful disconnection              (Client <-> Server)

  /* ------ Error Signaling Session Messages ------ */

  /*
   * These messages, that can be sent by both parties,
   * cause upon reception the current session command
   * to be aborted and the session state to be reset
   */

  // An internal error has occurred on the peer
  ERR_INTERNAL_ERROR,

  // The peer received a session message invalid for its current state
  ERR_UNEXPECTED_SESS_MESSAGE,

  // The peer received a malformed session message
  ERR_MALFORMED_SESS_MESSAGE,

  // The peer received a session message of unknown type, an error
  // to be attributed to a desynchronization between the connection
  // peers' IVs and that requires their connection to be reset
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

/* ------------------------ 'FILE_INFO Session Message ------------------------ */

// Used with msgType = FILE_UPLOAD_REQ, FILE_EXISTS

struct __attribute__((packed)) SessMsgFileInfo : public SessMsg
 {
  long int fileSize;         // The file size in bytes
  long int lastModTime;      // The file last modification time in UNIX epochs
  long int creationTime;     // The file creation time in UNIX epochs
  unsigned char fileName[];  // The file name (variable size)
 };

#endif //SAFECLOUD_SESSMSG_H
