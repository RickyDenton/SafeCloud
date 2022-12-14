#ifndef SAFECLOUD_SESSMSG_H
#define SAFECLOUD_SESSMSG_H

/* SafeCloud Session Messages Definitions */

/* ================ SAFECLOUD SESSION MESSAGE TYPES DEFINITIONS ================ */
enum SessMsgType : uint8_t
 {
  /* ---------------------- Payload Session Message Types ---------------------- */

  // ------------ Operation-Starting Payload Session Message Types ------------ //
  FILE_UPLOAD_REQ,    // File upload request                      (Client -> Server)
  FILE_DOWNLOAD_REQ,  // File download request                    (Client -> Server)
  FILE_DELETE_REQ,    // File delete request                      (Client -> Server)
  FILE_RENAME_REQ,    // File rename request                      (Client -> Server)

  // ------------------- Other Payload Session Message Types ------------------- //
  FILE_EXISTS,        // A file with such name already exists     (Client <- Server)
  POOL_SIZE,          // Client storage pool information raw size (Client <- Server)

  /* -------------- Signaling Session Message Types (no payload) -------------- */

  // ----------- Operation-Starting Signaling Session Message Types ----------- //
  FILE_LIST_REQ,       // Storage pool contents list request       (Client -> Server)

  // ------------ Other Non-error Signaling Session Message Types ------------ //
  FILE_NOT_EXISTS,     // A file with such name does not exist     (Client <- Server)
  CONFIRM,             // Session operation confirmation           (Client -> Server)
  CANCEL,              // Session operation cancellation           (Client -> Server)
  COMPLETED,           // Session operation completion             (Client <-> Server)
  BYE,                 // Peer graceful disconnection              (Client <-> Server)

  // ------------------ Error Signaling Session Message Types ------------------ //

  /*
   * Error signaling session message types can be sent by both parties
   * in any operation and state, and cause upon reception the current
   * operation to be aborted and the session state to be reset
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
  uint16_t  wrapLen;                      // Total session message wrapper length in bytes
  /*  Encrypted Session Message Here  */
  char      tag[AES_128_GCM_TAG_SIZE];    // AES_128_GCM Integrity Tag (16 bytes)
 };

/* -------------------- 'SessMsgFileInfo' Session Message -------------------- */

// Used with type = FILE_UPLOAD_REQ, FILE_EXISTS

struct __attribute__((packed)) SessMsgFileInfo : public SessMsg
 {
  long int fileSize;         // The file size in bytes
  long int lastModTime;      // The file last modification time in UNIX epochs
  long int creationTime;     // The file creation time in UNIX epochs
  unsigned char fileName[];  // The file name (variable size)
 };

/* -------------------- 'SessMsgFileName' Session Message -------------------- */

// Used with type = FILE_DOWNLOAD_REQ, FILE_DELETE_REQ

struct __attribute__((packed)) SessMsgFileName : public SessMsg
 {
  unsigned char fileName[];  // The file name, '/0' character included (variable size)
 };

/* ------------------- 'SessMsgFileRename' Session Message ------------------- */

// Used with type = FILE_RENAME_REQ

struct __attribute__((packed)) SessMsgFileRename : public SessMsg
 {
  unsigned char oldFilenameLen;  // The old file name length
  unsigned char oldFileName;     // The old file name, '/0' character included (placeholder, variable size)
  unsigned char newFileName;     // The new file name, '/0' character included (placeholder, variable size)
 };

/* -------------------- 'SessMsgPoolSize' Session Message -------------------- */

// Used with type = POOL_SIZE

struct __attribute__((packed)) SessMsgPoolSize : public SessMsg
 {
  unsigned int serPoolSize;  // The serialized contents' size of a user's storage pool
 };


/* ================= OTHER SAFECLOUD SESSION TYPE DEFINITIONS ================= */

// The serialized information on a file in a user's storage pool

struct __attribute__((packed)) PoolFileInfo
 {
  unsigned char filenameLen;      // The file name length ('\0' excluded)
  long int      fileSizeRaw;      // The file size in bytes (max 9999GB)
  long int      lastModTimeRaw;   // The file last modification time in UNIX epochs
  long int      creationTimeRaw;  // The file creation time in UNIX epoch
  char          filename[];       // The file name
 };


#endif //SAFECLOUD_SESSMSG_H