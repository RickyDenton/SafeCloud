#ifndef SAFECLOUD_SESSERRCODES_H
#define SAFECLOUD_SESSERRCODES_H

/**
 * SafeCloud Session Error Codes Declarations
 *
 * These are non-fatal error that may occur in the session
 * phase, causing its state to be reset without aborting
 * the connection between the SafeCloud client and server
 */

/* ================================== INCLUDES ================================== */
#include <unordered_map>
#include "errCodes/errCodes.h"

/* ======================= SAFECLOUD SESSION ERROR CODES ======================= */

enum sessErrCode : unsigned char
 {
  /* -------------------------- SERVER-SPECIFIC ERRORS -------------------------- */

  // --------------------- Session Messages Server Errors --------------------- //
  ERR_SESS_SRV_CLI_INTERNAL_ERROR,
  ERR_SESS_SRV_CLI_UNEXPECTED_MESSAGE,
  ERR_SESS_SRV_CLI_MALFORMED_MESSAGE,


  /* -------------------------- CLIENT-SPECIFIC ERRORS -------------------------- */

  // Unsupported user session command
  ERR_UNSUPPORTED_CMD,

  // ----------------------- Session Files Client Errors ----------------------- //
  ERR_SESS_FILE_NOT_FOUND,
  ERR_SESS_FILE_READ_FAILED,
  ERR_SESS_FILE_IS_DIR,
  ERR_SESS_FILE_TOO_BIG,
  ERR_SESS_UPLOAD_DIR,
  ERR_SESS_UPLOAD_TOO_BIG,
  ERR_SESS_RENAME_SAME_NAME,

  // --------------------- Session Messages Client Errors --------------------- //
  ERR_SESS_CLI_SRV_INTERNAL_ERROR,
  ERR_SESS_CLI_SRV_UNEXPECTED_MESSAGE,
  ERR_SESS_CLI_SRV_MALFORMED_MESSAGE,


  /* ----------------------- CLIENT-SERVER COMMON ERRORS ----------------------- */

  // ----------------------- Session Files Common Errors ----------------------- //
  ERR_SESS_DIR_INFO_OVERFLOW,
  ERR_SESS_MAIN_FILE_IS_DIR,
  ERR_SESS_FILE_INVALID_NAME,
  ERR_SESS_FILE_META_NEGATIVE,
  ERR_SESS_FILE_INFO_COMP_NULL,
  ERR_SESS_FILE_INFO_COMP_DIFF_NAMES,
  ERR_SESS_FILE_OPEN_FAILED,
  ERR_SESS_FILE_DELETE_FAILED,
  ERR_SESS_FILE_META_SET_FAILED,
  ERR_SESS_FILE_CLOSE_FAILED,
  ERR_SESS_FILE_RENAME_FAILED,

  // --------------------- Session Messages Common Errors --------------------- //
  ERR_SESS_INTERNAL_ERROR,
  ERR_SESS_UNEXPECTED_MESSAGE,
  ERR_SESS_MALFORMED_MESSAGE,

  // -------------------------- Other Session Errors -------------------------- //
  ERR_OSSL_DECRYPT_VERIFY_FAILED,  // Session Wrapper Integrity Tag Verification Error
  ERR_SESS_UNKNOWN                 // Unknown session error
 };



/* =================== SAFECLOUD SESSION ERROR CODES INFO MAP =================== */

// Associates each SafeCloud session error code with its severity level and human-readable description
static const std::unordered_map<sessErrCode,errCodeInfo> sessErrCodeInfoMap =
  {

    /* -------------------------- SERVER-SPECIFIC ERRORS -------------------------- */

    // --------------------- Session Messages Server Errors --------------------- //
    { ERR_SESS_SRV_CLI_INTERNAL_ERROR,     {WARNING, "The client reported an internal error"}},
    { ERR_SESS_SRV_CLI_UNEXPECTED_MESSAGE, {ERROR,   "The client reported to have received an unexpected session message"}},
    { ERR_SESS_SRV_CLI_MALFORMED_MESSAGE,  {ERROR,   "The client reported to have received a malformed session message"}},


    /* -------------------------- CLIENT-SPECIFIC ERRORS -------------------------- */

    // Unsupported user session command
    { ERR_UNSUPPORTED_CMD, {INFO, "Unsupported command"}},

    // ----------------------- Session Files Client Errors ----------------------- //
    { ERR_SESS_FILE_NOT_FOUND,   {WARNING, "The file was not found"}},
    { ERR_SESS_FILE_READ_FAILED, {ERROR,   "Error in reading the file"}},
    { ERR_SESS_FILE_IS_DIR,      {WARNING, "The specified file is a directory"}},
    { ERR_SESS_FILE_TOO_BIG,     {WARNING, "The file is too big (> 4GB)"}},
    { ERR_SESS_UPLOAD_DIR,       {WARNING, "Uploading directories is currently not supported"}},
    { ERR_SESS_UPLOAD_TOO_BIG,   {WARNING, "The file is too big to be uploaded"}},
    { ERR_SESS_RENAME_SAME_NAME, {WARNING, "Renaming a file to itself would have no effect"}},

    // --------------------- Session Messages Client Errors --------------------- //
    { ERR_SESS_CLI_SRV_INTERNAL_ERROR,     {ERROR,    "The server reported an internal error"}},
    { ERR_SESS_CLI_SRV_UNEXPECTED_MESSAGE, {CRITICAL, "The server reported to have received an unexpected session message"}},
    { ERR_SESS_CLI_SRV_MALFORMED_MESSAGE,  {CRITICAL, "The server reported to have received a malformed session message"}},


    /* ----------------------- CLIENT-SERVER COMMON ERRORS ----------------------- */

    // ----------------------- Session Files Common Errors ----------------------- //
    { ERR_SESS_DIR_INFO_OVERFLOW,         {ERROR,    "Directory information size overflow (>4GB)"}},
    { ERR_SESS_MAIN_FILE_IS_DIR,          {CRITICAL, "Main file found as a sub-directory of the session's main directory"}},
    { ERR_SESS_FILE_INVALID_NAME,         {ERROR,    "The provided file name is invalid"}},
    { ERR_SESS_FILE_META_NEGATIVE,        {CRITICAL, "Attempting to initialize a file's metadata to negative values"}},
    { ERR_SESS_FILE_INFO_COMP_NULL,       {CRITICAL, "Attempting to compare the metadata of a a NULL FileInfo"}},
    { ERR_SESS_FILE_INFO_COMP_DIFF_NAMES, {CRITICAL, "Attempting to compare the metadata of two files of different names"}},
    { ERR_SESS_FILE_OPEN_FAILED,          {ERROR,    "The file could not be opened"}},
    { ERR_SESS_FILE_DELETE_FAILED,        {CRITICAL, "Error in deleting the file"}},
    { ERR_SESS_FILE_META_SET_FAILED,      {CRITICAL, "Error in setting the file's metadata"}},
    { ERR_SESS_FILE_CLOSE_FAILED,         {CRITICAL, "Error in closing the file"}},
    { ERR_SESS_FILE_RENAME_FAILED,        {CRITICAL, "Error in moving the file"}},

    // --------------------- Session Messages Common Errors --------------------- //
    { ERR_SESS_INTERNAL_ERROR,     {CRITICAL, "An internal error has occurred"}},
    { ERR_SESS_UNEXPECTED_MESSAGE, {ERROR,    "An unexpected session message was received"}},
    { ERR_SESS_MALFORMED_MESSAGE,  {ERROR,    "A malformed session message was received"}},

    // -------------------------- Other Session Errors -------------------------- //
    { ERR_OSSL_DECRYPT_VERIFY_FAILED, {ERROR,    "AES_GCM Tag verification failed"}},
    { ERR_SESS_UNKNOWN,               {CRITICAL, "Unknown Session Error"} }
  };


/* ==================== SAFECLOUD SESSION ERRORS EXCEPTION  ==================== */

/**
 * @brief An exception class associated with as session error code
 *        (sessErrCode) and an optional additional description an reason
 */
class sessErrExcp : public errExcp
 {
   public:

  /* ========================= Attributes ========================= */
  enum sessErrCode sesErrCode;  // The exception's execution error code (severity >= WARNING)

  /* ================= Constructors and Destructor ================= */

#ifdef DEBUG_MODE
  /* ------------------- DEBUG_MODE Constructors ------------------- */

  // sessErrCode-only constructor (with implicit source file name and line)
  sessErrExcp(const enum sessErrCode seErrCode, std::string* srcFileName, const unsigned int line)
    : errExcp(srcFileName,line), sesErrCode(seErrCode)
   {}

  // sessErrCode + additional description constructor (with implicit source file name and line)
  sessErrExcp(const enum sessErrCode seErrCode, std::string* addDescr, std::string* srcFileName, const unsigned int line)
    : errExcp(addDescr,srcFileName,line), sesErrCode(seErrCode)
   {}

  // sessErrCode + additional description + reason constructor (with implicit source file name and line)
  sessErrExcp(const enum sessErrCode seErrCode, std::string* addDescr, std::string* errReason, std::string* srcFileName, const unsigned int line)
    : errExcp(addDescr,errReason, srcFileName,line), sesErrCode(seErrCode)
   {}
#else
  /* ----------------- Non-DEBUG_MODE Constructors ----------------- */

  // sessErrCode-only constructor
  explicit sessErrExcp(const enum sessErrCode seErrCode)
    : errExcp(), sesErrCode(seErrCode)
   {}

  // sessErrCode + additional description constructor
  sessErrExcp(const enum sessErrCode seErrCode, std::string* addDescr)
    : errExcp(addDescr), sesErrCode(seErrCode)
   {}

  // sessErrCode + additional description + reason constructor
  sessErrExcp(const enum sessErrCode seErrCode, std::string* addDescr, std::string* errReason)
    : errExcp(addDescr,errReason), sesErrCode(seErrCode)
   {}
#endif
 };


/* ======================== SESSION ERRORS HANDLING MACROS ======================== */

/*
 * NOTE: The dynamic strings allocated in these macros are deallocated
 *       within the SafeCloud default error handler (handleErrCode() function)
 */

/* ---------------------------- Session Errors Logging ---------------------------- */

/**
 * LOG_SESS_CODE_ macros, calling the handleSessErrCode()
 * function with the arguments passed to the LOG_SESS_CODE macro:
 *  - 1 argument   -> sessErrCode only
 *  - 2 arguments  -> sessErrCode + additional description
 *  - 3 arguments  -> sessErrCode + additional description + error reason
 *  - (DEBUG_MODE) -> The source file name and line number at which the exception is thrown
 */
#ifdef DEBUG_MODE
 #define LOG_SESS_CODE_ONLY(sessErrCode) handleSessErrCode(sessErrCode,nullptr,nullptr,new std::string(__FILE__),__LINE__-1)
 #define LOG_SESS_CODE_DSCR(sessErrCode,dscr) handleSessErrCode(sessErrCode,new std::string(dscr),nullptr,new std::string(__FILE__),__LINE__-1)
 #define LOG_SESS_CODE_DSCR_REASON(sessErrCode,dscr,reason) handleSessErrCode(sessErrCode,new std::string(dscr),new std::string(reason),new std::string(__FILE__),__LINE__-1)
#else
#define LOG_SESS_CODE_ONLY(sessErrCode) handleSessErrCode(sessErrCode,nullptr,nullptr)
 #define LOG_SESS_CODE_DSCR(sessErrCode,dscr) handleSessErrCode(sessErrCode,new std::string(dscr),nullptr)
 #define LOG_SESS_CODE_DSCR_REASON(sessErrCode,dscr,reason) handleSessErrCode(sessErrCode,new std::string(dscr),new std::string(reason))
#endif

/**
 * Substitutes the appropriate LOG_SESS_CODE_ depending on the
 * number of arguments passed to the LOG_SESS_CODE variadic macro:
 *  - 1 argument  -> sessErrCode only
 *  - 2 arguments -> sessErrCode + additional description
 *  - 3 arguments -> sessErrCode + additional description + error reason
 */
#define GET_LOG_SESS_CODE_MACRO(_1,_2,_3,LOG_SESS_CODE_MACRO,...) LOG_SESS_CODE_MACRO
#define LOG_SESS_CODE(...) GET_LOG_SESS_CODE_MACRO(__VA_ARGS__,LOG_SESS_CODE_DSCR_REASON,LOG_SESS_CODE_DSCR,LOG_SESS_CODE_ONLY)(__VA_ARGS__)


/* ---------------------- Session Error Exceptions Throwing ---------------------- */

/**
 * THROW_SESS_EXCP_ macros, passing their arguments
 * to the matching sessErrExcp exception constructor
 *  - 1 argument   -> sessErrCode only
 *  - 2 arguments  -> sessErrCode + additional description
 *  - 3 arguments  -> sessErrCode + additional description + error reason
 *  - (DEBUG_MODE) -> The source file name and line number at which the sessErrCode has been thrown
 */
#ifdef DEBUG_MODE
#define THROW_SESS_EXCP_CODE_ONLY(sessErrCode) throw sessErrExcp(sessErrCode,new std::string(__FILE__),__LINE__-1)
 #define THROW_SESS_EXCP_DSCR(sessErrCode,dscr) throw sessErrExcp(sessErrCode,new std::string(dscr),new std::string(__FILE__),__LINE__-1)
 #define THROW_SESS_EXCP_DSCR_REASON(sessErrCode,dscr,reason) throw sessErrExcp(sessErrCode,new std::string(dscr),new std::string(reason),new std::string(__FILE__),__LINE__-1)
#else
#define THROW_SESS_EXCP_CODE_ONLY(sessErrCode) throw sessErrExcp(sessErrCode)
 #define THROW_SESS_EXCP_DSCR(sessErrCode,dscr) throw sessErrExcp(sessErrCode,new std::string(dscr))
 #define THROW_SESS_EXCP_DSCR_REASON(sessErrCode,dscr,reason) throw sessErrExcp(sessErrCode,new std::string(dscr),new std::string(reason))
#endif


/**
 * Substitutes the appropriate THROW_SESS_EXCP_ macro depending on the
 * number of arguments passed to the THROW_SESS_EXCP variadic macro:
 *  - 1 argument  -> sessErrCode only
 *  - 2 arguments -> sessErrCode + additional description
 *  - 3 arguments -> sessErrCode + additional description + error reason
 */
#define GET_THROW_SESS_EXCP_MACRO(_1,_2,_3,THROW_SESS_EXCP_MACRO,...) THROW_SESS_EXCP_MACRO
#define THROW_SESS_EXCP(...) GET_THROW_SESS_EXCP_MACRO(__VA_ARGS__,THROW_SESS_EXCP_DSCR_REASON,THROW_SESS_EXCP_DSCR,THROW_SESS_EXCP_CODE_ONLY)(__VA_ARGS__)


/* =============== SESSION ERRORS HANDLING FUNCTIONS DECLARATIONS =============== */

/**
 * @brief             Session error codes handler, passing its information
 *                    to the SafeCloud application default error handler
 * @param execErrCode The session error code that has occurred
 * @param addDsc      The additional session error description (optional)
 * @param reason      The session error reason (optional)
 * @param srcFile     (DEBUG MODE ONLY) The source file where the session error has occurred
 * @param lineNumber  (DEBUG MODE ONLY) The line number at which the session error has occurred
 */
#ifdef DEBUG_MODE
void handleSessErrCode(sessErrCode sesErrCode, const std::string* addDscr, const std::string* reason, const std::string* srcFile, unsigned int lineNumber);
#else
void handleSessErrCode(sessErrCode sesErrCode,const std::string* addDscr,const std::string* reason);
#endif


/**
 * @brief            Session error exceptions default handler, passing the exception's
 *                   information to the handleSessErrCode() session code error handler
 * @param exeErrExcp The sessErrExcp exception that was caught
 */
void handleSessErrException(const sessErrExcp& sesErrExcp);


#endif //SAFECLOUD_SESSERRCODES_H