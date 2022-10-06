#ifndef SAFECLOUD_SESSERRCODES_H
#define SAFECLOUD_SESSERRCODES_H

/**
 * SafeCloud session error codes definitions
 *
 * These are non-fatal error that may occur in the session
 * phase, causing its state to be reset without aborting
 * the connection between the SafeCloud client and server
 */

/* ================================== INCLUDES ================================== */
#include <unordered_map>
#include "errCode.h"

/* ======================= SAFECLOUD SESSION ERROR CODES ======================= */

enum sessErrCode : unsigned char
 {
  // Operation Successful
  OK = 0,

  /* -------------------------- SERVER-SPECIFIC ERRORS -------------------------- */


  /* -------------------------- CLIENT-SPECIFIC ERRORS -------------------------- */


  /* ----------------------- CLIENT-SERVER COMMON ERRORS ----------------------- */

  // Unknown error
  ERR_UNKNOWN
 };


/* =================== SAFECLOUD SESSION ERROR CODES INFO MAP =================== */

// Associates each SafeCloud session error code with its severity level and human-readable description
static const std::unordered_map<sessErrCode,errCodeInfo> sessErrCodeInfoMap =
  {
    // Operation Successful
    { OK, {DEBUG,"Operation Successful"}},

    // Unknown error
    {ERR_UNKNOWN,{CRITICAL, "Unknown Error"} }
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
  sessErrExcp(const enum sessErrCode seErrCode, std::string srcFileName, const unsigned int line)
    : errExcp(std::move(srcFileName),line), sesErrCode(seErrCode)
   {}

  // sessErrCode + additional description constructor (with implicit source file name and line)
  sessErrExcp(const enum sessErrCode seErrCode, std::string addDescr, std::string srcFileName, const unsigned int line)
    : errExcp(std::move(addDescr),std::move(srcFileName),line), sesErrCode(seErrCode)
   {}

  // sessErrCode + additional description + reason constructor (with implicit source file name and line)
  sessErrExcp(const enum sessErrCode seErrCode, std::string addDescr, std::string errReason, std::string srcFileName, const unsigned int line)
    : errExcp(std::move(addDescr),std::move(errReason), std::move(srcFileName),line), sesErrCode(seErrCode)
   {}
#else
  /* ----------------- Non-DEBUG_MODE Constructors ----------------- */

  // sessErrCode-only constructor
  explicit sessErrExcp(const enum sessErrCode seErrCode)
    : errExcp(), sesErrCode(seErrCode)
   {}

  // sessErrCode + additional description constructor
  sessErrExcp(const enum sessErrCode seErrCode, std::string addDescr)
    : errExcp(std::move(addDescr)), sesErrCode(seErrCode)
   {}

  // sessErrCode + additional description + reason constructor
  sessErrExcp(const enum sessErrCode seErrCode, std::string addDescr, std::string errReason)
    : errExcp(std::move(addDescr),std::move(errReason)), sesErrCode(seErrCode)
   {}
#endif

  // Destructor
  ~sessErrExcp()
   {}
 };


/* ======================== SESSION ERRORS HANDLING MACROS ======================== */

/* ---------------------------- Session Errors Logging ---------------------------- */

/**
 * LOG_SESS_CODE_ macros, calling the handleSessErrCode() function with the arguments passed to the LOG_SESS_CODE macro:
 *  - 1 argument   -> sessErrCode only
 *  - 2 arguments  -> sessErrCode + additional description
 *  - 3 arguments  -> sessErrCode + additional description + error reason
 *  - (DEBUG_MODE) -> The source file name and line number at which the exception is thrown
 */
#ifdef DEBUG_MODE
 #define LOG_SESS_CODE_ONLY(sessErrCode) handleSessErrCode(sessErrCode,"","",__FILE__,__LINE__-1)
 #define LOG_SESS_CODE_DSCR(sessErrCode,dscr) handleSessErrCode(sessErrCode,dscr,"",__FILE__,__LINE__-1)
 #define LOG_SESS_CODE_DSCR_REASON(sessErrCode,dscr,reason) handleSessErrCode(sessErrCode,dscr,reason,__FILE__,__LINE__-1)
#else
#define LOG_SESS_CODE_ONLY(sessErrCode) handleSessErrCode(sessErrCode,"","")
 #define LOG_SESS_CODE_DSCR(sessErrCode,humanDscr) handleSessErrCode(sessErrCode,humanDscr,"")
 #define LOG_SESS_CODE_DSCR_REASON(sessErrCode,humanDscr,reason) handleSessErrCode(sessErrCode,humanDscr,reason)
#endif

/**
 * Substitutes the appropriate LOG_SESS_CODE_ depending on the number of arguments passed to the LOG_SESS_CODE variadic macro:
 *  - 1 argument  -> sessErrCode only
 *  - 2 arguments -> sessErrCode + additional description
 *  - 3 arguments -> sessErrCode + additional description + error reason
 */
#define GET_LOG_SESS_CODE_MACRO(_1,_2,_3,LOG_SESS_CODE_MACRO,...) LOG_SESS_CODE_MACRO
#define LOG_SESS_CODE(...) GET_LOG_SESS_CODE_MACRO(__VA_ARGS__,LOG_SESS_CODE_DSCR_REASON,LOG_SESS_CODE_DSCR,LOG_SESS_CODE_ONLY)(__VA_ARGS__)


/* ---------------------- Session Error Exceptions Throwing ---------------------- */

/**
 * THROW_SESS_EXCP_ macros, passing their arguments to the matching sessErrExcp exception constructor
 *  - 1 argument   -> sessErrCode only
 *  - 2 arguments  -> sessErrCode + additional description
 *  - 3 arguments  -> sessErrCode + additional description + error reason
 *  - (DEBUG_MODE) -> The source file name and line number at which the sessErrCode has been thrown
 */
#ifdef DEBUG_MODE
#define THROW_SESS_EXCP_CODE_ONLY(sessErrCode) throw sessErrExcp(sessErrCode,__FILE__,__LINE__-1)
 #define THROW_SESS_EXCP_DSCR(sessErrCode,dscr) throw sessErrExcp(sessErrCode,dscr,__FILE__,__LINE__-1)
 #define THROW_SESS_EXCP_DSCR_REASON(sessErrCode,dscr,reason) throw sessErrExcp(sessErrCode,dscr,reason,__FILE__,__LINE__-1)
#else
#define THROW_SESS_EXCP_CODE_ONLY(sessErrCode) throw sessErrExcp(sessErrCode)
 #define THROW_SESS_EXCP_DSCR(sessErrCode,humanDscr) throw sessErrExcp(sessErrCode,humanDscr)
 #define THROW_SESS_EXCP_DSCR_REASON(sessErrCode,humanDscr,reason) throw sessErrExcp(sessErrCode,humanDscr,reason)
#endif


/**
 * Substitutes the appropriate THROW_SESS_EXCP_ macro depending on the number of arguments passed to the THROW_SESS_EXCP variadic macro:
 *  - 1 argument  -> sessErrCode only
 *  - 2 arguments -> sessErrCode + additional description
 *  - 3 arguments -> sessErrCode + additional description + error reason
 */
#define GET_THROW_SESS_EXCP_MACRO(_1,_2,_3,THROW_SESS_EXCP_MACRO,...) THROW_SESS_EXCP_MACRO
#define THROW_SESS_EXCP(...) GET_THROW_SESS_EXCP_MACRO(__VA_ARGS__,THROW_SESS_EXCP_DSCR_REASON,THROW_SESS_EXCP_DSCR,THROW_SESS_EXCP_CODE_ONLY)(__VA_ARGS__)


/* ====================== SESSION ERRORS HANDLING FUNCTIONS ====================== */

/**
 * @brief             Session error codes handler, passing its information to the SafeCloud application default error handler
 * @param execErrCode The session error code that has occurred
 * @param addDsc      The additional session error description (optional)
 * @param reason      The session error reason (optional)
 * @param srcFile     (DEBUG MODE ONLY) The source file where the session error has occurred
 * @param lineNumber  (DEBUG MODE ONLY) The line number at which the session error has occurred
 */
#ifdef DEBUG_MODE
void handleSessErrCode(const sessErrCode sesErrCode, const std::string& addDscr, const std::string& reason, const std::string& srcFile, const unsigned int lineNumber)
#else
void handleSessErrCode(const sessErrCode sesErrCode,const std::string& addDscr,const std::string& reason)
#endif
 {
  // Retrieve the information associated with the session error code from the sessErrCodeInfoMap
  errCodeInfo sesCodeInfo = sessErrCodeInfoMap.find(sesErrCode)->second;

  // Call the SafeCloud application default error handler passing it the information associated with the session error
#ifdef DEBUG_MODE
  handleErrCode(sesCodeInfo, addDscr, reason, srcFile, lineNumber);
#else
  handleErrCode(sesCodeInfo,addDscr,reason);
#endif
 }


/**
 * @brief            Session error exceptions default handler, passing the exception's
 *                   information to the handleSessErrCode() session code error handler
 * @param exeErrExcp The sessErrExcp exception that was caught
 */
void handleSessErrException(const sessErrExcp& sesErrExcp)
 {
#ifdef DEBUG_MODE
  handleSessErrCode(sesErrExcp.sesErrCode, sesErrExcp.addDscr, sesErrExcp.reason, sesErrExcp.srcFile, sesErrExcp.lineNumber);
#else
  handleSessErrCode(sesErrExcp.sesErrCode,sesErrExcp.addDscr,sesErrExcp.reason);
#endif
  /*
   * NOTE: Exception objects are automatically destroyed after handling (matching
   *       catch{} clause), and so do not require to be manually deallocated
   */
 }


#endif //SAFECLOUD_SESSERRCODES_H
