/* SafeCloud Session Error Codes Definitions */

/* ================================== INCLUDES ================================== */
#include "sessErrCodes.h"

/* ================ SESSION ERRORS HANDLING FUNCTIONS DEFINITIONS ================ */

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
void handleSessErrCode(const sessErrCode sesErrCode, const std::string* addDscr, const std::string* reason, const std::string* srcFile, const unsigned int lineNumber)
#else
void handleSessErrCode(const sessErrCode sesErrCode,const std::string* addDscr,const std::string* reason)
#endif
 {
  // Retrieve the information associated with the session error code from the sessErrCodeInfoMap
  errCodeInfo sesCodeInfo = sessErrCodeInfoMap.find(sesErrCode)->second;

  // Call the SafeCloud application default error handler passing
  // it the information associated with the session error
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