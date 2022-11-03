/*  * SafeCloud Execution Error Codes Definitions */

/* ================================== INCLUDES ================================== */
#include "execErrCodes.h"

/* =============== EXECUTION ERRORS HANDLING FUNCTIONS DEFINITIONS =============== */

/**
 * @brief             Execution error codes handler, passing its information
 *                    to the SafeCloud application default error handler
 * @param execErrCode The execution error code that has occurred
 * @param addDsc      The additional execution error description (optional)
 * @param reason      The execution error reason (optional)
 * @param srcFile     (DEBUG MODE ONLY) The source file where the execution error has occurred
 * @param lineNumber  (DEBUG MODE ONLY) The line number at which the execution error has occurred
 */
#ifdef DEBUG_MODE
void handleExecErrCode(const execErrCode exeErrCode, const std::string* addDscr, const std::string* reason, const std::string* srcFile, const unsigned int lineNumber)
#else
void handleExecErrCode(const execErrCode exeErrCode,const std::string* addDscr,const std::string* reason)
#endif
 {
  // Retrieve the information associated with the execution error code from the execErrCodeInfoMap
  errCodeInfo exeErrCodeInfo = execErrCodeInfoMap.find(exeErrCode)->second;

  // Call the SafeCloud application default error handler passing
  // it the information associated with the execution error
#ifdef DEBUG_MODE
  handleErrCode(exeErrCodeInfo,addDscr,reason,srcFile,lineNumber);
#else
  handleErrCode(exeErrCodeInfo,addDscr,reason);
#endif
 }


/**
 * @brief            Execution error exceptions default handler, passing the exception's
 *                   information to the handleExecErrCode() execution code error handler
 * @param exeErrExcp The execErrExcp exception that was caught
 */
void handleExecErrException(const execErrExcp& exeErrExcp)
 {
#ifdef DEBUG_MODE
  handleExecErrCode(exeErrExcp.exErrcode, exeErrExcp.addDscr, exeErrExcp.reason, exeErrExcp.srcFile, exeErrExcp.lineNumber);
#else
  handleExecErrCode(exeErrExcp.exErrcode,exeErrExcp.addDscr,exeErrExcp.reason);
#endif
  /*
   * NOTE: Exception objects are automatically destroyed after handling (matching
   *       catch{} clause), and so do not require to be manually deallocated
   */
 }