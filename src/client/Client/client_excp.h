#ifndef SAFECLOUD_CLIENT_EXCP_H
#define SAFECLOUD_CLIENT_EXCP_H

#include "errlog.h"


/* ============================== MACROS DEFINITIONS ============================== */


/* --------------------- cmdException Throwing and Catching --------------------- */

/**
 * THROW_CMD_EXCP macros, passing their arguments to the appropriate cmdException constructor
 *  - 1 argument   -> scode only
 *  - 2 arguments  -> scode + additional description
 *  - 3 arguments  -> scode + additional description + error reason
 *  - (DEBUG_MODE) -> The source file name and line number at which the exception is thrown
 */
#ifdef DEBUG_MODE
 #define THROW_CMDEXCP_ONLY(scode) throw cmdException(scode,__FILE__,__LINE__-1)
 #define THROW_CMDEXCP_DSCR(scode,dscr) throw cmdException(scode,dscr,__FILE__,__LINE__-1)
 #define THROW_CMDEXCP_DSCR_REASON(scode,dscr,reason) throw cmdException(scode,dscr,reason,__FILE__,__LINE__-1)
#else
 #define THROW_CMDEXCP_ONLY(scode) throw connException(scode)
 #define THROW_CMDEXCP_DSCR(scode,dscr) throw connException(scode,dscr)
 #define THROW_CMDEXCP_DSCR_REASON(scode,dscr,reason) throw connException(scode,dscr,reason)
#endif


/**
 * Substitutes the appropriate THROW_CMDEXCP_MACRO depending on the number of arguments passed to the THROW_CMD_EXCP variadic macro:
 *  - 1 argument  -> scode only
 *  - 2 arguments -> scode + additional description
 *  - 3 arguments -> scode + additional description + error reason
 */
#define GET_THROW_CMDEXCP_MACRO(_1,_2,_3,THROW_CMDEXCP_MACRO,...) THROW_CMDEXCP_MACRO
#define THROW_CMD_EXCP(...) GET_THROW_CMDEXCP_MACRO(__VA_ARGS__,THROW_CMDEXCP_DSCR_REASON,THROW_CMDEXCP_DSCR,THROW_CMDEXCP_ONLY)(__VA_ARGS__)


/* ============================== TYPE DEFINITIONS ============================== */

// TODO: Write definitions ("using" is for inheriting constructors from the base class)
class remLoginException : public sCodeException
 { using sCodeException::sCodeException; };

class connException : public sCodeException
 { using sCodeException::sCodeException; };

class cmdException : public sCodeException
 { using sCodeException::sCodeException; };


#endif //SAFECLOUD_CLIENT_EXCP_H
