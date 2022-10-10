#ifndef SAFECLOUD_SRVSESSMGR_H
#define SAFECLOUD_SRVSESSMGR_H

/* SafeCloud Server Session Manager */

/* ================================== INCLUDES ================================== */
#include "ConnMgr/SessMgr/SessMgr.h"

// Forward Declaration
class SrvConnMgr;

class SrvSessMgr : SessMgr
 {
  private:

   // Server session commands states
   enum srvSessCmdState : uint8_t
    {
     SRV_IDLE,
     // Server UPLOAD command states


     // Server DOWNLOAD command states


     // Server DELETE command states


     // Server RENAME command states


     // Server LIST command states
    };


   /* ================================= ATTRIBUTES ================================= */
   srvSessCmdState _srvSessCmdState;  // The current server session command state
   SrvConnMgr&     _srvConnMgr;       // The parent SrvConnMgr instance managing this object

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */
   SrvSessMgr(SrvConnMgr& cliConnMgr);

   // Same destructor of the SessMgr base class

   /* ============================= OTHER PUBLIC METHODS ============================= */

   // TODO: Placeholder implementation
   bool SessBlockHandler()
    { return true; }

 };


#endif //SAFECLOUD_SRVSESSMGR_H
