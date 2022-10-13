#ifndef SAFECLOUD_SRVSESSMGR_H
#define SAFECLOUD_SRVSESSMGR_H

/* SafeCloud Server Session Manager */

/* ================================== INCLUDES ================================== */
#include "ConnMgr/SessMgr/SessMgr.h"

// Forward Declaration
class SrvConnMgr;

class SrvSessMgr : public SessMgr
 {
  private:

   // Server session commands states
   enum srvSessCmdState : uint8_t
    {
     SRV_IDLE,

     WAITING_CLI_CONF,
     WAITING_CLI_COMPL



     // Server UPLOAD command states


     // Server DOWNLOAD command states


     // Server DELETE command states


     // Server RENAME command states


     // Server LIST command states
    };


   /* ================================= ATTRIBUTES ================================= */
   srvSessCmdState _srvSessMgrSubstate;  // The current server session command state
   SrvConnMgr&     _srvConnMgr;       // The parent SrvConnMgr instance managing this object


  // TODO
  void sendSrvSessSignalMsg(SessMsgType sessMsgType);

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */
   explicit SrvSessMgr(SrvConnMgr& cliConnMgr);

   // Same destructor of the SessMgr base class

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief Resets the server session manager state
    *        to be ready for the next session command
    */
   void resetSrvSessState();

   // TODO
   void SessMsgHandler();

   // TODO: Placeholder implementation
   void recvRaw(size_t recvBytes);
 };


#endif //SAFECLOUD_SRVSESSMGR_H
