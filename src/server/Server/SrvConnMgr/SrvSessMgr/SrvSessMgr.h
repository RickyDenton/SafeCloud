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

   // The server session manager reception mode
   enum srvSessRecvMode : uint8_t
    {
     RECV_MSG,  // Session message expected
     RECV_RAW   // Raw data expected
    };

   /* ================================= ATTRIBUTES ================================= */
   srvSessRecvMode _srvSessRecvMode;  // The current server session manager reception mode
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
   void recvCheckSrvSessMsg();

   bool passRawData()
    {
     if(_srvSessRecvMode == RECV_RAW)
      return true;
     return false;
    }

   // TODO: Placeholder implementation
   void recvRaw();
 };


#endif //SAFECLOUD_SRVSESSMGR_H
