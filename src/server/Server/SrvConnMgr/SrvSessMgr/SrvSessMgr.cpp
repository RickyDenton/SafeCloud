/* SafeCloud Server Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvSessMgr.h"
#include "ConnMgr/SessMgr/SessMsg.h"
#include "../SrvConnMgr.h"

/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

SrvSessMgr::SrvSessMgr(SrvConnMgr& srvConnMgr)
  : SessMgr(reinterpret_cast<ConnMgr&>(srvConnMgr)), _srvSessCmdState(SRV_IDLE), _srvConnMgr(srvConnMgr), _srvSessRecvMode(RECV_MSG)
 {}

// Same destructor of the SessMgr base class

/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief Resets the server session manager state
 *        to be ready for the next session command
 */
void SrvSessMgr::resetSrvSessState()
 {
  // Reset the base class state
  resetSessState();

  // Set the session manager reception mode to expect a message
  _srvSessRecvMode = RECV_MSG;
 }


// TODO
bool SrvSessMgr::recvSrvSessMsg()
{
 // TODO: Remove
 std::cout << "in recvSrvSessMsg()" << std::endl;

 // unwrap the received session message into the
 // associated connection manager's secondary buffer
 unWrapSessMsg();

 // Interpret the contents of the associated connection
 // manager's secondary buffer as a session message
 SessMsg* sessMsg = reinterpret_cast<SessMsg*>(_srvConnMgr._secBuf);

 // TODO: Check for errors and cancel and then switch(sessMsg->msgType)

 // LOG: Session message length and msgType
 std::cout << "sessMsg->wrapLen" << sessMsg->msgLen << std::endl;
 std::cout << "sessMsg->msgType" << sessMsg->msgType << std::endl;

  // TODO: stub
 return true;
}



void SrvSessMgr::recvRaw()
 {
  std::cout << "In recvRaw()" << std::endl;
 }