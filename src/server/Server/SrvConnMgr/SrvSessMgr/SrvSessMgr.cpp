/* SafeCloud Server Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvSessMgr.h"

/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

SrvSessMgr::SrvSessMgr(SrvConnMgr& srvConnMgr)
  : SessMgr(reinterpret_cast<ConnMgr&>(srvConnMgr)), _srvSessCmdState(SRV_IDLE), _srvConnMgr(srvConnMgr)
 {}

// Same destructor of the SessMgr base class

/* ============================= OTHER PUBLIC METHODS ============================= */