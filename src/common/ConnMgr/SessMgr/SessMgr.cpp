/* SafeCloud Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SessMgr.h"

// TODO: Write descriptions

/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */


SessMgr::SessMgr(ConnMgr& connMgr)
  : _sessCmd(IDLE), _connMgr(connMgr), _aesGCMMgr(_connMgr._skey,_connMgr._iv), _targFileDscr(nullptr), _targFileAbsPath(nullptr), _targFileInfo(nullptr),
    _tmpFileDscr(nullptr), _tmpFileAbsPath(nullptr), _tmpFileInfo(nullptr), _bytesTransf(0), _progBar(100), _tProgUnit(0), _tProgTemp(0)
 {}


SessMgr::~SessMgr()
 {
  // _connMgr must not be deleted, the other objects do so in their destructors

  if(_targFileDscr != nullptr)
   fclose(_targFileDscr);
  delete _targFileDscr;

  delete _targFileAbsPath;
  delete _targFileInfo;

  if(_tmpFileDscr != nullptr)
   fclose(_tmpFileDscr);
  delete _tmpFileDscr;

  delete _tmpFileAbsPath;
  delete _tmpFileInfo;
 }


/* ============================ OTHER PUBLIC METHODS ============================ */


// TODO: Check and write description
void SessMgr::resetSessState()
 {
  _sessCmd = IDLE;

  _aesGCMMgr.resetState();

  if(_targFileDscr != nullptr)
   fclose(_targFileDscr);
  delete _targFileDscr;

  delete _targFileAbsPath;
  delete _targFileInfo;

  if(_tmpFileDscr != nullptr)
   fclose(_tmpFileDscr);
  delete _tmpFileDscr;

  delete _tmpFileAbsPath;
  delete _tmpFileInfo;

  _bytesTransf = 0;

  _progBar.reset();

  _tProgUnit = 0;
  _tProgTemp = 0;

  printf("in resetSessState()\n");
 }