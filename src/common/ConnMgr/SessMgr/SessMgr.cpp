/* SafeCloud Session Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SessMgr.h"
#include "errCodes/errCodes.h"
#include "SessMsg.h"


/* ============================= PROTECTED METHODS ============================= */

void SessMgr::wrapSendSessMsg()
 {
  // Determine the session message size from the first 16 bit
  // of the associated connection manager's secondary buffer
  uint16_t sessMsgSize = ((uint16_t*)_connMgr._secBuf)[0];

  // Determine the session message wrapper size
  uint16_t sessWrapSize = sessMsgSize + sizeof(SessMsgWrapper);

  // Write the session message wrapper size at the start of
  // the associated connection manager's primary buffer
  memcpy(&_connMgr._priBuf[0], &sessWrapSize, sizeof(uint16_t));

  // Initialize an AES_128_GCM encryption operation
  _aesGCMMgr.encryptInit();

  // Set the encryption operation's AAD to the message wrapper size
  _aesGCMMgr.encryptAddAAD(reinterpret_cast<unsigned char*>(&sessWrapSize), sizeof(sessWrapSize));

  // Encrypt the session message from the secondary to the primary connection buffer
  _aesGCMMgr.encryptAddPT(&_connMgr._secBuf[0], sessMsgSize, &_connMgr._priBuf[sizeof(uint16_t)]);

  // Finalize the encryption by adding wrapper integrity tag
  _aesGCMMgr.encryptFinal(&_connMgr._priBuf[sessWrapSize - AES_128_GCM_TAG_SIZE]);

  // Send the session message wrapper
  _connMgr.sendMsg();
 }



// TODO
void SessMgr::unWrapSessMsg()
 {
  // Determine the session message wrapper size as the first 16
  // bit of the associated connection manager's primary buffer
  uint16_t sessWrapSize = ((uint16_t*)_connMgr._priBuf)[0];

  // Determine the wrapped session message size
  uint16_t sessMsgSize = sessWrapSize - sizeof(SessMsgWrapper);

  // Initialize an AES_128_GCM decryption operation
  _aesGCMMgr.decryptInit();

  // Set the decryption operation's AAD to the message wrapper size
  _aesGCMMgr.decryptAddAAD(reinterpret_cast<unsigned char*>(&sessWrapSize), sizeof(sessWrapSize));

  // Decrypt the session message from the primary into the secondary connection buffer
  _aesGCMMgr.decryptAddCT(&_connMgr._priBuf[sizeof(uint16_t)], sessMsgSize, &_connMgr._secBuf[0]);

  // Finalize the decryption by verifying the wrapper integrity tag
  _aesGCMMgr.decryptFinal(&_connMgr._priBuf[sessWrapSize - AES_128_GCM_TAG_SIZE]);
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */


// TODO: Write descriptions

SessMgr::SessMgr(ConnMgr& connMgr)
  : _sessCmd(IDLE), _connMgr(connMgr), _aesGCMMgr(_connMgr._skey,_connMgr._iv), _targFileDscr(nullptr), _targFileAbsPath(nullptr), _targFileInfo(nullptr),
    _tmpFileDscr(nullptr), _tmpFileAbsPath(nullptr), _tmpFileInfo(nullptr), _bytesTransf(0)
 {}


SessMgr::~SessMgr()
 {
  // _connMgr must not be deleted, the other objects do so in their destructors

  if(_targFileDscr != nullptr)
   fclose(_targFileDscr);

  delete _targFileAbsPath;
  delete _targFileInfo;

  if(_tmpFileDscr != nullptr)
   {
    fclose(_tmpFileDscr);
    if(remove(_tmpFileAbsPath->c_str()) == -1)
     LOG_WARNING("Couldn't delete the temporary file " + *_tmpFileAbsPath)
   }
 }


/* ============================ OTHER PUBLIC METHODS ============================ */


// TODO: Check and write description
void SessMgr::resetSessState()
 {
  _sessCmd = IDLE;

  _aesGCMMgr.resetState();

  if(_targFileDscr != nullptr)
   fclose(_targFileDscr);
  _targFileDscr = nullptr;

  delete _targFileAbsPath;
  _targFileAbsPath = nullptr;

  delete _targFileInfo;
  _targFileInfo = nullptr;

  if(_tmpFileDscr != nullptr)
   {
    fclose(_tmpFileDscr);
    if(remove(_tmpFileAbsPath->c_str()) == -1)
     LOG_WARNING("Couldn't delete the temporary file " + *_tmpFileAbsPath)
   }
  _tmpFileDscr = nullptr;

  _bytesTransf = 0;

  printf("in resetSessState()\n");
 }