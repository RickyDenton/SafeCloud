/* SafeCloud Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <stdlib.h>
#include "ConnMgr.h"
#include "defaults.h"
#include "utils.h"

/* =============================== PRIVATE METHODS =============================== */
// TODO

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief       Connection Manager object constructor
 * @param csk   The connection socket's file descriptor
 * @param ip    The connection endpoint's IP address
 * @param port  The connection endpoint's port
 */
ConnMgr::ConnMgr(int csk, char* ip, int port, char* name, char* tmpDir) : _connState(KEYXCHANGE), _csk(csk), _ip(ip), _port(port), _name(name), _tmpDir(tmpDir),
_buf(), _bufSize(CONN_BUF_SIZE), _oobBuf(), _oobBufSize(CONN_OOBUF_SIZE), _iv(), _ivSize(IV_SIZE), _skey(), _skeySize(SKEY_SIZE)
 {
  // Allocate the connection's array variables
  _buf = (unsigned char*)malloc(CONN_BUF_SIZE);
  _oobBuf = (unsigned char*)malloc(CONN_OOBUF_SIZE);
  _iv = (unsigned char*)malloc(IV_SIZE);
  _skey = (unsigned char*)malloc(SKEY_SIZE);
 }


/**
 * @brief Connection Manager object constructor, which safely deletes its sensitive attributes
 *        (the general-purpose and out-of band buffers, the IV and the session key)
 */
ConnMgr::~ConnMgr()
 {
  safeFree(reinterpret_cast<void*&>(_buf), _bufSize);
  safeFree(reinterpret_cast<void*&>(_oobBuf), _oobBufSize);
  safeFree(reinterpret_cast<void*&>(_iv), _ivSize);
  safeFree(reinterpret_cast<void*&>(_skey), _skeySize);
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

// TODO

// sendOk()
// sendClose()
// sendCloseError()