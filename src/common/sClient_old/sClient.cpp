#include "sClient.h"

// Miscellaneous Libraries
#include <string.h>

// SafeCloud Libraries
#include "defaults.h"
#include "utils.h"

using namespace std;


/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* ------------------------ Constructors and Destructor ------------------------ */

/**
 * @brief          sClient object constructor
 * @param csk      The client's connection socket
 * @param name     The client's name (already sanitized)
 * @param stsmData The client's STSM handshake data (already initialized)
 * @param tempDir  The client's temporary directory (already sanitized)
 */
sClient::sClient(int csk, char* name, char* tempDir) : _cliType(GUEST), _csk(csk), _name(), _buf(), _bufInd(0), _bufSize(CLI_BUF_SIZE), _skey(nullptr),
                                                       _skeySize(SKEY_SIZE), _iv(nullptr), _ivSize(IV_SIZE), _sentMsg(nullptr), _recvMsg(nullptr), _tempDir(tempDir)
 {
  sprintf(_name,"%30s",name);               // Client's name
  _buf = (unsigned char*)malloc(CLI_BUF_SIZE);   // General purpose buffer initialization
 }


/**
 * @brief sClient object destructor, which safely deletes its sensitive attributes
 */
sClient::~sClient()
 {
  // Safely erase all dynamic memory attributes
  safeMemset0(reinterpret_cast<void*&>(_name), 31);
  safeMemset0(reinterpret_cast<void*&>(_buf), _bufSize);
  safeFree(reinterpret_cast<void*&>(_skey), _skeySize);
  safeFree(reinterpret_cast<void*&>(_iv), _ivSize);
  safeFree(reinterpret_cast<void*&>(_tempDir),strlen(_tempDir)+1);  // + `\0' character

  // Delete all child objects (safe erase are implemented in their destructors)
  delete _sentMsg;
  delete _recvMsg;
 }


/* ------------------------------- Other Methods ------------------------------- */

/**
 * @brief  Returns the client's name
 * @return The client's name
 */
char* sClient::getName()
 { return _name; }



