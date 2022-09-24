#ifndef SAFECLOUD_CONNMGR_H
#define SAFECLOUD_CONNMGR_H

#include "defaults.h"
#include <string>

/* SafeCloud Connection Manager */

class ConnMgr
 {
  protected:

   enum connState
    {
     KEYXCHANGE,  // Connection in the STSM key establishment phase
     SESSION      // Connection in the session phase
    };

   /* ========================= Attributes ========================= */

   // General connection information
   connState    _connState;           // Current connection state (key establishment or session)
   const int    _csk;                 // The connection socket's file descriptor
   std::string* _name;                // The client's name associated with this connection
   std::string* _tmpDir;              // The connection's temporary directory

   // General-purpose buffer for sending and receiving data
   unsigned char      _buf[CONN_BUF_SIZE];  // General-purpose buffer
   const unsigned int _bufSize;             // General-purpose buffer size (CONN_BUF_SIZE)
   unsigned int       _bufInd;              // First available byte in the general-purpose buffer

   // Cryptographic quantities
   unsigned char* _iv[IV_SIZE];      // The connection's initialization vector
   unsigned short _ivSize;           // The connection's initialization vector size (IV_SIZE = 12 bytes = 96 bit, AES128_GCM)
   unsigned char* _skey[SKEY_SIZE];  // The connection's symmetric key
   unsigned short _skeySize;         // The connection's symmetric key size (SKEY_SIZE = 16 bytes = 128 bit, AES128_GCM)

   /* =========================== Methods =========================== */

   /**
    * @brief Deletes the contents of the connection's temporary directory
    */
   void cleanTmpDir();

  public:

   /* ================= Constructor and Destructor ================= */

   /**
    * @brief        ConnMgr object constructor
    * @param csk    The connection socket's file descriptor
    * @param name   The client's name associated with this connection
    * @param tmpDir The connection's temporary directory
    */
   ConnMgr(int csk, std::string* name, std::string* tmpDir);

   /**
    * @brief Connection Manager object destructor, which closes its associated connection
    *        socket and safely deletes all the connection's sensitive information
    */
   ~ConnMgr();

   /* ======================== Other Methods ======================== */

   bool recvData();

  // TODO
   // sendOk()
   // sendClose()
   // sendCloseError()
 };


#endif //SAFECLOUD_CONNMGR_H
