#ifndef SAFECLOUD_CONNMGR_H
#define SAFECLOUD_CONNMGR_H

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
   connState   _connState;          // Current connection state (key establishment or session)
   const int   _csk;                // The connection socket's file descriptor
   char*       _ip;                 // The connection endpoint's IP address
   const int   _port;               // The connection endpoint's port
   char*       _name;               // The client's name associated with this connection
   char*       _tmpDir;             // The connection's temporary directory

   // General-purpose buffer for sending and receiving data
   unsigned char*     _buf;         // General-purpose buffer
   const unsigned int _bufSize;     // General-purpose buffer size (CONN_BUF_SIZE)

   // TODO: Check if needed
   // Out-of-band buffer for asynchronous messages
   unsigned char*      _oobBuf;     // Out-of-Band buffer
   const unsigned int  _oobBufSize; // Out-of-Band buffer size

   // Cryptographic quantities
   unsigned char* _iv;          // The connection's initialization vector
   unsigned short _ivSize;      // The connection's initialization vector size (IV_SIZE = 12 bytes = 96 bit, AES128_GCM)
   unsigned char* _skey;        // The connection's symmetric key
   unsigned short _skeySize;    // The connection's symmetric key size (SKEY_SIZE = 16 bytes = 128 bit, AES128_GCM)

   /* =========================== Methods =========================== */
   // TODO

  public:

   /* ================= Constructors and Destructor ================= */
   ConnMgr(int csk, char* ip, int port, char* name, char* tmpDir);
   ~ConnMgr();

   /* ======================== Other Methods ======================== */
   // TODO
   // sendOk()
   // sendClose()
   // sendCloseError()
 };


#endif //SAFECLOUD_CONNMGR_H