#ifndef SAFECLOUD_CONNMGR_H
#define SAFECLOUD_CONNMGR_H

/* SafeCloud Connection Manager Declarations */

/* ================================== INCLUDES ================================== */
#include "defaults.h"
#include "SafeCloudApp/ConnMgr/IV/IV.h"
#include "ossl_crypto/AES_128_CBC.h"
#include "SafeCloudApp/ConnMgr/SessMgr/AESGCMMgr/AESGCMMgr.h"
#include <string>

// The size in bytes of SafeCloud Message
// (STSMMsg or Session Message) length header
#define MSG_LEN_HEAD_SIZE 2

class ConnMgr
 {
  protected:

   // Connection Phases
   enum connPhase
    {
     KEYXCHANGE,  // STSM key establishment phase
     SESSION      // Session phase
    };

   // Connection manager reception modes
   enum recvMode : uint8_t
    {
     // Receive either a STSMMsg or a SessMsgWrapper, with
     // its first 16 bits representing the total message size
     RECV_MSG,

     // Receive raw data
     RECV_RAW
    };

   /* ================================= ATTRIBUTES ================================= */

   /* ----------------------- Connection General Information ----------------------- */
   connPhase _connPhase;    // The connection's current phase (STSM key establishment or session)
   recvMode  _recvMode;     // The connection manager's current reception mode (RECV_MSG or RECV_RAW)
   const int _csk;          // The connection socket associated with this manager
   bool      _shutdownConn; // Whether the connection manager should be terminated

   /* ------------------------ Primary Communication Buffer ------------------------ */

   /*
    * This buffer is used for sending and receiving data to and
    * from the peer associated with the connection socket "_csk"
    */

   // Primary communication buffer
   unsigned char      _priBuf[CONN_BUF_SIZE];

  // TODO: _priBuf[CONN_BUF_SIZE + AES_128_GCM_TAG_SIZE] causes a buffer overflow in receiving a message.
  // TODO: Ensure that it works like this (Session messages must be < 1MB
  // TODO: Remember in case to also change the '_priBufInd' and '_secBufInd' values in the constructor
  // unsigned char      _priBuf[CONN_BUF_SIZE + AES_128_GCM_TAG_SIZE];


  // Primary communication buffer size
   const unsigned int _priBufSize;

   // Index of the first available byte (or number of
   // significant bytes) in the primary communication buffer
   unsigned int       _priBufInd;

   // Expected size of the data block (message or raw) to be received
   uint32_t           _recvBlockSize;

   /* ----------------------- Secondary Communication Buffer ----------------------- */

   /*
    * This buffer is used as a support for preparing the data to be sent to or parsing
    * the data received from the communication peer (e.g. encryption and decryption)
    */

   // Secondary communication buffer
   unsigned char      _secBuf[CONN_BUF_SIZE];

   // Secondary communication buffer size
   const unsigned int _secBufSize;

   /* -------------------- Connection Cryptographic Quantities -------------------- */
   unsigned char _skey[AES_128_KEY_SIZE];   // The connection's symmetric key
   IV* _iv;                                 // The connection's initialization vector

   /* ----------------------- Connection Client Information ----------------------- */
   std::string* _name;   // The name of the client associated with this connection
   std::string* _tmpDir; // The absolute path of the temporary directory of the client associated with this connection


   /* =============================== FRIEND CLASSES =============================== */
   friend class SessMgr;
   friend class CliSessMgr;
   friend class SrvSessMgr;

   /* ============================== PROTECTED METHODS ============================== */

   /* ------------------------------- Utility Methods ------------------------------- */

   /**
    * @brief Deletes the contents of the connection's temporary directory
    *        (called within the connection manager's destructor)
    */
   void cleanTmpDir();

   /**
    * @brief Marks the contents of the primary connection buffer as consumed,
    *        resetting the index of its first significant byte and the
    *        expected size of the data block (message or raw) to be received
    */
   void clearPriBuf();

   /* ----------------------- SafeCloud Messages Send/Receive ----------------------- */

   /**
    * @brief Sends a SafeCloud message (STSMMsg or SessMsg) stored in
    *        the primary connection buffer to the connection peer
    * @throws ERR_PEER_DISCONNECTED The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED       send() fatal error
    */
   void sendMsg();

   /**
    * @brief  Blocks until a SafeCloud message length header of MSG_LEN_HEAD_SIZE bytes (2)
    *         is received from the connection socket into the primary connection buffer
    * @throws ERR_CSK_RECV_FAILED    Error in receiving data from the connection socket
    * @throws ERR_PEER_DISCONNECTED  The connection peer has abruptly disconnected
    * @throws ERR_MSG_LENGTH_INVALID Received an invalid message length value
    */
   void recvMsgLenHeader();

   /**
    * @brief  Blocks until a full SafeCloud message (STSMMsg or SessMsg) has been
    *         received from the connection socket into the primary communication buffer
    * @throws ERR_CONNMGR_INVALID_STATE Attempting to receive a message with
    *                                   the connection manager in RECV_RAW mode
    * @throws ERR_CSK_RECV_FAILED       Error in receiving data from the connection socket
    * @throws ERR_PEER_DISCONNECTED     The connection peer has abruptly disconnected
    * @throws ERR_MSG_LENGTH_INVALID    Received an invalid message length value
    */
   void recvFullMsg();

   /* ---------------------------- Raw Data Send/Receive ---------------------------- */

   /**
    * @brief Sends bytes from the start of the primary connection buffer to the connection peer
    * @param numBytes The number of bytes to be sent (must be <= _priBufSize)
    * @throws ERR_SEND_OVERFLOW     Attempting to send a number of bytes > _priBufSize
    * @throws ERR_PEER_DISCONNECTED The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED       send() fatal error
    */
   void sendRaw(unsigned int numBytes);

   /**
    * @brief  Blocks until any number of bytes belonging to the data block to be received (message
    *         or raw) are read from the connection socket into the primary connection buffer
    * @return The number of bytes read from the connection socket into the primary connection buffer
    * @throws ERR_CSK_RECV_FAILED       Error in receiving data from the connection socket
    * @throws ERR_PEER_DISCONNECTED     The connection peer has abruptly disconnected
    * @throws ERR_CONNMGR_INVALID_STATE The expected data block size is unknown or not greater than the
    *                                   index of the first available byte in the primary connection buffer
    */
   unsigned int recvRaw();

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief        ConnMgr object constructor
    * @param csk    The connection socket associated with this manager
    * @param name   The name of the client associated with this connection
    * @param tmpDir The absolute path of the temporary directory associated with this connection
    */
   ConnMgr(int csk, std::string* name, std::string* tmpDir);

   /**
    * @brief Connection Manager object destructor, which:\n
    *          1) Closes its associated connection socket\n
    *          2) Delete the contents of the connection's temporary directory\n
    *          3) Safely deletes all the connection's sensitive information
    */
   ~ConnMgr();

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief  Returns whether the connection manager should be terminated
    * @return A boolean indicating whether the connection manager should be terminated
    */
   bool shutdownConn() const;

   /**
    * @brief  Returns whether the connection manager is in the session phase
    * @return Whether the connection manager is in the session phase
    */
   bool isInSessionPhase() const;
 };


#endif //SAFECLOUD_CONNMGR_H
