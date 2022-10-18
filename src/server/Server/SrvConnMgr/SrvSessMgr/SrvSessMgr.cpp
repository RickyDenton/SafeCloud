/* SafeCloud Server Session Manager Class Implementation */

/* ================================== INCLUDES ================================== */
#include <fstream>
#include "SrvSessMgr.h"
#include "ConnMgr/SessMgr/SessMsg.h"
#include "../SrvConnMgr.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"


/* ============================== PRIVATE METHODS ============================== */

/**
 * @brief Sends a session message signaling type to the client and performs the actions
 *        appropriate to session signaling types resetting or terminating the session
 * @param sessMsgSignalingType The session message signaling type to be sent to the client
 * @param errReason            An optional error reason to be embedded with the exception that
 *                             must be thrown after sending such session message signaling type
 * @throws ERR_SESS_INTERNAL_ERROR       The session manager experienced an internal error
 * @throws ERR_SESS_UNEXPECTED_MESSAGE   The session manager received a session message invalid for its current state
 * @throws ERR_SESS_MALFORMED_MESSAGE    The session manager received a malformed session message
 * @throws ERR_SESS_UNKNOWN_SESSMSG_TYPE The session manager received a session message of unknown type
 * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
 * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
 * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
 * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
 * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
 * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
 * @throws ERR_CLI_DISCONNECTED          The client disconnected during the send()
 * @throws ERR_SEND_FAILED               send() fatal error
 */
void SrvSessMgr::sendSrvSessSignalMsg(SessMsgType sessMsgSignalingType)
 { sendSrvSessSignalMsg(sessMsgSignalingType,""); }

void SrvSessMgr::sendSrvSessSignalMsg(SessMsgType sessMsgSignalingType, const std::string& errReason)
 {
  // Attempt to send the signaling session message
  try
   { sendSessSignalMsg(sessMsgSignalingType); }
  catch(execErrExcp& sendSessSignExcp)
   {
    // Change a ERR_PEER_DISCONNECTED into the more specific ERR_CLI_DISCONNECTED error code
    if(sendSessSignExcp.exErrcode == ERR_PEER_DISCONNECTED)
     sendSessSignExcp.exErrcode = ERR_CLI_DISCONNECTED;

    // Rethrow the exception
    throw;
   }

  // In case of signaling messages resetting or terminating the session,
  // perform their associated actions or raise their associated exceptions
  switch(sessMsgSignalingType)
   {
    // The connection manager (and the SafeCloud server as a whole) is terminating
    case BYE:

     // Set that this client connection must be closed
     _srvConnMgr._keepConn = false;
     break;

    // The server session manager experienced an internal error
    case ERR_INTERNAL_ERROR:
     THROW_SESS_EXCP(ERR_SESS_INTERNAL_ERROR,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);

    // A session message invalid for the current server session manager was received
    case ERR_UNEXPECTED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);

    // A malformed session message was received
    case ERR_MALFORMED_SESS_MESSAGE:
     THROW_SESS_EXCP(ERR_SESS_MALFORMED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);

    // A session message of unknown type was received, an error to be attributed to a desynchronization
    // between the client and server IVs and that requires the connection to be reset
    case ERR_UNKNOWN_SESSMSG_TYPE:
     THROW_EXEC_EXCP(ERR_SESS_UNKNOWN_SESSMSG_TYPE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr(), errReason);

    // The other signaling message types require no further action
    default:
     break;
   }
 }


void SrvSessMgr::dispatchRecvSessMsg()
 {
  switch(_sessMgrState)
   {

    case SessMgr::IDLE:
     switch(_recvSessMsgType)
      {
       case FILE_UPLOAD_REQ:
        _sessMgrState = UPLOAD;
        srvUploadStart();
        break;

       case FILE_DOWNLOAD_REQ:
        _sessMgrState = DOWNLOAD;
        //srvDownloadStart();
        break;

       case FILE_DELETE_REQ:
        _sessMgrState = DELETE;
        //srvDeleteStart();
        break;

       case FILE_RENAME_REQ:
        _sessMgrState = RENAME;
        //srvRenameStart();
        break;

       case FILE_LIST_REQ:
        _sessMgrState = LIST;
        //srvListStart();
        break;

       default:
        sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"\"" + std::to_string(_recvSessMsgType) + "\""
                                                         "session message received in the 'IDLE' session state");
      }
     break;

    // TODO

    default:
     sendSrvSessSignalMsg(ERR_INTERNAL_ERROR,"Invalid server session manager state (" + std::to_string(_sessMgrState) + ")");
   }
 }


/* ------------------------- 'UPLOAD' Callback Methods ------------------------- */

// TODO: Rewrite descriptions
void SrvSessMgr::srvUploadStart()
 {
  // Whether the client's storage pool contains a file with the
  // same name of the one the client is requesting to upload
  bool fileUpExists;

  // Load the name and metadata of the file the client is requesting to upload
  loadRemFileInfo();

  // TODO: Remove
  _remFileInfo->printInfo();

  // Check whether a file with such name already exists in
  // the client's storage pool by attempting to load its metadata
  try
   {
    _locFileInfo = new FileInfo(*_srvConnMgr._poolDir + "/" + _remFileInfo->fileName);
    fileUpExists = true;
   }
  catch(sessErrExcp& locFileError)
   {
    if(locFileError.sesErrCode == ERR_SESS_FILE_READ_FAILED)
     fileUpExists = false;
    else
     if(locFileError.sesErrCode == ERR_SESS_FILE_IS_DIR)
      sendSrvSessSignalMsg(ERR_INTERNAL_ERROR,"The file \"" + _remFileInfo->fileName + " the client is attempting"
                                              "to upload already exists in their storage pool as a directory");
   }

  // If a file with such name was found
  if(fileUpExists)
   {
    // Prepare a 'SessMsgFileInfo' session message of type 'FILE_EXISTS'
    // containing the local file name and metadata and send it to the client
    sendLocalFileInfo(FILE_EXISTS);

    // Update the server session manager 'UPLOAD' sub-state
    _srvSessMgrSubstate = WAITING_CLI_CONF;

    // TODO: Remove
    std::cout << "in srvUploadStart(), FILE_EXISTS (WAITING_CLI_CONF)" << std::endl;
   }

  // Otherwise, if it was not found
  else
   {
    // If the file to be uploaded is empty
    if(_remFileInfo->fileMeta.fileSize == 0)
     {
      // Touch the file in the client's pool dir
      std::ofstream upFile(*_srvConnMgr._poolDir + "/" + _remFileInfo->fileName);

      // TODO: Set file last modification time?

      // TODO: Remove
      std::cout << "in srvUploadStart(), FILE_NOT_EXISTS, empty (COMPLETED)" << std::endl;

      // Send the 'COMPLETED' signaling message
      sendSrvSessSignalMsg(COMPLETED);

      // Reset the server session manager state
      resetSrvSessState();
     }

    // Otherwise, if it is not empty
    else
     {
      // Send the 'FILE_NOT_EXISTS' signaling message
      sendSrvSessSignalMsg(FILE_NOT_EXISTS);

      // Change the associated connection manager reception mode to 'RECV_RAW'
      _srvConnMgr._recvMode = ConnMgr::RECV_RAW;

      // Update the server session manager 'UPLOAD' sub-state
      _srvSessMgrSubstate = WAITING_CLI_DATA;

      // TODO: Remove
      std::cout << "in srvUploadStart(), FILE_NOT_EXISTS, non-empty (WAITING_CLI_DATA)" << std::endl;
     }
   }
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief Server session manager object constructor, initializing the session parameters
 *        of the authenticated client associated with the srvConnMgr parent object
 * @param srvConnMgr A reference to the server connection manager parent object
 */
SrvSessMgr::SrvSessMgr(SrvConnMgr& srvConnMgr)
  : SessMgr(reinterpret_cast<ConnMgr&>(srvConnMgr)), _srvSessMgrSubstate(SRV_IDLE), _srvConnMgr(srvConnMgr)
 {}

/* Same destructor of the SessMgr base class */

/* ============================= OTHER PUBLIC METHODS ============================= */

/**
 * @brief Resets all session parameters in preparation for the next
 *        session command to be executed by the server session manager
 */
void SrvSessMgr::resetSrvSessState()
 {
  // Reset the server session manage sub-state
  _srvSessMgrSubstate = SRV_IDLE;

  // Reset the base session parameters
  resetSessState();

  // TODO: Necessary? why?
  // Set that the client connection must be maintained
  // _srvConnMgr._keepConn = true;
 }





/**
 * @brief  Server Session message handler, which:\name
 *            1) Unwraps a received session message wrapper from
 *               the primary into the secondary connection buffer\n
 *            2) Asserts the resulting session message to be allowed in
 *               the current server session manager state and substate\n
 *            3) Handles session-resetting or terminating signaling messages\n
 *            4) Handles session error signaling messages\n
 *            5) Valid session messages requiring further action are
 *               dispatched to the session callback method associated
 *               with the session manager current state and substate
 * @throws TODO (most session exceptions)
 */
void SrvSessMgr::srvSessMsgHandler()
{
 // TODO: Remove
 std::cout << "in srvSessMsgHandler()" << std::endl;

 // Unwrap the received session message wrapper stored in the connection's primary
 // buffer into its associated session message in the connection's secondary buffer
 unwrapSessMsg();

 // Interpret the contents of associated connection
 // manager's secondary buffer as a base session message
 SessMsg* sessMsg = reinterpret_cast<SessMsg*>(_srvConnMgr._secBuf);

 // Copy the received session message length
 // and type into their dedicated attributes
 _recvSessMsgLen = sessMsg->msgLen;
 _recvSessMsgType = sessMsg->msgType;

 // If a signaling message type was received, assert the message
 // length to be equal to the size of a base session message
 if(isSessSignalingMsgType(_recvSessMsgType) && _recvSessMsgLen != sizeof(SessMsg))
  sendSrvSessSignalMsg(ERR_MALFORMED_SESS_MESSAGE,"Received a session signaling message of invalid"
                                                  "length (" + std::to_string(_recvSessMsgLen) + ")");

 /*
  * Check whether the received session message type:
  *   1) Should trigger a session state reset or termination,
  *      directly performing the appropriate actions
  *   2) Is valid in the current server session manager state
  *      and substate, signaling the error to the client
  *      and throwing the associated exception otherwise
  */
 switch(_recvSessMsgType)
  {
   /* --------------------------- Command-Starting Session Message Types --------------------------- */

   // Command-starting session messages are allowed in the 'IDLE' state only
   case FILE_UPLOAD_REQ:
   case FILE_DOWNLOAD_REQ:
   case FILE_DELETE_REQ:
   case FILE_RENAME_REQ:
   case FILE_LIST_REQ:
    if(_sessMgrState != IDLE)
     sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"\"" + std::to_string(_recvSessMsgType) + "\""
                                                      "command-starting session message received in session"
                                                      "state \"" + currSessMgrStateToStr() + "\"");
    break;

   /* -------------------------------- 'CONFIRM' Signaling Message -------------------------------- */

   // A client confirmation notification is allowed only in the 'UPLOAD',
   // 'DOWNLOAD' and 'DELETE' states with sub-state 'WAITING_CLI_CONF'
   case CONFIRM:
    if(!((_sessMgrState == UPLOAD || _sessMgrState == DOWNLOAD || _sessMgrState == DELETE)
         && _srvSessMgrSubstate == WAITING_CLI_CONF))
     sendSrvSessSignalMsg(ERR_UNEXPECTED_SESS_MESSAGE,"'CONFIRM' session message received in session"
                                                      "state \"" + currSessMgrStateToStr() + "\"");
    break;

   /* ------------------------------- 'COMPLETED' Signaling Message ------------------------------- */

   // A client completion notification is allowed only in:
   //   1) The 'DOWNLOAD' state of any sub-state
   //   2) The 'LIST' state with sub-state 'WAITING_CLI_COMPL'
   case COMPLETED:

    // Since after sending a 'COMPLETED' message the client has supposedly
    // reset its session state, in case the message is received in an invalid
    // state just throw the associated exception without notifying the client
    if(!((_sessMgrState == DOWNLOAD) || (_sessMgrState == LIST && _srvSessMgrSubstate == WAITING_CLI_COMPL)))
     THROW_SESS_EXCP(ERR_SESS_UNEXPECTED_MESSAGE, abortedCmdToStr(), "'COMPLETED' session message received in"
                                                                     "session state" "\"" + currSessMgrStateToStr() +
                                                                     "\", sub-state " + std::to_string(_srvSessMgrSubstate));

   /* --------------------------------- 'CANCEL' Signaling Message --------------------------------- */

   // A client cancellation notification is allowed in any but the 'IDLE' state
   case CANCEL:

    // Since after sending a 'CANCEL' message the client has supposedly reset its session
    // state, in case such a message is received in the 'IDLE' state just log the error
    // without notifying the client that an unexpected session message was received
    if(_sessMgrState == IDLE)
     LOG_WARNING("Received a 'CANCEL' session message from client \"" + *_srvConnMgr._name + "\" with an idle session manager")
    else

     // If the 'CANCEL' message is allowed, log the operation that was cancelled
     LOG_INFO("Client \"" + *_srvConnMgr._name + "\" cancelled its " + currSessMgrStateToStr() + " operation")

     // Reset the server session state and return
     resetSrvSessState();
     return;

   /* ---------------------------------- 'BYE' Signaling Message ---------------------------------- */

   // The client graceful disconnect notification is allowed in the 'IDLE' state only
   case BYE:

    // If such a message is not received in the 'IDLE' state, just log the
    // error without notifying the client, as it is supposedly disconnecting
    if(_sessMgrState != IDLE)
     LOG_WARNING("Client \"" + *_srvConnMgr._name + "\" gracefully disconnecting with"
                 "the session manager in the \""+ currSessMgrStateToStr() + "\" state")

    // Set the associated connection manager to be terminated and return
    _srvConnMgr._keepConn = false;
    return;

   /* --------------------------------- Error Signaling Messages --------------------------------- */

   // The client reported to have experienced a recoverable internal error
   case ERR_INTERNAL_ERROR:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_INTERNAL_ERROR,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   // The client reported to have received an unexpected session message
   case ERR_UNEXPECTED_SESS_MESSAGE:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_UNEXPECTED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   // The client reported to have received a malformed session message
   case ERR_MALFORMED_SESS_MESSAGE:
    THROW_SESS_EXCP(ERR_SESS_SRV_CLI_MALFORMED_MESSAGE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   // The client reported to have received a session message of unknown type, an error to be attributed to
   // a desynchronization between the connection peers' IVs and that requires the connection to be reset
   case ERR_UNKNOWN_SESSMSG_TYPE:
    THROW_EXEC_EXCP(ERR_SESS_SRV_CLI_UNKNOWN_SESSMSG_TYPE,"Client: \""+ *_srvConnMgr._name + "\", " + abortedCmdToStr());

   /* ----------------------------------- Unknown Message Type ----------------------------------- */

   // A session message of unknown type has been received, an error to be attributed to a
   // desynchronization between the connection peers' IVs and that requires the connection to be reset
   default:
    sendSrvSessSignalMsg(ERR_UNKNOWN_SESSMSG_TYPE,std::to_string(_recvSessMsgType));
  }

 /*
  * At this point the received session message type is valid
  * for the current server session manager state and sub-state
  */

 // TODO: Comment
 // LOG: Received session message length and type
 std::cout << "_recvSessMsgLen = " << _recvSessMsgLen << std::endl;
 std::cout << "_recvSessMsgType = " << _recvSessMsgType << std::endl;

 // Dispatch the received session message to the session callback method
 // associated with the session manager current state and substate
 dispatchRecvSessMsg();
}


// TODO: Placeholder implementation
void SrvSessMgr::recvRaw(size_t recvBytes)
 {
  std::cout << "In recvRaw()" << std::endl;
 }