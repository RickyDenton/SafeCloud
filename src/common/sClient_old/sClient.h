#ifndef SAFECLOUD_SCLIENT_H
#define SAFECLOUD_SCLIENT_H

/* Abstract class representing a client in the SafeCloud application */

/* ================================== INCLUDES ================================== */
#include <stdio.h>
#include <unistd.h>

/* ============================== CLASS DEFINITION ============================== */

enum sClientType
 {
  GUEST,     // A client that is authenticating via the STSM handshake protocol
  USER       // A client that has successfully logged within the SafeCloud server
 };


class sClient
 {
   private:

    /* ------------------------- Attributes ------------------------- */
    sClientType         _cliType;   // The client's type (GUEST or USER)
    int                 _csk;       // The client connection socket
    char                _name[31];  // The client's name

    unsigned char*      _buf;       // General purpose buffer
    unsigned int        _bufInd;    // Index to the first available byte in the general purpose buffer
    const unsigned int  _bufSize;   // General purpose buffer size

    unsigned char*      _skey;      // The client's current session key
    const unsigned int  _skeySize;  // General purpose buffer size (32 bytes = 256 bits using AES_GCM)
    unsigned char*      _iv;        // The client's current initialization vector value
    const unsigned int  _ivSize;    // Initialization vector size (12 bytes = 96 bits using AES_GCM)

    sMessage*           _sentMsg;   // The last SafeCloud Message sent from the client
    sMessage*           _recvMsg;   // The last SafeCloud Message received from the client

    char*               _tempDir;   // The path to the client's temporary directory

   public:

    /* ---------------- Constructors and Destructor ---------------- */
    sClient(int csk, char* name, char* tempDir);
    ~sClient();

    /* -------------------- Getters and Setters -------------------- */
    char* getName();  // Returns the client's name
 };