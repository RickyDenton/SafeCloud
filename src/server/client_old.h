#ifndef SAFECLOUD_CLIENT_OLD_H
#define SAFECLOUD_CLIENT_OLD_H

/* SafeCloud Client Class Definition */

/* ================================== INCLUDES ================================== */
#include <stdio.h>
#include <unistd.h>
#include <unordered_map>

/* ============================== CLASS DEFINITION ============================== */

enum clientType
 {
  GUEST,     // A client that is authenticating via the STSM handshake protocol (_name = "Guest "+ cski)
  USER       // A client that has successfully logged in (_name = username)
 };


class client_old
 {
  private:

   /* ------------------------- Attributes ------------------------- */

   // TODO: STUB

   clientType _cliType;   // The client's type (GUEST or USER)
   const int  _csk;       // The client connection socket
   char       _ip[16];    // The client's IP address
   const int  _port;      // The client's port
   char       _name[31];  // The client's name (a temporary one for guests and the username for users)
   int        _skey;      // The client's session key
   int        _iv;        // The client's initialization vector

   /* -------------------------- Methods -------------------------- */

   // Reads data from the client's connection socket into the specified buffer
   bool recvCheck(char* buf, size_t bufSize, ssize_t& recvSize);

  public:

   /* ---------------- Constructors and Destructor ---------------- */
   client_old(int csk, const char* ip, int port);
   ~client_old();

   /* ----------------------- Other Methods ----------------------- */

   // Attempts to read data destined to the client from its connection socket and performs
   // the appropriate actions depending on its cliType and state, returning an indication
   // on whether the client connection should be maintained ('true') or not ('false')
   bool recvData();

   // Returns the client's name
   char* getName();
 };


/* ============================== TYPE DEFINITIONS ============================== */

// An unordered map used for associating connection sockets' file descriptors to their client objects
typedef std::unordered_map<int,client_old*> clientMap;

// An iterator for the clientMap type
typedef std::unordered_map<int,client_old*>::iterator cliMapIt;

#endif //SAFECLOUD_CLIENT_OLD_H