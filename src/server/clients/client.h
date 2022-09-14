#ifndef SAFECLOUD_CLIENT_H
#define SAFECLOUD_CLIENT_H

/* SafeCloud client interface definition */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <stdio.h>
#include <unistd.h>
#include <unordered_map>


/* ============================== TYPE DEFINITIONS ============================== */

/* --------------------------- Connected Clients Map --------------------------- */
class client; // Forward declaration

// An unordered map used for associating the file descriptor of open connection sockets to their client objects
typedef std::unordered_map<int,client*> clientMap;

// clientMap iterator
typedef std::unordered_map<int,client*>::iterator clientMapIt;


/* -------------------------- postAction Enumeration -------------------------- */
/**
 * @brief readData() return indicating required server operations
 *        after the incoming client data has been processed
 */
enum postAction
{
 KEEP_CONN,   // Keep the connection socket open  (no action required)
 DELETE_OBJ,  // Delete the current client object (returned when a Guest logs in as a User)
 CLOSE_CONN   // Delete the client object and close its connection socket
};


/* ----------------------------- Client Interface ----------------------------- */
class client
 {
  protected:

   /* ------------------------- Attributes ------------------------- */
   const int  _csk;    // The file descriptor of the client's connection socket
   char       _ip[16]; // The client's IP address
   const int  _port;   // The client's port

  public:

   /* ---------------- Constructors and Destructor ---------------- */
   // Constructor
   //
   // NOTE: ISO C++ forbids the initialization of constant arrays via initialization lists
   //
   client(int csk,const char* ip, int port) : _csk(csk), _ip(), _port(port)
    { sprintf(_ip,"%15s",ip); }

   // Destructor (virtual)
   virtual ~client()
    {}

   /* ------==------------ Getters and Setters --------====-------- */
   int getCsk() const
    { return _csk; };

   const char* getIP()
    { return _ip; }

   int getPort() const
    { return _port; }

   /* ----------------------- Other Methods ----------------------- */
   // Read incoming client data
   virtual postAction readData() = 0;
 };

#endif //SAFECLOUD_CLIENT_H