#include <iostream>
#include <string>
#include <stdio.h>              // for fopen(), etc.
#include <limits.h>             // for INT_MAX
#include <string.h>             // for memset()

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>        // for error descriptions

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>


#include "def.h"


using namespace std;

int main()
{
 struct sockaddr_in myAddr;
 int srvPort = SRV_PORT;
 int list_sock;
 int conn_sock;
 int sock_opt = 1;
 int valread;
 char buffer[1024] = { 0 };
 unsigned char* hello = (unsigned char*) "Hello from server";

 cout<<"Hello There server, Line = " << __LINE__ <<", SRV_PORT = "<< srvPort << endl;

 // Create Listening Socket
 list_sock = socket(AF_INET, SOCK_STREAM, 0);
 if(list_sock == 0)
  {
   cerr << "<FATAL," << __LINE__ << ">: Listening Socket Creation Failed! " << endl;
   exit(EXIT_FAILURE);
  }

 // Set Listening Socket Options
 if(setsockopt(list_sock, SOL_SOCKET,
               SO_REUSEADDR | SO_REUSEPORT, &sock_opt,
               sizeof(sock_opt)) == -1)
  {
   cerr << "<FATAL," << __LINE__ << ">: Listening Socket Options Setting Failed! " << endl;
   exit(EXIT_FAILURE);
  }

 // Bind myAddr
 myAddr.sin_family = AF_INET;
 myAddr.sin_addr.s_addr = INADDR_ANY;
 myAddr.sin_port = htons(SRV_PORT);

 // Bind socket
 if(bind(list_sock, (struct sockaddr*)&myAddr,sizeof(myAddr)) < 0)
  {
   cerr << "<FATAL," << __LINE__ << ">: Socket Binding Failed! " << endl;
   exit(EXIT_FAILURE);
  }

 // Listen Socket
 if(listen(list_sock, 20) < 0)
  {
   cerr << "<FATAL," << __LINE__ << ">: Socket Listening Failed! " << endl;
   exit(EXIT_FAILURE);
  }

 cout << "All ok up to the connect" << endl;

 // Accept a connection
 if((conn_sock = accept(list_sock, (struct sockaddr*)&myAddr,(socklen_t*)&myAddr)) < 0)
  {
   cerr << "<FATAL," << __LINE__ << ">: Socket Accept Failed! " << endl;
   exit(EXIT_FAILURE);
  }

 // Read from client
 valread = read(conn_sock, buffer, 1024);
 cout << "client sent: " << buffer << endl;

 // Reply to client
 send(conn_sock, hello, 1024, 0);


 // Close the connection socket
 close(conn_sock);

 // Close the listening socket
 shutdown(list_sock, SHUT_RDWR);

 return 0;
}



/*

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define PORT 8080

int main(int argc, char const* argv[])
{
    int sock = 0, valread, client_fd;
    struct sockaddr_in serv_addr;
    char* hello = "Hello from client";
    char buffer[1024] = { 0 };
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)
        <= 0) {
        printf(
            "\nInvalid address/ Address not supported \n");
        return -1;
    }

    if ((client_fd
         = connect(sock, (struct sockaddr*)&serv_addr,
                   sizeof(serv_addr)))
        < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    send(sock, hello, strlen(hello), 0);
    printf("Hello message sent\n");
    valread = read(sock, buffer, 1024);
    printf("%s\n", buffer);

    // closing the connected socket
    close(client_fd);
    return 0;
}
 */