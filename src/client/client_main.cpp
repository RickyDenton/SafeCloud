#include <iostream>
#include <string>
#include <stdio.h>              // for fopen(), etc.
#include <limits.h>             // for INT_MAX
#include <string.h>             // for memset()

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>        // for error descriptions

#include <arpa/inet.h>          // Socket stuff
#include <sys/socket.h>
#include <unistd.h>


#include "def.h"

using namespace std;

int main()
{
 int sock = 0;
 int valread;
 int client_fd;
 const char* srvIP = SRV_IP;
 int srvPort = SRV_PORT;
 struct sockaddr_in srv_addr;
 char climsg[1024];
 char buffer[1024] = { 0 };

 cout<<"Hello There client, SRV_PORT = "<< srvPort << endl;

 if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
   cerr << "<FATAL," << __LINE__ << ">: client Socket Creation Failed! " << endl;
   exit(EXIT_FAILURE);
  }

 srv_addr.sin_family = AF_INET;
 srv_addr.sin_port = htons(srvPort);

 // Convert IPv4 and IPv6 addresses from text to binary form
 if(inet_pton(AF_INET, srvIP, &srv_addr.sin_addr) <= 0)
  {
   cerr << "<FATAL," << __LINE__ << ">: Cannot convert server IP address to binary! " << endl;
   exit(EXIT_FAILURE);
  }

 if((client_fd = connect(sock, (const struct sockaddr*)&srv_addr,sizeof(srv_addr))) < 0)
  {
   cerr << "<FATAL," << __LINE__ << ">: client Connection Failed! " << endl;
   exit(EXIT_FAILURE);
  }

 cout << "Message to send to server: ";
 cin >> climsg;

 send(sock, climsg, strlen(climsg), 0);

 valread = read(sock, buffer, 1024);

 cout << "server returned: " << buffer;

 // Close the connection socket
 close(client_fd);

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