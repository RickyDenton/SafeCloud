/* SafeCloud Client Utility Functions */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>

using namespace std;


/* ============================ FUNCTIONS DEFINITIONS ============================ */

/**
 * @brief Reads the first non-carriage return character from stdin, flushing following carriage returns and 'EOF' characters
 * @return The the first non-carriage return character read from stdin
 */
int get1char()
 {
 int ret;  // First non-carriage return character in the stdin to return
 int c;    // Support character used for removing trailing carriage return and EOF characters from the stdin

 // Read the first non-carriage return from the stdin, prompting user input if it is not present
 do
  ret = getchar();
 while (ret == '\n');

 // Flush carriage return and EOF characters from the input stream
 do
  c = getchar();
 while ((c != '\n') && (c != EOF));

 // Return the first non-carriage return character read from stdin
 return ret;
 }


/**
 * @brief Reads a character representing a binary choice (y/Y or n/N) read from stdin, prompting the user until a valid character is provided
 * @return The y/Y or n/N character provided by the user
 */
int getYNChar()
 {
 int ret; // Character to return

 // Read the first character from stdin until a y/Y or n/N is provided
 do
  {
  ret = get1char();
  if((ret != 'Y') && (ret != 'N') && (ret != 'y') && (ret != 'n'))
   std::cout << "Please answer \"yes\" (y/Y) or \"no\" (n/N): ";
  } while((ret != 'Y') && (ret != 'N') && (ret != 'y') && (ret != 'n'));

 return ret;
 }


/**
 * @brief Prompt the user on whether to attempt to re-establish a connection with the SafeCloud Server
 * @return 'true' if the user wants to reconnect, 'false' otherwise
 */
bool askReconnection()
 {
  int retryConn;  // A character representing the user choice on whether attempting to re-establish connection with the server (y/Y or n/N)

  cout << "Try again to connect with the server? (Y/N): ";

  // Read the first y/Y or n/N character from standard input
  retryConn = getYNChar();

  // Return true or false depending on the user's choice
  if((retryConn == 'Y') || (retryConn == 'y'))
   return true;
  return false;
 }