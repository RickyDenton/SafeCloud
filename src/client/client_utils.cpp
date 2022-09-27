/* SafeCloud Client Utility Functions Implementations */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>



/* ============================ FUNCTIONS DEFINITIONS ============================ */

/**
 * @brief Flushes carriage return and EOF characters from the input stream (stdin)
 */
void flush_CR_EOF()
 {
  // Flush carriage return and EOF characters from the input stream
  int c;

  do
   c = getchar();
  while ((c != '\n') && (c != EOF));
 }


/**
 * @brief Reads the first non-carriage return character from stdin, flushing following carriage returns and 'EOF' characters
 * @return The the first non-carriage return character read from stdin
 */
int get1char()
 {
 int ret;  // First non-carriage return character in the stdin to return

 // Read the first non-carriage return from the stdin, prompting user input if it is not present
 do
  ret = getchar();
 while (ret == '\n');

 // Flush carriage return and EOF characters from the input stream
 flush_CR_EOF();

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
 * @brief  Asks the user a yes-no question, continuously reading a character from stdin until a valid response is provided (y/Y or n/N)
 * @return 'true' if the user answers y/Y or 'false' if it answers 'n/N'
 */
bool askUser(const char* question)
 {
  // Ask the user the question
  std::cout << question << " (Y/N): ";

  // Read the user's y/N or n/N answer
  int userAnswer = getYNChar();

  // Return true or false depending on the user's answer
  if((userAnswer == 'Y') || (userAnswer == 'y'))
   return true;
  return false;
 }