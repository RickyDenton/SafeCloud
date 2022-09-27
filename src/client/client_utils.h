#ifndef SAFECLOUD_CLIENT_UTILS_H
#define SAFECLOUD_CLIENT_UTILS_H

/* SafeCloud Client Utility Functions Declarations */

/**
 * @brief Flushes carriage return and EOF characters from the input stream (stdin)
 */
void flush_CR_EOF();


/**
 * @brief Reads the first non-carriage return character from stdin, flushing following carriage returns and 'EOF' characters
 * @return The the first non-carriage return character read from stdin
 */
int get1char();


/**
 * @brief Reads a character representing a binary choice (y/Y or n/N) read from stdin, prompting the user until a valid character is provided
 * @return The y/Y or n/N character provided by the user
 */
int getYNChar();


/**
 * @brief  Asks the user a yes-no question, continuously reading a character from stdin until a valid response is provided (y/Y or n/N)
 * @return 'true' if the user answers y/Y or 'false' if it answers 'n/N'
 */
bool askUser(const char* question);


#endif //SAFECLOUD_CLIENT_UTILS_H
