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
 * @brief Prompt the user on whether to attempt to re-establish a connection with the SafeCloud Server
 * @return 'true' if the user wants to reconnect, 'false' otherwise
 */
bool askReconnection();


#endif //SAFECLOUD_CLIENT_UTILS_H
