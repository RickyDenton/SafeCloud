/* FileMeta Class Implementation */

/* ================================== INCLUDES ================================== */
#include "FileMeta.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"


/* =============================== PRIVATE METHODS =============================== */

/**
 * @brief   Stringyfies the raw file size into a
 *          "size_value||size_unit" string, with:\n\n
 *             - "size_value" ranging between [0,9999]\n\n
 *             - "size_unit" consisting either in "B", "KB", "MB" or "GB"
 * @throws ERR_FILE_TOO_LARGE The file is too large (> 9999GB)
 */
void FileMeta::rawSizeToStr()
 {
  // The candidate stringifyed "size_value"
  signed long candSize = fileSizeRaw;

  // If the candidate file size is greater than 9999 bytes
  if(candSize > 9999)
   {
    // Convert the candidate file size in KB
    candSize /= 1024;

    // If the candidate file size is greater than 9999 kilobytes
    if(candSize > 9999)
     {
      // Convert the candidate file size in MB
      candSize /= 1024;

      // if the candidate file size is greater than 9999 megabytes
      if(candSize > 9999)
       {
        // Convert the candidate file size in GB
        candSize /= 1024;

        // if the candidate file size is greater than 9999 gigabytes, throw an error
        if(candSize > 9999)
         THROW_EXEC_EXCP(ERR_FILE_TOO_LARGE,std::to_string(candSize) + " GB");
        else
         sprintf(fileSizeStr, "%dGB", (int)candSize);  // XXXXGB
       }
      else
       sprintf(fileSizeStr, "%dMB", (int)candSize); // XXXXMB
     }
    else
     sprintf(fileSizeStr, "%dKB", (int)candSize); // XXXXKB
   }
  else
   sprintf(fileSizeStr, "%dB", (int)candSize); // XXXXB
 }


/**
 * @brief Stringyfies a raw last modified or creation time in Unix epochs
 *        into its destination buffer as a "HH:MM:SS DD/MM/YY" string
 * @param rawTime The raw time in Unix Epochs
 * @param destBuf The destination buffer address
 */
void FileMeta::rawTimeToStr(signed long rawTime, char* destBuf)
 {
  struct tm timeCalendar{};  // Stores a time in a calendar-like representation

  // Convert the time from epochs to a calendar form
  timeCalendar = *localtime(&rawTime);

  // Format the time as the "HH:MM:SS DD/MM/YY" string into the 'destBuf' buffer
  strftime(destBuf, 18, "%H:%M:%S %d/%m/%y", &timeCalendar);
 }


/* ================================ CONSTRUCTORS ================================ */

/**
 * @brief  fileMetadata values constructor, initializing its raw attributes to the
 *         provided values and its stringifyed attributes to their stringifyed versions
 * @param  fileSizeRaw_     The raw file size in bytes
 * @param  lastModTimeRaw_  The raw file last modified time in Unix Epochs
 * @param  creationTimeRaw_ The raw file creation time in Unix Epochs
 * @throws ERR_SESS_FILE_META_NEGATIVE Negative metadata values were provided
 * @throws ERR_FILE_TOO_LARGE          The file is too large (> 9999GB)
 */
FileMeta::FileMeta(long int fileSizeRaw_, long int lastModTimeRaw_, long int creationTimeRaw_)
 : fileSizeRaw(fileSizeRaw_), lastModTimeRaw(lastModTimeRaw_), creationTimeRaw(creationTimeRaw_),
   fileSizeStr(""), lastModTimeStr(""), creationTimeStr("")
 {
  // Ensure the provided values to be non-negative
  if(fileSizeRaw_ < 0 || lastModTimeRaw_ < 0 || creationTimeRaw_ < 0)
   THROW_SESS_EXCP(ERR_SESS_FILE_META_NEGATIVE);

  // Stringify the raw file size into a "size_value||size_unit" string
  rawSizeToStr();

  // Stringify the raw file last modified time into a "HH:MM:SS DD/MM/YY" string
  rawTimeToStr(lastModTimeRaw,lastModTimeStr);

  // Stringify the raw file creation time into a "HH:MM:SS DD/MM/YY" string
  rawTimeToStr(creationTimeRaw,creationTimeStr);
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief Prints the stringifyed file size to stdout, possibly formatted by:\n\n
 *          - Adding padding so to be aligned beneath a 'SIZE' table header\n\n
 *          - Printing it in bold
 * @param addPadding Whether padding should be added to the file size
 * @param printBold  Whether the file size should be printed in bold
 */
void FileMeta::printFormattedSize(bool addPadding, bool printBold) const
 {
  // The number of padding spaces to be printed
  // before the stringyfied file size (if any)
  unsigned char paddingSpacesBefore = 0;

  // The number of padding spaces to be printed
  // after the stringyfied file size (if any)
  unsigned char paddingSpacesAfter = 0;

  // If padding must be added in printing the stringyfied file size
  if(addPadding)
   {
    // Determine the number of padding spaces to be printed before
    // and after the file size depending on its number of characters
    switch(strlen(fileSizeStr))
     {
      // Minimum size characters (e.g. "9B")
      case 2:
       paddingSpacesBefore = 3;
       paddingSpacesAfter = 1;
       break;

      case 3:
       paddingSpacesBefore = 2;
       paddingSpacesAfter = 1;
       break;

      case 4:
       paddingSpacesBefore = 1;
       paddingSpacesAfter = 1;
       break;

      case 5:
       paddingSpacesBefore = 0;
       paddingSpacesAfter = 1;
       break;

      // Maximum size characters (e.g. "2467MB")
      case 6:
       paddingSpacesBefore = 0;
       paddingSpacesAfter = 0;
       break;
     }
   }

  // Print the padding spaces before the stringyfied file size
  for(int i=0; i<paddingSpacesBefore; i++)
   printf(" ");

  // Print the stringyfied file size, in bold if requested
  if(printBold)
   std::cout << BOLD << fileSizeStr << RESET;
  else
   std::cout << fileSizeStr;

  // Print the padding spaces after the stringyfied file size
  for(int i=0; i<paddingSpacesAfter; i++)
   printf(" ");
 }


/**
 * @brief Prints the stringifyed file's last
 *        modification time to stdout, possibly in bold
 * @param printBold Whether to print the stringifyed
 *                  file's last modification time in bold
 */
void FileMeta::printFormattedLastModTime(bool printBold) const
 {
  // Print the stringyfied file last
  // modification time, in bold if requested
  if(printBold)
   std::cout << BOLD << lastModTimeStr << RESET;
  else
   std::cout << lastModTimeStr;
 }


/**
 * @brief Prints the stringifyed file's creation
 *        time to stdout, possibly in bold
 * @param printBold Whether to print the stringifyed
 *        file's creation time in bold
 */
void FileMeta::printFormattedCreationTime(bool printBold) const
 {
  // Print the stringyfied file creation
  // time, in bold if requested
  if(printBold)
   std::cout << BOLD << creationTimeStr << RESET;
  else
   std::cout << creationTimeStr;
 }