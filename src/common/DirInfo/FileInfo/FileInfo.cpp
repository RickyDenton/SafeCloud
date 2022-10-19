/* FileInfo class methods definitions */

/* ================================== INCLUDES ================================== */
#include "FileInfo.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"


/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief fileMetadata default constructor, initializing its fields to "-1"
 */
fileMetadata::fileMetadata() : fileSize(-1), creationTime(-1), lastModTime(-1)
 {}

/**
 * @brief fileMetadata object values constructor, initializing its fields to the provided values
 */
fileMetadata::fileMetadata(long int fileSize_, long int creationTime_, long int lastModTime_)
 : fileSize(fileSize_), creationTime(creationTime_), lastModTime(lastModTime_)
 {}


/**
 * @brief  FileInfo object path constructor, initializing the
 *         file name and metadata from its absolute path
 * @param  fileAbsPath The file's absolute path
 * @throws ERR_SESS_FILE_READ_FAILED Error in reading the file's metadata
 * @throws ERR_SESS_FILE_IS_DIR      The file is in fact a directory
 */
FileInfo::FileInfo(const std::string& fileAbsPath) : fileName(), fileMeta()
{
 // The file's absolute path as a C string
 char fileAbsPathC[PATH_MAX];

 // Used for reading the file's metadata via the "stat.h" library
 struct stat fileInfo{};

 // Convert the file's absolute path to a C string
 strcpy(fileAbsPathC,fileAbsPath.c_str());

 // Attempt to read the file's metadata
 if(stat(fileAbsPathC, &fileInfo) != 0)
  THROW_SESS_EXCP(ERR_SESS_FILE_READ_FAILED, fileAbsPathC, ERRNO_DESC);

 // Ensure the file not to be a directory
 if(S_ISDIR(fileInfo.st_mode))
  THROW_SESS_EXCP(ERR_SESS_FILE_IS_DIR,fileAbsPath);

 // Initialize the file's metadata
 fileMeta.fileSize = fileInfo.st_size;
 fileMeta.creationTime = fileInfo.st_ctime;
 fileMeta.lastModTime = fileInfo.st_mtime;

 // Extract and initialize the file's name
 fileName = basename(fileAbsPathC);
}


/**
 * @brief  FileInfo object values constructor, initializing its attributes
 *         to the provided values
 * @param  fileName_     The file's name
 * @param  fileSize_     The file's size
 * @param  creationTime_ The file's creation time
 * @param  lastModTime_  The file's last modification time
 * @note   Conversely from the object path constructor, this constructor does
 *         not verify whether such a file exists in the local file system
 * @throws ERR_SESS_INVALID_FILE_NAME Invalid file name
 */
FileInfo::FileInfo(std::string& fileName_, long int fileSize_, long int creationTime_, long int lastModTime_)
   : fileMeta(fileSize_,creationTime_,lastModTime_), fileName(std::move(fileName_))
 {
  // The file name cannot consist of the current or the parent's directory
  if(fileName == "." || fileName == "..")
   THROW_SESS_EXCP(ERR_SESS_INVALID_FILE_NAME);

  // The file name cannot contain '/' or '\0' characters
  for(auto& ch : fileName)
   if(ch == '/' || ch == '\0')
    THROW_SESS_EXCP(ERR_SESS_INVALID_FILE_NAME);
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

/* ----------------------------- File Size Printing ----------------------------- */

/**
 * @brief  Writes into a buffer the file size formatted
 *         as a "size_value||size_unit" string, with:\n
 *          - "size_value" ranging between [0,9999]\n
 *          - "size_unit" consisting either in "B", "KB", "MB" or "GB"
 * @param  fileSizeStr The buffer where to write the formatted file size
 * @note   This function assumes the 'fileSizeStr' buffer to be large
 *         enough to contain the formatted file size (at least 7 bytes)
 * @throws ERR_FILE_TOO_LARGE The file size is too large (> 9999GB)
 */
void FileInfo::sizeToStr(char* fileSizeStr) const
 {
  // The candidate file size to be written into the destination buffer
  signed long candSize = fileMeta.fileSize;

  // If the file size is greater than 9999 bytes
  if(candSize > 9999)
   {
    // Convert the candidate file size in KB
    candSize /= 1024;

    // If the file size is greater than 9999 kilobytes
    if(candSize > 9999)
     {
      // Convert the candidate file size in MB
      candSize /= 1024;

      // if the file size is greater than 9999 megabytes
      if(candSize > 9999)
       {
        // Convert the candidate file size in GB
        candSize /= 1024;

        // if the file size is greater than 9999 gigabytes, throw an error
        if(candSize > 9999)
         THROW_EXEC_EXCP(ERR_FILE_TOO_LARGE,std::to_string(candSize) + " GB");
        else
         sprintf(fileSizeStr, "%ldGB", candSize);  // XXXXGB
       }
      else
       sprintf(fileSizeStr, "%ldMB", candSize); // XXXXMB
     }
    else
     sprintf(fileSizeStr, "%ldKB", candSize); // XXXXKB
   }
  else
   sprintf(fileSizeStr, "%ldB", candSize); // XXXXB
 }


/**
 * @brief Prints the file size as a "size_value||size_unit" string, with:\n
 *          - "size_value" ranging between [0,9999]\n
 *          - "size_unit" consisting either in "B", "KB", "MB" or "GB"\n
 *        The file size can also be formatted by:
 *          - Adding padding so to be aligned beneath a 'SIZE' table header
 *          - Printing it in bold
 * @param addPadding Whether padding should be added to the file size
 * @param printBold  Whether the file size should be printed in bold
 * @throws ERR_FILE_TOO_LARGE The file size is too large (> 9999GB)
 */
void FileInfo::printSize(bool addPadding, bool printBold) const
 {
  // Stores the file size as a "size_value||size_unit" string
  char fileSizeStr[7];

  // The number of padding spaces to be
  // printed before the file size (if any)
  unsigned char paddingSpacesBefore = 0;

  // The number of padding spaces to be
  // printed before the file size (if any)
  unsigned char paddingSpacesAfter = 0;

  /* ----------------- File Size to String Conversion ----------------- */

  /* Write into the 'fileSizeStr' buffer the file size
   * formatted as the string "size_value||size_unit", with:
   *    - "size_value" ranging between [0,9999]
   *    - "size_unit" consisting either in "B", "KB", "MB" or "GB"
   */
  sizeToStr(fileSizeStr);

  /* ----------------- File Size Padding Computation ----------------- */

  // If padding spaces must be added in printing the file size
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

      // Unexpected number of characters
      default:
       LOG_CRITICAL("Unexpected file size string length: " + std::to_string(strlen(fileSizeStr)))
      paddingSpacesBefore = 0;
      paddingSpacesAfter = 0;
     }
   }

  /* ----------------------- File Size Printing ----------------------- */

  // Print the padding spaces before the file's size
  for(int i=0; i<paddingSpacesBefore; i++)
   printf(" ");

  // Print the file size, in bold if requested
  if(printBold)
   std::cout << BOLD << fileSizeStr << RESET;
  else
   std::cout << fileSizeStr;

  // Print the padding spaces after the file's size
  for(int i=0; i<paddingSpacesAfter; i++)
   printf(" ");
 }


/* ---------------------------- File Times Printing ---------------------------- */

/**
 * @brief Prints a time in Unix Epochs as a "HH:MM:SS DD/MM/YY" string, possibly in bold
 * @param timeEpochs The time in Unix Epochs
 * @param printBold  Whether the "HH:MM:SS DD/MM/YY" string should be printed in bold
 */
void FileInfo::printTime(signed long timeEpochs, bool printBold)
 {
  char timeDate[18];         // Stores a time as the string "HH:MM:SS DD/MM/YY"
  struct tm timeCalendar{};  // Stores a  time in a calendar-like representation

  // Convert the time from epochs to a calendar form
  timeCalendar = *localtime(&timeEpochs);

  // Format the time as the "HH:MM:SS DD/MM/YY" string in the 'timeDate' buffer
  strftime(timeDate, sizeof(timeDate), "%H:%M:%S %d/%m/%y", &timeCalendar);

  // Print the formatted time, in bold if requested
  if(printBold)
   std::cout << BOLD << timeDate << RESET;
  else
   std::cout << timeDate;
 }


/**
 * @brief Prints the file's last modification time as a
 *        "HH:MM:SS DD/MM/YY" string, possibly in bold
 * @param printBold Whether to print the file's
 *                  last modification time in bold
 */
void FileInfo::printLastModTime(bool printBold) const
 { printTime(fileMeta.lastModTime,printBold); }


/**
 * @brief Prints the file's creation time as a
 *        "HH:MM:SS DD/MM/YY" string, possibly in bold
 * @param printBold Whether to print the file's
 *                  creation time in bold
 */
void FileInfo::printCreationTime(bool printBold) const
 { printTime(fileMeta.creationTime,printBold); }


/* ---------------------------- File Times Printing ---------------------------- */

/**
 * @brief Prints the indented file's name and metadata on stdout
 * @throws ERR_FILE_TOO_LARGE The file size is too large (> 9999GB)
 */
void FileInfo::printInfo() const
 {
  // Indentation
  printf("\n");

  // File name
  std::cout << fileName << std::endl;

  // File name separator
  for(int i = 0; i<fileName.length(); i++)
   printf("-");

  // Indentation
  printf("\n");

  // File Size
  std::cout << "Size:          ";
  printSize(false, false);
  std::cout << std::endl;

  // File Last Modification Time
  std::cout << "Last Modified: ";
  printLastModTime(false);
  std::cout << std::endl;

  // File Creation Time
  std::cout << "Created:       ";
  printCreationTime(false);
  std::cout << std::endl;

  // Indentation
  printf("\n");
 }


/**
 * @brief Prints a table comparing the metadata of the FileInfo (or 'local file') object
 *        with another FileInfo (or 'remote file') object with the same 'fileName'
 * @param remFileInfo The FileInfo associated with the remote file
 * @throws ERR_FILEINFO_COMP_NULL       NULL 'remFileInfo' argument
 * @throws ERR_FILEINFO_COMP_DIFF_NAMES The two files have different names
 */
void FileInfo::compareMetadata(FileInfo* remFileInfo) const
 {
  // Ensure the 'remFileInfo' argument to have been initialized
  if(remFileInfo == nullptr)
   THROW_SESS_EXCP(ERR_FILEINFO_COMP_NULL);

  // Ensure the local and remote files to have the same name
  if(fileName != remFileInfo->fileName)
   THROW_SESS_EXCP(ERR_FILEINFO_COMP_DIFF_NAMES,"local: \"" + fileName + "\", remote: \"" + remFileInfo->fileName + "\"");

  /* -------------------- Files Metadata Comparison Table -------------------- */

  // Indentation
  printf("\n");

  // Print the files' metadata legend
  std::cout << "        SIZE    CREATION TIME      LAST MODIFIED " << std::endl;
  std::cout << "       -------------------------------------------" << std::endl;

  /* -------------------------- Local File Metadata -------------------------- */

  // Print the local file table header
  std::cout << "LOCAL ";

  // Print the local file size, in bold if it is
  // greater or equal than the remote file size
  printSize(true,fileMeta.fileSize >= remFileInfo->fileMeta.fileSize);

  // Indentation between the "SIZE" and "CREATION TIME" headers
  printf("  ");

  // Print the local file last modification time, in bold if it is
  // more recent or equal than the remote file last modification time
  printLastModTime(fileMeta.lastModTime >= remFileInfo->fileMeta.lastModTime);

  // Indentation between the "CREATION TIME" and "LAST MODIFIED" headers
  printf("  ");

  // Print the local file creation time
  printCreationTime(false);

  // Indentation
  printf("\n");

  /* ------------------------- Remote File Metadata ------------------------- */

  // Print the remote file table header
  std::cout << "REMOTE";

  // Print the remote file size, in bold if it is
  // greater or equal than the local file size
  remFileInfo->printSize(true,fileMeta.fileSize >= remFileInfo->fileMeta.fileSize);

  // Indentation between the "SIZE" and "CREATION TIME" headers
  printf("  ");

  // Print the remote file last modification time, in bold if it is
  // more recent or equal than the local file last modification time
  remFileInfo->printLastModTime(fileMeta.lastModTime >= remFileInfo->fileMeta.lastModTime);

  // Indentation between the "CREATION TIME" and "LAST MODIFIED" headers
  printf("  ");

  // Print the remote file creation time
  remFileInfo->printCreationTime(false);

  // Indentation
  printf("\n\n");
 }


// TODO: Needed? In case, section
/**
 * @brief  Reads and returns a file's metadata
 * @param  fileAbsPath The file's absolute path
 * @return A dynamic structure containing the file's metadata, or
 *         "nullptr" if the file does not exist or could not be opened
 * @note   It is up to the caller to delete() the returned struct when no longer needed
 */
fileMetadata* FileInfo::getFileMetadata(std::string* fileAbsPath)
 {
  // Used for reading the file's metadata via the "stat.h" library
  struct stat fileInfo{};

  // Attempt to read the file's metadata

  // Attempt to read the file's metadata, returning a 'nullptr' in case
  // of failure (i.e. the file doesn't exist or could not be read)
  if(stat(fileAbsPath->c_str(), &fileInfo) != 0)
   return nullptr;

  // Initialize a fileMetadata struct with
  // the file's metadata and return its address
  return new fileMetadata(fileInfo.st_size,fileInfo.st_ctime,fileInfo.st_mtime);
 }