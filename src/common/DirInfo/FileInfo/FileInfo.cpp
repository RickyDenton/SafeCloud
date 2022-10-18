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
 * @brief FileInfo object values constructor, initializing its attributes
 *        to the provided values
 * @param fileName_     The file's name
 * @param fileSize_     The file's size
 * @param creationTime_ The file's creation time
 * @param lastModTime_  The file's last modification time
 * @note  Conversely from the object path constructor, this constructor does
 *        not verify whether such a file exists in the local file system
 */
FileInfo::FileInfo(std::string& fileName_, long int fileSize_, long int creationTime_, long int lastModTime_)
   : fileMeta(fileSize_,creationTime_,lastModTime_), fileName(std::move(fileName_))
 {}


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief  Writes in a buffer the file size formatted
 *         as the string "size_value||size_unit", with:
 *          - "size_value" ranging between [0,9999]
 *          - "size_unit" consisting either in "B", "KB", "MB" or "GB"
 * @param  formSizeDest The buffer where to write the formatted file size
 * @note   This function assumes the destination buffer to be large
 *         enough to contain the formatted file size (at least 7 bytes)
 * @throws ERR_FILE_TOO_LARGE The file size is too large (> 9999GB)
 */
void FileInfo::getFormattedSize(char* formSizeDest) const
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
         sprintf(formSizeDest, "%ldGB", candSize);  // XXXXGB
       }
      else
       sprintf(formSizeDest,"%ldMB",candSize); // XXXXMB
     }
    else
     sprintf(formSizeDest,"%ldKB",candSize); // XXXXKB
   }
  else
   sprintf(formSizeDest,"%ldB",candSize); // XXXXB
 }


/**
 * @brief Prints the indented file's name and metadata on stdout
 * @throws ERR_FILE_TOO_LARGE The file size is too large (> 9999GB)
 */
void FileInfo::printInfo()
 {
  char fileSize[7];          // The file size formatted as a string
  char timeDate[18];         // A creation or last modified time value expressed as the string "HH:MM:SS DD/MM/YY"
  struct tm timeCalendar{};  // Stores a creation or last modification time in a calendar-like representation

  // Indentation
  printf("\n");

  // File name
  std::cout << fileName << std::endl;

  // File name separator
  for(int i = 0; i<fileName.length(); i++)
   printf("-");

  // Indentation
  printf("\n");

  // Formatted file size
  getFormattedSize(fileSize);
  std::cout << "Size:          "<< fileSize << std::endl;

  // File creation time
  timeCalendar = *localtime(&fileMeta.creationTime);
  strftime(timeDate, sizeof(timeDate), "%H:%M:%S %d/%m/%y", &timeCalendar);
  std::cout << "Created:       "<< timeDate << std::endl;

  // File last modification time
  timeCalendar = *localtime(&fileMeta.lastModTime);
  strftime(timeDate, sizeof(timeDate), "%H:%M:%S %d/%m/%y", &timeCalendar);
  std::cout << "Last Modified: "<< timeDate << std::endl;

  // Indentation
  printf("\n");
 }


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
