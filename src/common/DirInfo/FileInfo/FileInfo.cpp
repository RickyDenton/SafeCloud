/* FileInfo class methods definitions */

/* ================================== INCLUDES ================================== */
#include "FileInfo.h"
#include "errCodes/execErrCodes/execErrCodes.h"


/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief fileMetadata default constructor, initializing its fields to "-1"
 */
fileMetadata::fileMetadata() : fileSize(-1), creationTime(-1), lastModTime(-1)
 {}

/**
 * @brief fileMetadata object values constructor, initializing its fields to the provided values
 */
fileMetadata::fileMetadata(long int fileSize_, long int creationTime_, long int lastModTime_) : fileSize(fileSize_), creationTime(creationTime_), lastModTime(lastModTime_)
 {}

/**
 * @brief  FileInfo object constructor, initializing the file name and metadata
 * @param  dirAbsPath The absolute path of the directory the file is contained in
 * @param  fileName_  The file's name
 * @throws ERR_FILE_READ_FAILED Error in reading the file's metadata
 */
FileInfo::FileInfo(std::string* dirAbsPath,std::string fileName_) : fileName(std::move(fileName_)), fileMeta()
 {
  // Used for reading the file's metadata via the "stat.h" library
  struct stat fileInfo{};

  // Attempt to read the file's metadata
  if(stat((*dirAbsPath + '/' + fileName).c_str(), &fileInfo) != 0)
   THROW_EXEC_EXCP(ERR_FILE_READ_FAILED,(*dirAbsPath + fileName),ERRNO_DESC);

  // Initialize the file's metadata
  fileMeta.fileSize = fileInfo.st_size;
  fileMeta.creationTime = fileInfo.st_ctime;
  fileMeta.lastModTime = fileInfo.st_mtime;
 }


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
