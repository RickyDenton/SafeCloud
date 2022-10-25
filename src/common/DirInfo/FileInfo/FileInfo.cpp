/* FileInfo class methods definitions */

/* ================================== INCLUDES ================================== */
#include "FileInfo.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"
#include "utils.h"


/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief  FileInfo object path constructor, initializing the
 *         file name and metadata from its absolute path
 * @param  fileAbsPath The file's absolute path
 * @throws ERR_SESS_FILE_INVALID_NAME  Invalid Linux file name
 * @throws ERR_SESS_FILE_READ_FAILED   Error in reading the file's metadata
 * @throws ERR_SESS_FILE_IS_DIR        The file is in fact a directory
 * @throws ERR_SESS_FILE_META_NEGATIVE The file presents negative metadata values
 * @throws ERR_FILE_TOO_LARGE          The file is too large (> 9999GB)
 */
FileInfo::FileInfo(const std::string& fileAbsPath) : fileName(), meta(nullptr)
{
 // Stores the file's absolute path as a C string
 char fileAbsPathC[PATH_MAX];

 // Used for reading the file's metadata via the "stat.h" library
 struct stat fileInfo{};

 // Convert the file's absolute path to a C string
 strcpy(fileAbsPathC,fileAbsPath.c_str());

 // Extract and initialize the file's name
 fileName = basename(fileAbsPathC);

 // Assert the file name string to consist of a valid Linux file name
 validateFileName(fileName);

 // Attempt to read the file's metadata
 if(stat(fileAbsPathC, &fileInfo) != 0)
  THROW_SESS_EXCP(ERR_SESS_FILE_READ_FAILED, fileAbsPathC, ERRNO_DESC);

 // Ensure the file not to be a directory
 if(S_ISDIR(fileInfo.st_mode))
  THROW_SESS_EXCP(ERR_SESS_FILE_IS_DIR,fileAbsPath);

 // Initialize the file's metadata
 meta = new FileMeta(fileInfo.st_size, fileInfo.st_mtime, fileInfo.st_ctime);
}


/**
 * @brief  FileInfo object values constructor, initializing its attributes
 *         to the provided values
 * @param  fileName_     The file's name
 * @param  fileSize_     The file's size
 * @param  lastModTime_  The file's last modification time
 * @param  creationTime_ The file's creation time
 * @note   Conversely from the object path constructor, this constructor does
 *         not verify whether such a file exists in the local file system
 * @throws ERR_SESS_FILE_INVALID_NAME  Invalid Linux file name
 * @throws ERR_SESS_FILE_META_NEGATIVE The file presents negative metadata values
 * @throws ERR_FILE_TOO_LARGE          The file is too large (> 9999GB)
 */
FileInfo::FileInfo(std::string& fileName_, long int fileSize_, long int lastModTime_, long int creationTime_)
   : fileName(std::move(fileName_)), meta(new FileMeta(fileSize_,lastModTime_,creationTime_))
 {
  // Assert the file name string to consist of a valid Linux file name
  validateFileName(fileName);
 }


/**
 * @brief FileInfo object destructor, deleting the file's metadata
 */
FileInfo::~FileInfo()
 { delete meta; }


/* ============================ OTHER PUBLIC METHODS ============================ */

/* --------------------------- File Metadata Printing --------------------------- */

/**
 * @brief Prints the file size as a "size_value||size_unit" string, with:\n
 *          - "size_value" ranging between [0,9999]\n
 *          - "size_unit" consisting either in "B", "KB", "MB" or "GB"\n
 *        The file size can also be formatted by:
 *          - Adding padding so to be aligned beneath a 'SIZE' table header
 *          - Printing it in bold
 * @param addPadding Whether padding should be added to the file size
 * @param printBold  Whether the file size should be printed in bold
 */
void FileInfo::printFormattedSize(bool addPadding, bool printBold) const
 { meta->printFormattedSize(addPadding,printBold);  }


/**
 * @brief Prints the file's last modification time as a
 *        "HH:MM:SS DD/MM/YY" string, possibly in bold
 * @param printBold Whether to print the file's
 *                  last modification time in bold
 */
void FileInfo::printFormattedLastModTime(bool printBold) const
 { meta->printFormattedLastModTime(printBold); }


/**
 * @brief Prints the file's creation time as a
 *        "HH:MM:SS DD/MM/YY" string, possibly in bold
 * @param printBold Whether to print the file's
 *                  creation time in bold
 */
void FileInfo::printFormattedCreationTime(bool printBold) const
 { meta->printFormattedCreationTime(printBold); }


/* ----------------------------- File-Wide Printing ----------------------------- */

/**
 * @brief Prints the indented file's name and metadata on stdout
 */
void FileInfo::printFileInfo() const
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
  meta->printFormattedSize(false, false);
  std::cout << std::endl;

  // File Last Modification Time
  std::cout << "Last Modified: ";
  meta->printFormattedLastModTime(false);
  std::cout << std::endl;

  // File Creation Time
  std::cout << "Created:       ";
  meta->printFormattedCreationTime(false);
  std::cout << std::endl;

  // Indentation
  printf("\n");
 }


/**
 * @brief  Prints a table comparing the metadata of the FileInfo (or 'local file') object
 *         with another FileInfo (or 'remote file') object with the same 'fileName'
 * @param  remFileInfo The FileInfo associated with the remote file
 * @throws ERR_FILEINFO_COMP_NULL       NULL 'remFileInfo' argument
 * @throws ERR_FILEINFO_COMP_DIFF_NAMES The two files have different names
 */
void FileInfo::compareMetadata(FileInfo* remFileInfo) const
 {
  // Ensure the 'remFileInfo' argument to have been initialized
  if(remFileInfo == nullptr)
   THROW_SESS_EXCP(ERR_SESS_FILE_INFO_COMP_NULL);

  // Ensure the local and remote files to have the same name
  if(fileName != remFileInfo->fileName)
   THROW_SESS_EXCP(ERR_SESS_FILE_INFO_COMP_DIFF_NAMES, "local: \"" + fileName + "\", remote: \"" + remFileInfo->fileName + "\"");

  /* -------------------- Files Metadata Comparison Table -------------------- */

  // Indentation
  printf("\n");

  // Print the files' metadata legend
  std::cout << "        SIZE     LAST MODIFIED      CREATION TIME "  << std::endl;
  std::cout << "       --------------------------------------------" << std::endl;

  /* -------------------------- Local File Metadata -------------------------- */

  // Print the local file table header
  std::cout << "LOCAL  ";

  // Print the local file size, in bold if it is
  // greater or equal than the remote file size
  meta->printFormattedSize(true, meta->fileSizeRaw >= remFileInfo->meta->fileSizeRaw);

  // Indentation between the "SIZE TIME" and "LAST MODIFIED" headers
  printf("  ");

  // Print the local file last modification time, in bold if it is
  // more recent or equal than the remote file last modification time
  printFormattedLastModTime(meta->lastModTimeRaw >= remFileInfo->meta->lastModTimeRaw);

  // Indentation between the "LAST MODIFIED" and "CREATION TIME" headers
  printf("  ");

  // Print the local file creation time
  printFormattedCreationTime(false);

  // Indentation
  printf("\n");

  /* ------------------------- Remote File Metadata ------------------------- */

  // Print the remote file table header
  std::cout << "REMOTE ";

  // Print the remote file size, in bold if it is
  // greater or equal than the local file size
  remFileInfo->printFormattedSize(true, remFileInfo->meta->fileSizeRaw >= meta->fileSizeRaw);

  // Indentation between the "SIZE TIME" and "LAST MODIFIED" headers
  printf("  ");

  // Print the remote file last modification time, in bold if it is
  // more recent or equal than the local file last modification time
  remFileInfo->printFormattedLastModTime(remFileInfo->meta->lastModTimeRaw >= meta->lastModTimeRaw);

  // Indentation between the "LAST MODIFIED" and "CREATION TIME" headers
  printf("  ");

  // Print the remote file creation time
  remFileInfo->printFormattedCreationTime(false);

  // Indentation
  printf("\n\n");
 }