/* DirInfo class methods definitions */

/* ================================== INCLUDES ================================== */
#include "DirInfo.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief DirInfo empty constructor, creating an
 *        empty object of implicit directory path
 */
DirInfo::DirInfo()
 : dirPath(new std::string("(NO_PATH)")), dirFiles(), dirRawSize(0), numFiles(0)
 {}

/**
 * @brief  DirInfo absolute path constructor, creating a snapshot
 *         of the files (names + metadata) in a directory
 * @param  dirAbspath The absolute path of the directory to create the snapshot of
 * @throws ERR_DIR_OPEN_FAILED        The target directory was not found
 * @throws ERR_SESS_FILE_READ_FAILED  Error in reading a file's metadata
 * @throws ERR_SESS_DIR_SIZE_OVERFLOW The directory contents' raw size exceeds 4GB
 */
DirInfo::DirInfo(std::string* dirAbspath)
 : dirPath(dirAbspath), dirFiles(), dirRawSize(0), numFiles(0)
 {
  // The file descriptor used for reading the target directory
  DIR*           dir;

  // Information on a file in the target directory as returned by the "dirent.h" library
  struct dirent* dirFile;

  // Information on a file (name + metadata) in the target directory
  FileInfo*      fileInfo;

  // The raw size of information of a file in the target directory
  unsigned short fileInfoRawSize;

  // Convert the directory path to a C string
  const char* dirPathC = dirPath->c_str();

  // Open the temporary directory
  dir = opendir(dirPathC);
  if(!dir)
   THROW_EXEC_EXCP(ERR_DIR_OPEN_FAILED, *dirPath, ERRNO_DESC);
  else
   {
    // For each file in the target directory
    while((dirFile = readdir(dir)) != NULL)
     {
      // Skip the directory itself, the pointer to the parent's directory, and subdirectories
      if(!strcmp(dirFile->d_name, ".") || !strcmp(dirFile->d_name, "..") || dirFile->d_type == DT_DIR)
       continue;

      // Initialize the information on the file in the target directory
      fileInfo = new FileInfo(*dirAbspath + '/' + std::string(dirFile->d_name));

      // Compute the file information's raw size (name length, '\0' excluded, + metadata)
      fileInfoRawSize = strlen(dirFile->d_name) + 3 * sizeof(long int);

      // Ensure that adding the file information's raw size to the
      // directory contents' raw size would not overflow an unsigned integer
      if(dirRawSize > UINT_MAX - fileInfoRawSize)
       THROW_SESS_EXCP(ERR_SESS_DIR_SIZE_OVERFLOW,*dirAbspath);

      // Add the file's information to the list of directory's files information
      dirFiles.emplace_front(fileInfo);

      // Update the directory contents' raw size
      dirRawSize += fileInfoRawSize;

      // Increment the number of files in the directory
      numFiles++;
     }

    // Close the target directory
    if(closedir(dir) == -1)
     LOG_EXEC_CODE(ERR_DIR_CLOSE_FAILED, *dirPath, ERRNO_DESC);
   }
 }


/**
 * @brief DirInfo object destructor, deleting the list of FileInfo objects
 */
DirInfo::~DirInfo()
 {
  for(FileInfo* fileInfo : dirFiles)
   delete fileInfo;
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief  Adds a file with its information in the directory
 * @param  fileInfo The information on the file to be added to the directory
 * @throws ERR_SESS_DIR_SIZE_OVERFLOW The directory contents' raw size exceeds 4GB
 */
void DirInfo::addFileInfo(FileInfo* fileInfo)
 {
  // Compute the file information's raw size (name length, '\0' excluded, + metadata)
  unsigned short fileInfoRawSize = fileInfo->fileName.length() + 3 * sizeof(long int);

  // Ensure that adding the file information's raw size to the
  // directory contents' raw size would not overflow an unsigned integer
  if(dirRawSize > UINT_MAX - fileInfoRawSize)
   THROW_SESS_EXCP(ERR_SESS_DIR_SIZE_OVERFLOW,*dirPath);

  // Add the file's information to the list of directory's files information
  dirFiles.emplace_front(fileInfo);

  // Update the directory contents' raw size
  dirRawSize += fileInfoRawSize;

  // Increment the number of files in the directory
  numFiles++;
 }


/**
 * @brief  Prints the indented metadata and name of all files in the directory, if any
 * @return 'true' if at least one file was printed or 'false' if the directory is empty
 */
bool DirInfo::printDirContents()
 {
  // If there are no files in the directory, just return
  if(numFiles == 0)
   return false;

   // Otherwise, if the directory contains at least 1 file
  else
   {
    // Indentation
    printf("\n");

    // Print the files attributes' legend
    std::cout << " SIZE     LAST MODIFIED      CREATION TIME    FILE" << std::endl;
    std::cout << "---------------------------------------------------" << std::endl;

    // Print the attributes of each file in the directory
    for(const auto& it : dirFiles)
     {
      // Print the file size with padding spaces
      it->printFormattedSize(true, false);

      // Indentation between the "SIZE" and "LAST MODIFIED" headers
      printf("  ");

      // Print the file last modification time
      it->printFormattedLastModTime(false);

      // Indentation between the "LAST MODIFIED and "CREATION TIME" headers
      printf("  ");

      // Print the file creation time
      it->printFormattedCreationTime(false);

      // Indentation between the "CREATION TIME" and "FILE" headers
      printf("  ");

      // Print the file name and a new line
      std::cout << it->fileName << std::endl;
     }

    // Indentation
    printf("\n");

    // Return that at least one file has been printed
    return true;
   }
 }