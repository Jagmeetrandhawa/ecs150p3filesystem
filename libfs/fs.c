#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define BLOCK_SIZE 4096 //from discussion slide 6
#define ENTRIESPERFATBLOCK 2048 // slide 16 discussio
#define FileNameMaxSize 16
#define FAT_EOC 0xFFFF

/* TODO: Phase 1 */

//https://stackoverflow.com/questions/12213866/is-attribute-packed-ignored-on-a-typedef-declaration/37184767
//https://gcc.gnu.org/onlinedocs/gcc-3.3/gcc/Type-Attributes.html

//defining the structures for Supper Block, FAT, RootDirectory, 
struct SupperBlock
{
    //uint64_t  Signature;     //Signature
    char      Signature[8];
    uint16_t  TotNumOfBlock;   //Total amount of virtual disk
    uint16_t  RDBIndex;        //Root directory block index
    uint16_t  DBSIndex;        //Data block start index
    uint16_t  ADBlock;         //Amount of data blocks
    uint8_t   NumBlockFat;     //Numbers of blocks for FAT
    uint8_t   Unused[4079];    //Unused/Padding
 }__attribute__((__packed__));
typedef struct SupperBlock SupperBlock_t;

struct rootEntry
{
    //uint8_t    Filename[16];   //Filename????
	char       Filename[FileNameMaxSize];
    uint32_t   SizeFile;       //Size of the file
    uint16_t   IndexFDB;       //Index of the first data block
    uint8_t    Unused[10];     //Unused/Padding
 }__attribute__((__packed__));
typedef struct rootEntry rootEntry_t; 

//RootDirectory_t rootD[FS_FILE_MAX_COUNT];
struct fileDescriptor
{
    char fileName[FileNameMaxSize];
    int fd;
    int offset;
};typedef struct fileDescriptor fileDescriptor_t; 

uint16_t  *FAT;
SupperBlock_t S_B;
rootEntry_t Root_Directory[FS_FILE_MAX_COUNT];
fileDescriptor_t fd_table[FS_OPEN_MAX_COUNT];
int diskOpen = 0;
int NumOpenFile = 0;

int NumFATFree()
{
	int num_FAT_Free = 0;
	for(int i = 0; i < S_B.ADBlock; i++)
	{
		if (FAT[i] == 0)
		{
			num_FAT_Free++;
		}
	}
	return num_FAT_Free;
}

int NumROOTFree()
{
	int num_ROOT_Free = 0;
	for (int j = 0; j < FS_FILE_MAX_COUNT; j++)
	{
		//if (Root_Directory[j].Filename[0] == '\0')
		if(strlen(Root_Directory[j].Filename) == 0)
		{
			num_ROOT_Free++;
		}
	}
	return num_ROOT_Free;
}

int IsFileNameExist(const char *filename)
{
	int exist = 0;
	for (int j = 0; j < FS_FILE_MAX_COUNT; j++)
	{
		if (memcmp(Root_Directory[j].Filename, filename, strlen(filename)) == 0)//if (memcmp(Root_Directory[j].Filename, filename, 16) == 0)
		{
			exist = 1;
			return exist;
		}
	}
	return exist;
}

int findTheIndex(const char *filename)
{
	int returnVal = 0;
	for (int j = 0; j < FS_FILE_MAX_COUNT; j++)
	{
		if (memcmp(Root_Directory[j].Filename, filename, strlen(filename)) == 0)//if (memcmp(Root_Directory[j].Filename, filename, 16) == 0)
		{
			returnVal = j;
			return j;
		}
	}
	//return -1;
	return returnVal;
}

int findFileInfd_Table(const char *filename)
{
	int exist = 0;
	for (int j = 0; j < FS_OPEN_MAX_COUNT; j++)
	{
		if (memcmp(fd_table[j].fileName, filename, strlen(filename)) == 0)//if (memcmp(Root_Directory[j].Filename, filename, 16) == 0)
		{
			exist = 1;
			return exist;
		}
	}
	return exist;
}

int RootFreeIndex()
{
	int index = -1;
	for (int j = 0; j < FS_FILE_MAX_COUNT; j++)
	{
		if(strlen(Root_Directory[j].Filename) == 0)
		{
			index = j;
			return index;
		}
	}
	return index;
}
int FAT_First_Fit()
{
	int index = -1;
	for (int i = 0; i < S_B.ADBlock; i++)
	{
		if (FAT[index] == 0)
		{
			index = i;
			//printf("what is this index: %d\n what is S_B.ADBLOCK: %d\n",index,S_B.ADBlock);
			return index;
		}
	}
	return index;
}

int fs_mount(const char *diskname)
{
    /* TODO: Phase 1 */
    int retval = 0;
    char SIG[8];

	memset(SIG, '\0', 8);
	//set the file descriptor
	for(int i = 0; i < FS_OPEN_MAX_COUNT; i++)
	{
		memcpy(fd_table[i].fileName, "", FileNameMaxSize);
		fd_table[i].offset = 0;
		fd_table[i].fd = -1;
	}
	memcpy(SIG, "ECS150FS", 8);
    retval = block_disk_open(diskname);
    if (retval == -1) //There was no virtual disk file opened
    {
        diskOpen = 0;
        return retval;
    }
    retval = block_read(0, &S_B);
    if (retval == -1)
    {
        return retval;
    }
    //compare the signature with "ECS150FS"
    retval = memcmp(S_B.Signature, SIG, 8);
    if (retval != 0)
    {
        return retval;
    }

    //Compare the total number of block with block_disk_count();

    FAT = malloc(BLOCK_SIZE*S_B.NumBlockFat*sizeof(uint16_t));   
	//MIGHT have to change the above from ENTRIESPERFATBLOCK to BLOCK_SIZE
    if(FAT == 0){
        return retval = -1;
     }
    for(int i = 1; i <= S_B.NumBlockFat; i++){

       block_read(i, &FAT[(i-1)* BLOCK_SIZE]);
	   //might have to change the above to ENTRIESPERFAT LATER
     }

    //read root directory
    retval = block_read(S_B.RDBIndex, &Root_Directory); 
    if(retval == -1)
	{
        return retval; //error checking
    }

    diskOpen = 1;
    return retval;
}

/**
 * fs_umount - Unmount file system
 *
 * Unmount the currently mounted file system and close the underlying virtual
 * disk file.
 *
 * Return: -1 if no FS is currently mounted, or if the virtual disk cannot be
 * closed, or if there are still open file descriptors. 0 otherwise.
 */
int fs_umount(void)
{
    /* TODO: Phase 1 */
	int retval = 0;
	
	if(diskOpen == 0) //no FS is currently mounted
	{
		retval = -1;
        return retval;
    }
	if(NumOpenFile > 0){ //there are still open file descriptor
		retval = -1;
        return retval;
	}

	block_write(0, &S_B);
	for(int i = 1; i <= S_B.NumBlockFat; i++){
       block_write(i, &FAT[(i-1)* BLOCK_SIZE]);
	   //might have to change the above to ENTRIESPERFAT LATER
     }

	 free(FAT);
	 block_write(S_B.RDBIndex, &Root_Directory);

	retval = block_disk_close(); //virtual disk cannot be closed
	return retval;
}

/**
 * fs_info - Display information about file system
 *
 * Display some information about the currently mounted file system.
 *
 * Return: -1 if no underlying virtual disk was opened. 0 otherwise.
 */
int fs_info(void)
{
    /* TODO: Phase 1 */
    
    if(diskOpen == 0)
	{
        printf("Disk is not opened \n");
        return -1;
    }
    printf("FS Info: \n");
	printf("total_blk_count=%d \n", S_B.TotNumOfBlock);
	printf("fat_blk_count=%d \n", S_B.NumBlockFat);
	printf("rdir_blk=%d \n", S_B.RDBIndex);
	printf("data_blk=%d \n", S_B.DBSIndex);
	printf("data_blk_count=%d \n", S_B.ADBlock);
	//Find the number of free FAT
	int num_FAT_Free = 0;
	num_FAT_Free = NumFATFree();
	printf("fat_free_ratio=%d/%d \n", num_FAT_Free, S_B.ADBlock);
	//Find the number of free RootDirectory
	int num_ROOT_Free = 0;
	num_ROOT_Free = NumROOTFree();
	printf("rdir_free_ratio=%d/%d \n", num_ROOT_Free, FS_FILE_MAX_COUNT);
	return 0;
}


/**
 * fs_create - Create a new file
 * @filename: File name
 *
 * Create a new and empty file named @filename in the root directory of the
 * mounted file system. String @filename must be NULL-terminated and its total
 * length cannot exceed %FS_FILENAME_LEN characters (including the NULL
 * character).
 *
 * Return: -1 if no FS is currently mounted, or if @filename is invalid, or if a
 * file named @filename already exists, or if string @filename is too long, or
 * if the root directory already contains %FS_FILE_MAX_COUNT files. 0 otherwise.
 */
int fs_create(const char *filename)
{
    /* TODO: Phase 2 */
	int retval = 0;
	int len = 0;
	int num_ROOT_Free = 0;
	int exist = 0; 
	int root_Index = 0;
	if(diskOpen == 0)  //no FS is currently mounted
	{
        retval = -1;
        return retval;
    }
	// checking if filename is invalid
	len = strlen(filename);
	if ( len == 0 || len > FileNameMaxSize-1){ //empyt name or long name
		retval = -1;
		return retval;
	}
	//checking for number of roots are free
	num_ROOT_Free = NumROOTFree();
	if (num_ROOT_Free == 0){
		retval = -1;
		return retval;
	}
	//filename already exists
	exist = IsFileNameExist(filename);
	if (exist == 1){
		retval = -1;
		return retval;
	}
	root_Index = RootFreeIndex();
	if (root_Index == -1)
	{
		retval = root_Index;
		return retval;
	}

	strcpy(Root_Directory[root_Index].Filename, filename);
	Root_Directory[root_Index].SizeFile = 0;
	Root_Directory[root_Index].IndexFDB = FAT_EOC;

	return retval;
}

/*
 * fs_delete - Delete a file
 * @filename: File name
 *
 * Delete the file named @filename from the root directory of the mounted file
 * system.
 *
 * Return: -1 if no FS is currently mounted, or if @filename is invalid, or if
 * Return: -1 if @filename is invalid, if there is no file named @filename to
 * delete, or if file @filename is currently open. 0 otherwise.
 */
int fs_delete(const char *filename)
{
    /* TODO: Phase 2 */
	int retval = 0;
	int len = 0;
	int exist = 0;
	if(diskOpen == 0)  //no FS is currently mounted
	{
        retval = -1;
        return retval;
    }
	// checking if filename is invalid
	len = strlen(filename);
	if ( len == 0 || len > FileNameMaxSize-1){ //empyt name or long name
		retval = -1;
		return retval;
	}
	exist = findFileInfd_Table(filename); // file is open
	if(exist == 1){
		retval = -1;
		return retval;
	}
	int index = findTheIndex(filename); //Find the file in the root directory 
	if(index == -1){
		retval = -1;
		return retval;
	}
	int nxtIndex = 0;
	int curIndex = index;
	if(Root_Directory[index].IndexFDB != 0 && Root_Directory[index].IndexFDB != FAT_EOC){//need to clean up the FAT
		while(FAT[curIndex] != FAT_EOC){
			nxtIndex = FAT[curIndex];
			FAT[curIndex] = 0;
			curIndex = nxtIndex;
		}
	}
	memcpy(Root_Directory[index].Filename, "", FileNameMaxSize);//strcpy(Root_Directory[index].Filename, '\0');
	Root_Directory[index].SizeFile = 0;
	Root_Directory[index].IndexFDB = 0;

	return retval;
}

/**
 * fs_ls - List files on file system
 *
 * List information about the files located in the root directory.
 *
 * Return: -1 if no FS is currently mounted. 0 otherwise.
 */
int fs_ls(void)
{
    /* TODO: Phase 2 */
	int retval = 0;
	if(diskOpen == 0)  //no FS is currently mounted
	{
        retval = -1;
        return retval;
    }
	printf("FS Ls:\n");
	for (int j = 0; j < FS_FILE_MAX_COUNT; j++)
	{
		if(strlen(Root_Directory[j].Filename) != 0)
		{
			printf("file: %s, zise: %d, data_blk: %d\n", Root_Directory[j].Filename, Root_Directory[j].SizeFile,
														 Root_Directory[j].IndexFDB);
		}
	}
	return retval;
}
/**
 * fs_open - Open a file
 * @filename: File name
 *
 * Open file named @filename for reading and writing, and return the
 * corresponding file descriptor. The file descriptor is a non-negative integer
 * that is used subsequently to access the contents of the file. The file offset
 * of the file descriptor is set to 0 initially (beginning of the file). If the
 * same file is opened multiple files, fs_open() must return distinct file
 * descriptors. A maximum of %FS_OPEN_MAX_COUNT files can be open
 * simultaneously.
 *
 * Return: -1 if no FS is currently mounted, or if @filename is invalid, or if
 * there is no file named @filename to open, or if there are already
 * %FS_OPEN_MAX_COUNT files currently open. Otherwise, return the file
 * descriptor.
 */
int fs_open(const char *filename)
{
    /* TODO: Phase 3 */
	//we have filename, we find file in root entry,
	// error checking
	//find it and grab size and index of first data block
	//open file with that size
	int retval = 0;
	int len = 0;
	if(diskOpen == 0)  //no FS is currently mounted
	{
        retval = -1;
        return retval;
    }
	// checking if filename is invalid
	len = strlen(filename);
	if ( len == 0 || len > FileNameMaxSize-1){ //empyt name or long name
		retval = -1;
		return retval;
	}
	int indOfFileInRoot = findTheIndex(filename);
	if (indOfFileInRoot == -1){//checking the file name exists in root directory
		retval = -1;
		return retval;
	}
	if (NumOpenFile == FS_OPEN_MAX_COUNT){//checking the for the maximum of open files
		retval = -1;
		return retval;
	}
	for(int i=0; i < FS_OPEN_MAX_COUNT; i++){
		if (strlen(fd_table[i].fileName) == 0){
			NumOpenFile++;
			memcpy(fd_table[i].fileName, filename, strlen(filename));
			fd_table[i].fd = i;
			fd_table[i].offset = 0;
			return i;
		}
	}
	return -1;
}

/**
 * fs_close - Close a file
 * @fd: File descriptor
 *
 * Close file descriptor @fd.
 *
 * Return: -1 if no FS is currently mounted, or if file descriptor @fd is
 * invalid (out of bounds or not currently open). 0 otherwise.
 */
int fs_close(int fd)
{
    /* TODO: Phase 3 */
	int retval = 0;
	if(diskOpen == 0)  //no FS is currently mounted
	{
        retval = -1;
        return retval;
    }
	if(fd < 0 || fd >= FS_OPEN_MAX_COUNT) //fd is valid 0<=fd < 32
	{
        retval = -1;
        return retval;
    }
	if(strlen(fd_table[fd].fileName) == 0)//not open
	{
        retval = -1;
        return retval;
    }
	
	NumOpenFile--;
	memcpy(fd_table[fd].fileName, "", FileNameMaxSize);
	fd_table[fd].offset = 0;
	fd_table[fd].fd = -1;
	return retval;
}

/**
 * fs_stat - Get file status
 * @fd: File descriptor
 *
 * Get the current size of the file pointed by file descriptor @fd.
 *
 * Return: -1 if no FS is currently mounted, of if file descriptor @fd is
 * invalid (out of bounds or not currently open). Otherwise return the current
 * size of file.
 */
int fs_stat(int fd)
{
    /* TODO: Phase 3 */
	int retval = 0;
	if(diskOpen == 0)  //no FS is currently mounted
	{
        retval = -1;
        return retval;
    }
	if(fd < 0 || fd >= FS_OPEN_MAX_COUNT) //fd is valid 0<=fd < 32
	{
        retval = -1;
        return retval;
    }
	if(strlen(fd_table[fd].fileName) == 0)//not open
	{
        retval = -1;
        return retval;
    }

	int index = findTheIndex(fd_table[fd].fileName);
	int size = Root_Directory[index].SizeFile;
	return size;
}

/**
 * fs_lseek - Set file offset
 * @fd: File descriptor
 * @offset: File offset
 *
 * Set the file offset (used for read and write operations) associated with file
 * descriptor @fd to the argument @offset. To append to a file, one can call
 * fs_lseek(fd, fs_stat(fd));
 *
 * Return: -1 if no FS is currently mounted, or if file descriptor @fd is
 * invalid (i.e., out of bounds, or not currently open), or if @offset is larger
 * than the current file size. 0 otherwise.
 */
int fs_lseek(int fd, size_t offset)
{
    /* TODO: Phase 3 */
	int retval = 0;
	if(diskOpen == 0)  //no FS is currently mounted
	{
        retval = -1;
        return retval;
    }
	if(fd < 0 || fd >= FS_OPEN_MAX_COUNT) //fd is valid 0<=fd < 32
	{
        retval = -1;
        return retval;
    }
	if(strlen(fd_table[fd].fileName) == 0)//not open
	{
        retval = -1;
        return retval;
    }
	int index = findTheIndex(fd_table[fd].fileName);
	uint32_t size = Root_Directory[index].SizeFile;
	if(offset > size) //offset is larger than the current file size
	{
		retval = -1;
        return retval;
	}
	fd_table[fd].offset = offset;	
	return retval;
	
}

/**
 * fs_write - Write to a file
 * @fd: File descriptor
 * @buf: Data buffer to write in the file
 * @count: Number of bytes of data to be written
 *
 * Attempt to write @count bytes of data from buffer pointer by @buf into the
 * file referenced by file descriptor @fd. It is assumed that @buf holds at
 * least @count bytes.
 *
 * When the function attempts to write past the end of the file, the file is
 * automatically extended to hold the additional bytes. If the underlying disk
 * runs out of space while performing a write operation, fs_write() should write
 * as many bytes as possible. The number of written bytes can therefore be
 * smaller than @count (it can even be 0 if there is no more space on disk).
 *
 * Return: -1 if no FS is currently mounted, or if file descriptor @fd is
 * invalid (out of bounds or not currently open), or if @buf is NULL. Otherwise
 * return the number of bytes actually written.
 */
int fs_write(int fd, void *buf, size_t count)
{
    /* TODO: Phase 4 */

	int retval = 0;

	if(diskOpen == 0)  //no FS is currently mounted
	{
        retval = -1;
        return retval;
    }
	if(fd < 0 || fd >= FS_OPEN_MAX_COUNT) //fd is valid 0<=fd < 32
	{
        retval = -1;
        return retval;
    }
	if(strlen(fd_table[fd].fileName) == 0)//not open
	{
        retval = -1;
        return retval;
    }
	if(buf == NULL)
	{
        retval = -1;
        return retval;
    }
	size_t writeCount = 0;
	int findFile = findTheIndex(fd_table[fd].fileName);//findTheIndex(filename);
	int offset = fd_table[fd].offset;
	//size_t size = Root_Directory[findFile].SizeFile;
	void *tempBuf[BLOCK_SIZE];

	memset(tempBuf, '\0', sizeof(char));
	int nxtIndex;
	int currIndex;
	
	if(Root_Directory[findFile].IndexFDB == FAT_EOC && count != 0){
		Root_Directory[findFile].IndexFDB = FAT_First_Fit();
	}
	currIndex = Root_Directory[findFile].IndexFDB+S_B.DBSIndex;
	

	int startBlock = offset / BLOCK_SIZE;
	int NumBlock = count / BLOCK_SIZE;
	int startOffset = offset % BLOCK_SIZE;
	int endOffset = count % BLOCK_SIZE;
	int newBlockIndex;
	//printf("Root_Directory[findFile].IndexFDB outside loop is %d\n\n", Root_Directory[findFile].IndexFDB);
	//printf("--\nfindFile IN WRITE--- %d\n\n", findFile);

	//printf("currIndex outside loop is %d\n\n",currIndex);
	//printf("offsett outside loop is %d\n\n",offset);
	//printf("count outside loop is %ld\n\n",count);
	//printf("fd is : %d\n\n", fd);




	if (startBlock > 0)
	{
		for(int i = 0; i < startBlock-1; i++)
		{
			nxtIndex = FAT[currIndex];
			currIndex = nxtIndex;
		}
	}

	if(NumBlock == 0) //we need to write one block
	{
		if(((offset+count)/BLOCK_SIZE) == 0)//if(startBlock == 0)
		{
			//printf("currIndex is : %d\n and count is : %ld\n", currIndex, count);
			memcpy(tempBuf , buf, count);
			block_write(currIndex, tempBuf);
			Root_Directory[findFile].SizeFile += count; 
			writeCount = count;
		}
		else//we need to write into two blocks
		{
			block_read(currIndex, tempBuf);
			memcpy(tempBuf+startOffset , buf, BLOCK_SIZE-offset);
			block_write(currIndex, tempBuf);
			//fd_table[fd].offset = offset + count-offset;
			Root_Directory[findFile].SizeFile += BLOCK_SIZE-offset; 
			nxtIndex = FAT[currIndex];
			currIndex = nxtIndex;
			if(FAT[currIndex] == FAT_EOC) // create a block
			{
				newBlockIndex = FAT_First_Fit();
				if(newBlockIndex != -1)
				{
					FAT[currIndex] = newBlockIndex;
					FAT[newBlockIndex] = FAT_EOC;
					//S_B.ADBlock = S_B.ADBlock + 1;
					memcpy(tempBuf, buf+BLOCK_SIZE-offset+1, count-(BLOCK_SIZE-offset));
					block_write(currIndex, tempBuf);
					Root_Directory[findFile].SizeFile += count-(BLOCK_SIZE-offset); 
					writeCount = count;
				}
			}
			else
			{
				memcpy(tempBuf, buf+BLOCK_SIZE-offset+1, count-(BLOCK_SIZE-offset));
				block_write(currIndex, tempBuf);
				Root_Directory[findFile].SizeFile += count-(BLOCK_SIZE-offset); 
				writeCount = count;
			}
		}
	fd_table[fd].offset = offset + writeCount;
	}
	else
	{
		for(size_t i = 0; i <= ((offset+count)/BLOCK_SIZE); i++)//for(int i = 0; i <= NumBlock; i++)
		{ 
			if(FAT[currIndex] == FAT_EOC)
			{
				newBlockIndex = FAT_First_Fit();
				if(newBlockIndex != -1)
				{
					FAT[currIndex] = newBlockIndex;
					FAT[newBlockIndex] = FAT_EOC;
				//S_B.ADBlock = S_B.ADBlock + 1;
					if(i == 0) //first block
					{	
						block_read(currIndex, tempBuf);
						memcpy(tempBuf+startOffset ,buf , BLOCK_SIZE-startOffset+i);
						block_write(currIndex, tempBuf);
						writeCount = BLOCK_SIZE - startOffset + i;
						fd_table[fd].offset = offset + BLOCK_SIZE-startOffset+i;
						Root_Directory[findFile].SizeFile += BLOCK_SIZE-startOffset+i;
						FAT[currIndex] = newBlockIndex;
						FAT[newBlockIndex] = FAT_EOC;
						currIndex = newBlockIndex;
					}
					else if(i != 0 && i != ((offset+count)/BLOCK_SIZE))//middle blocks
					{
						block_read(currIndex, tempBuf);
						memcpy(tempBuf, buf+(i-1)*BLOCK_SIZE+(BLOCK_SIZE-startOffset+i), BLOCK_SIZE);
						block_write(currIndex, tempBuf);
						writeCount += BLOCK_SIZE;
						fd_table[fd].offset += BLOCK_SIZE;
						FAT[currIndex] = newBlockIndex;
						FAT[newBlockIndex] = FAT_EOC;
						currIndex = newBlockIndex;
					//printf("is the seg fault here:??\n");
					}
			
					else //last blocks
					{
						if(writeCount < count)
						{
							block_read(currIndex, tempBuf);
							memcpy(tempBuf, buf+(i-1)*BLOCK_SIZE+(BLOCK_SIZE-startOffset+i), endOffset+startOffset-1);
							block_write(currIndex, tempBuf);
							fd_table[fd].offset += endOffset+startOffset-1;
							writeCount += BLOCK_SIZE;
							FAT[currIndex] = newBlockIndex;
							FAT[newBlockIndex] = FAT_EOC;
						}
					}
				}	
			}	
			else
			{
				if(i == 0) //first block
				{	
					block_read(currIndex, tempBuf);
					memcpy(tempBuf+startOffset ,buf , BLOCK_SIZE-startOffset+i);
					block_write(currIndex, tempBuf);
					writeCount = BLOCK_SIZE - startOffset + i;
					fd_table[fd].offset = offset + BLOCK_SIZE-startOffset+i;
					Root_Directory[findFile].SizeFile += BLOCK_SIZE-startOffset+i;
					nxtIndex = FAT[currIndex];
					currIndex = nxtIndex;
				}
				else if(i != 0 && i != ((offset+count)/BLOCK_SIZE))//middle blocks
				{
					block_read(currIndex, tempBuf);
					memcpy(tempBuf, buf+(i-1)*BLOCK_SIZE+(BLOCK_SIZE-startOffset+i), BLOCK_SIZE);
					block_write(currIndex, tempBuf);
					writeCount += BLOCK_SIZE;
					fd_table[fd].offset += BLOCK_SIZE;
					nxtIndex = FAT[currIndex];
					currIndex = nxtIndex;
				}
				else //last blocks
				{
					if(writeCount < count)
					{
						block_read(currIndex, tempBuf);
						memcpy(tempBuf, buf+(i-1)*BLOCK_SIZE+(BLOCK_SIZE-startOffset+i), endOffset+startOffset-1);
						block_write(currIndex, tempBuf);
						fd_table[fd].offset += endOffset+startOffset-1;
						writeCount += BLOCK_SIZE;
						nxtIndex = FAT[currIndex];
						currIndex = nxtIndex;
					}
				}
			}
		}
	}

	return writeCount;
}

/**
 * fs_read - Read from a file
 * @fd: File descriptor
 * @buf: Data buffer to be filled with data
 * @count: Number of bytes of data to be read
 *
 * Attempt to read @count bytes of data from the file referenced by file
 * descriptor @fd into buffer pointer by @buf. It is assumed that @buf is large
 * enough to hold at least @count bytes.
 *
 * The number of bytes read can be smaller than @count if there are less than
 * @count bytes until the end of the file (it can even be 0 if the file offset
 * is at the end of the file). The file offset of the file descriptor is
 * implicitly incremented by the number of bytes that were actually read.
 *
 * Return: -1 if no FS is currently mounted, or if file descriptor @fd is
 * invalid (out of bounds or not currently open), or if @buf is NULL. Otherwise
 * return the number of bytes actually read.
 */

int fs_read(int fd, void *buf, size_t count)
{
    /* TODO: Phase 4 */
	//const char *filename;
	int offset;
	int retval = 0;
	

	if(diskOpen == 0)  //no FS is currently mounted
	{
        retval = -1;
        return retval;
    }

	if(fd < 0 || fd >= FS_OPEN_MAX_COUNT) //fd is valid 0<=fd < 32
	{
        retval = -1;
        return retval;
    }

	if(strlen(fd_table[fd].fileName) == 0)//not open
	{
        retval = -1;
        return retval;
    }

	//offset = findOffsetAndFilename(filename, fd);
	//if(offset == -1){
	//	return offset;
	//}
	int findFile = findTheIndex(fd_table[fd].fileName);//findTheIndex(filename);
	//Root_Directory[findFile].Filename;
	offset = fd_table[fd].offset;

	//void *bounceBuf[fs_stat(fd)];
	//char *tempBuf = malloc(BLOCK_SIZE*sizeof(char));
	void *tempBuf[BLOCK_SIZE];

	memset(tempBuf, '\0', sizeof(char));
	int nxtIndex;
	int currIndex = Root_Directory[findFile].IndexFDB+S_B.DBSIndex;
	//printf("Root_Directory[findFile].IndexFDB outside loop is IN READ %d\n\n", Root_Directory[findFile].IndexFDB);
	//printf("findFile IN READ %d\n\n", findFile);
	//printf("currIndex is: %d\n\n", currIndex);


	//int currIndex = S_B.DBSIndex;
	//uint16_t startDB = Root_Directory[findFile].DBSIndex;
	//int bounceCount = 0; 
	int startBlock = offset / BLOCK_SIZE;
	int NumBlock = count / BLOCK_SIZE;//(offset + count) / BLOCK_SIZE;
	int startOffset = offset % BLOCK_SIZE;
	int endOffset = count % BLOCK_SIZE;//(offset + count) % BLOCK_SIZE;
	size_t readCount = 0;
	if (startBlock > 0)
	{
		for(int i = 0; i < startBlock-1; i++)
		{
			if(FAT[currIndex] != FAT_EOC){
				nxtIndex = FAT[currIndex];
				currIndex = nxtIndex;
			}
		}
	}
	if(NumBlock == 0){//(startBlock == endBlock){//we need to read one block
		if(((offset+count)/BLOCK_SIZE) == 0)//if(startBlock == 0)
		{
			block_read(currIndex, tempBuf);
			memcpy(buf , tempBuf+startOffset, count);
			readCount = count;
			//printf("readcount is first first block: %ld\n", readCount);
			
		}
		else//we need to read two blocks
		{
			block_read(currIndex, tempBuf);
			memcpy(buf, tempBuf+startOffset, BLOCK_SIZE-offset);
			//fd_table[fd].offset += count-offset;
			nxtIndex = FAT[currIndex];
			currIndex = nxtIndex;
			block_read(currIndex, tempBuf);
			memcpy(buf+BLOCK_SIZE-offset+1 , tempBuf, count-(BLOCK_SIZE-offset));
			readCount = count;
		}
		fd_table[fd].offset += count;
	
	}
	else
	{
		for(size_t i = 0; i <= ((offset+count)/BLOCK_SIZE); i++)//for(int i = 0; i <= NumBlock; i++)
		{
			if(i == 0) //first block
			{

				block_read(currIndex, tempBuf);
				memcpy(buf , tempBuf+startOffset, BLOCK_SIZE-startOffset+i);
				readCount = (BLOCK_SIZE - startOffset + i);
				//printf("readCount is in first block: %ld\n", readCount);

				fd_table[fd].offset += BLOCK_SIZE-startOffset+i;
				if(FAT[currIndex] != FAT_EOC){//////???????
					nxtIndex = FAT[currIndex];
					currIndex = nxtIndex;
				}
			}
			else if(i != 0 && i != ((offset+count)/BLOCK_SIZE))//else if(i !=0 && i != NumBlock) //middle blocks
			{
				block_read(currIndex, tempBuf);
				memcpy(buf+(i-1)*BLOCK_SIZE+(BLOCK_SIZE-startOffset+i) , tempBuf, BLOCK_SIZE);
				readCount += BLOCK_SIZE;
				//printf("readCount is in middle block: %ld\n", readCount);

				fd_table[fd].offset += BLOCK_SIZE;//fd_table[fd].offset = offset + BLOCK_SIZE;
				//printf("is the seg fault here:??\n");
				if(FAT[currIndex] != FAT_EOC){
					nxtIndex = FAT[currIndex];
					currIndex = nxtIndex;
				}
			}
			else //last blocks
			{

			
				if(readCount < count){
					block_read(currIndex, tempBuf);
					memcpy(buf+(i-1)*BLOCK_SIZE+(BLOCK_SIZE-startOffset+i) , tempBuf, endOffset+startOffset-1);
					fd_table[fd].offset += endOffset+startOffset-1;
					readCount += endOffset + startOffset - 1;
				//	printf("readCount is in last block: %ld\n", readCount);
				}

				if(FAT[currIndex] != FAT_EOC){
					nxtIndex = FAT[currIndex];
					currIndex = nxtIndex;
				}
			}
		}
	}
	return readCount;
}
