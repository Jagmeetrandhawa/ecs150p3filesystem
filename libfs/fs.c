#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define BLOCK_SIZE 4096 
#define ENTRIESPERFATBLOCK 2048 
#define FileNameMaxSize 16
#define FAT_EOC 0xFFFF

/* TODO: Phase 1 */

//https://stackoverflow.com/questions/12213866/is-attribute-packed-ignored-on-a-typedef-declaration/37184767
//https://gcc.gnu.org/onlinedocs/gcc-3.3/gcc/Type-Attributes.html

//defining the structures for Supper Block, FAT, RootDirectory, 
struct SupperBlock
{
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
	char       Filename[FileNameMaxSize];
    uint32_t   SizeFile;       //Size of the file
    uint16_t   IndexFDB;       //Index of the first data block
    uint8_t    Unused[10];     //Unused/Padding
 }__attribute__((__packed__));
typedef struct rootEntry rootEntry_t; 

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
		if (memcmp(Root_Directory[j].Filename, filename, strlen(filename)) == 0)
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
		if (memcmp(Root_Directory[j].Filename, filename, strlen(filename)) == 0)
		{
			returnVal = j;
			return j;
		}
	}
	return returnVal;
}

int findFileInfd_Table(const char *filename)
{
	int exist = 0;
	for (int j = 0; j < FS_OPEN_MAX_COUNT; j++)
	{
		if (memcmp(fd_table[j].fileName, filename, strlen(filename)) == 0)
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
			return index;
		}
	}
	return index;
}

int fs_mount(const char *diskname)
{
    int retval = 0;
    char SIG[8];

	memset(SIG, '\0', 8);
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
    if(FAT == 0){
        return retval = -1;
     }
    for(int i = 1; i <= S_B.NumBlockFat; i++){

       block_read(i, &FAT[(i-1)* BLOCK_SIZE]);
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

int fs_umount(void)
{
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
     }

	 free(FAT);
	 block_write(S_B.RDBIndex, &Root_Directory);

	retval = block_disk_close(); //virtual disk cannot be closed
	return retval;
}

int fs_info(void)
{
    
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


int fs_create(const char *filename)
{
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
	if ( len == 0 || len > FileNameMaxSize-1){ //empty name or long name
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


int fs_delete(const char *filename)
{
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
	memcpy(Root_Directory[index].Filename, "", FileNameMaxSize);
	Root_Directory[index].SizeFile = 0;
	Root_Directory[index].IndexFDB = 0;

	return retval;
}

int fs_ls(void)
{
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

int fs_open(const char *filename)
{
    
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


int fs_close(int fd)
{
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

int fs_stat(int fd)
{
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

int fs_lseek(int fd, size_t offset)
{
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


int fs_write(int fd, void *buf, size_t count)
{

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
		if(((offset+count)/BLOCK_SIZE) == 0)
		{
			block_read(currIndex, tempBuf);
			if(offset > 0){
				memcpy(tempBuf + startOffset + 1 , buf, count);
			}
			else{
			memcpy(tempBuf + startOffset , buf, count);
			}
			block_write(currIndex, tempBuf);
			Root_Directory[findFile].SizeFile += count; 
			writeCount = count;
			}
		else//we need to write into two blocks
		{
			block_read(currIndex, tempBuf);
			if(offset > 0){
				memcpy(tempBuf + startOffset + 1 , buf, count);
			}
			else{
			memcpy(tempBuf+startOffset, buf, BLOCK_SIZE-offset);
			}
			block_write(currIndex, tempBuf);
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
		for(size_t i = 0; i <= ((offset+count)/BLOCK_SIZE); i++)
		{ 
			if(FAT[currIndex] == FAT_EOC)
			{
				newBlockIndex = FAT_First_Fit();
				if(newBlockIndex != -1)
				{
					FAT[currIndex] = newBlockIndex;
					FAT[newBlockIndex] = FAT_EOC;
					if(i == 0) //first block
					{	
						block_read(currIndex, tempBuf);
						if(offset > 0){
							memcpy(tempBuf + startOffset + 1 , buf, BLOCK_SIZE-startOffset+i);
							}
						else{
							memcpy(tempBuf+startOffset ,buf , BLOCK_SIZE-startOffset+i);
						}
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
						writeCount += endOffset + startOffset;
						nxtIndex = FAT[currIndex];
						currIndex = nxtIndex;
					}
				}
			}
		}
	}

	return writeCount;
}



int fs_read(int fd, void *buf, size_t count)
{
    
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

	
	int findFile = findTheIndex(fd_table[fd].fileName);//findTheIndex(filename);
	offset = fd_table[fd].offset;

	void *tempBuf[BLOCK_SIZE];

	memset(tempBuf, '\0', sizeof(char));
	int nxtIndex;
	int currIndex = Root_Directory[findFile].IndexFDB+S_B.DBSIndex;
	size_t fileSize = Root_Directory[findFile].SizeFile;
	
	int startBlock = offset / BLOCK_SIZE;
	int NumBlock = count / BLOCK_SIZE;
	int startOffset = offset % BLOCK_SIZE;
	int endOffset = count % BLOCK_SIZE;
	size_t readCount = 0;
	
	if(offset+count >= fileSize)
	{
		count = fileSize;
	}

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
	

	if(NumBlock == 0){//we need to read one block

		if(((offset+count)/BLOCK_SIZE) == 0)
		{
			block_read(currIndex, tempBuf);
			if(offset > 0 ){
				memcpy(buf , tempBuf+startOffset+1, count-startOffset);
			}
			else{
				memcpy(buf , tempBuf+startOffset, count);
			}
			if(offset > 0){
			readCount = count - startOffset;
			}
			else{
				readCount = count;
			}

			
		}
		else//we need to read two blocks
		{
			block_read(currIndex, tempBuf);
			memcpy(buf, tempBuf+startOffset, BLOCK_SIZE-offset);
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
		for(size_t i = 0; i <= ((offset+count)/BLOCK_SIZE); i++)
		{

			if(i == 0) //first block
			{

				block_read(currIndex, tempBuf);
				if(offset > 0 ){
					memcpy(buf , tempBuf+startOffset+1, BLOCK_SIZE-startOffset+i);
				}
				else{
					memcpy(buf , tempBuf+startOffset, count - startOffset + i);
				}
				readCount = (count - startOffset + i);
				if(offset > 0){
					readCount = (count - startOffset - offset + i);
				}
				else{
				readCount = (count - startOffset + i);
				}
				
				fd_table[fd].offset += BLOCK_SIZE-startOffset+i;
				if(FAT[currIndex] != FAT_EOC){
					nxtIndex = FAT[currIndex];
					currIndex = nxtIndex;
				}
			}
			else if(i != 0 && i != ((offset+count)/BLOCK_SIZE))//middle blocks
			{
				block_read(currIndex, tempBuf);
				memcpy(buf+(i-1)*BLOCK_SIZE+(BLOCK_SIZE-startOffset+i) , tempBuf, BLOCK_SIZE);
				readCount += BLOCK_SIZE;

				fd_table[fd].offset += BLOCK_SIZE;
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
					readCount += endOffset + startOffset;
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
