#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

/* TODO: Phase 1 */

//https://stackoverflow.com/questions/12213866/is-attribute-packed-ignored-on-a-typedef-declaration/37184767
//https://gcc.gnu.org/onlinedocs/gcc-3.3/gcc/Type-Attributes.html

//defining the structures for Supper Block, FAT, RootDirectory, 
struct SupperBlock
{
	//uint64_t  Signature;    //Signature
	char      Signature[8];
	uint16_t  NumOfBlock;   //Total amount of virtual disk
	uint16_t  RDBIndex;     //Root directory block index
	uint16_t  DBSIndex;     //Data block start index
	uint16_t  ADBlock;      //Amount of data blocks
	uint8_t   NumBlockFat;  //Numbers of blocks for FAT
	uint8_t   Unused[4079]; //Unused/Padding
 }__attribute__((__packed__));
typedef struct SupperBlock SupperBlock_t;

struct RootDirectory
{
	uint8_t    Filename[16];   //Filename????
	uint32_t   SizeFile;       //Size of the file
	uint16_t   IndexFDB;       //Index of the first data block
	uint8_t    Unused[10];     //Unused/Padding
 }__attribute__((__packed__));
typedef struct RootDirectory RootDirectory_t; 

uint16_t  *FAT;
SupperBlock_t S_B;


int fs_mount(const char *diskname)
{
	/* TODO: Phase 1 */
	int retval = 0;
	char SIG[8];

	memset(SIG, '\0', 8);
	memcpy(SIG, "ECS150FS", 8);

	retval = block_disk_open(diskname);
	if (retval == -1) //There was no virtual disk file opened
	{
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
	if (block_disk_count() != S_B.NumOfBlock)
	{
		retval = -1;
		return retval;
	}

	FAT = malloc(S_B.ADBlock*sizeof(uint16_t));

	return retval;
}

int fs_umount(void)
{
	/* TODO: Phase 1 */
}

int fs_info(void)
{
	/* TODO: Phase 1 */
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_ls(void)
{
	/* TODO: Phase 2 */
}

int fs_open(const char *filename)
{
	/* TODO: Phase 3 */
}

int fs_close(int fd)
{
	/* TODO: Phase 3 */
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

