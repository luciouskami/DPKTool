#include "stdafx.h"

#ifndef __EXEMEM__
#define __EXEMEM__
#pragma warning(disable:4311)
#pragma warning(disable:4312)
#pragma warning(disable:4554)
#pragma warning(disable:4996)
#pragma warning(disable:4267)

typedef IMAGE_SECTION_HEADER (*PIMAGE_SECTION_HEADERS)[1];   

#pragma pack(push, 1)   
typedef struct{   
    unsigned long VirtualAddress;   
    unsigned long SizeOfBlock;   
} *PImageBaseRelocation;   
#pragma pack(pop)   

class CExeMemory
{
public:
	CExeMemory();
	virtual ~CExeMemory();
	/*******************************************************\  
	{ ******************************************************* }  
	{ *                 从内存中加载并运行exe               * }  
	{ ******************************************************* }  
	{ * 参数：                                                }  
	{ * Buffer: 内存中的exe地址                               }  
	{ * Len: 内存中exe占用长度                                }  
	{ * CmdParam: 命令行参数(不包含exe文件名的剩余命令行参数）}  
	{ * ProcessId: 返回的进程Id                               }  
	{ * 返回值： 如果成功则返回进程的Handle(ProcessHandle),   }  
	{            如果失败则返回INVALID_HANDLE_VALUE           }  
	{ ******************************************************* }  
	 \*******************************************************/  
	HANDLE Run(void* lpBuffer, DWORD dwLen, char* szCmd, DWORD* dwProcId);
private:
	unsigned long GetAlignedSize(unsigned long Origin, unsigned long Alignment);
	unsigned long CalcTotalImageSize(PIMAGE_DOS_HEADER MzH, unsigned long FileLen, PIMAGE_NT_HEADERS peH, PIMAGE_SECTION_HEADERS peSecH);
	BOOL AlignPEToMem( void *Buf, long Len, PIMAGE_NT_HEADERS &peH, PIMAGE_SECTION_HEADERS &peSecH, void *&Mem, unsigned long &ImageSize);
	char* PrepareShellExe(char *CmdParam, unsigned long BaseAddr, unsigned long ImageSize);
	BOOL HasRelocationTable(PIMAGE_NT_HEADERS peH);
	void DoRelocation(PIMAGE_NT_HEADERS peH, void *OldBase, void *NewBase);
	BOOL UnloadShell(HANDLE ProcHnd, unsigned long BaseAddr);
	BOOL CreateChild(char *Cmd, CONTEXT &Ctx, HANDLE &ProcHnd, HANDLE &ThrdHnd, unsigned long &ProcId, unsigned long &BaseAddr, unsigned long &ImageSize);
	HANDLE AttachPE(char *CmdParam, PIMAGE_NT_HEADERS peH, PIMAGE_SECTION_HEADERS peSecH, void *Ptr, unsigned long ImageSize, unsigned long &ProcId);

};

#endif//__EXEMEM__