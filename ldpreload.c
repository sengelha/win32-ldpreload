/*---------------------------------------------------------------------------
	ldpreload.c
	Copyright © 2001 Steven Engelhardt
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions
	are met:
	1. Redistributions of source code must retain the above copyright
	   notice, this list of conditions, and the following disclaimer.
	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions, and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.
	3. The name of the author may not be used to endorse or promote products
	   derived from this software without specific prior written permission.
	
	THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
	IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
	OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
	IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
	INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
	NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
	THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
---------------------------------------------------------------------------*/

/*
 * Win32 LD_PRELOAD:
 *
 * A simple tool to emulate UNIX's LD_PRELOAD functionality.  Works by
 * modifying the startup code within the program to execute to first load
 * the DLL.  Idea from pg. 794 in _Programming Applications for Microsoft
 * Windows_: Fourth Edition by Jeffrey Richter.
 *
 * This program doesn't exactly correspond to LD_PRELOAD in that it
 * will not actually load the specified DLL _before_ all others, but
 * simply guarantee that the DLL is loaded before the program begins
 * executing.
 *
 * Usage: ldpreload.exe [program to execute] [DLL to preload]
 *
 * Works by locating the address at which the process will begin to
 * execute, and replacing the code at that address with code which will
 * call LoadLibrary() on the specified DLL.  After this is done, the
 * original instructions will be restored and execution will continue
 * as if nothing ever happened.
 *
 * This program will almost certainly only work on Windows NT 4.0, 2000,
 * and up.  It relies on such assumptions as NT EXE headers being present
 * and the function VirtualAllocEx existing.  If alternative methods for
 * determining the entry point address and finding a block of memory
 * within the process to put code exist, these assumptions can probably
 * be eliminated and this will work in Windows 95.  It also is limited
 * to 32-bit machines because of sizeof(LPVOID) == sizeof(DWORD)
 * assumptions.  This also assumes that KERNEL32.DLL will be mapped in
 * at the same address in this process and its child.
 * 
 * This program will allocate a small hunk of memory within the process
 * it creates to store the new instructions.  This hunk of memory will
 * never be freed (until, of course, the operating system cleans it up).
 */

#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "ldpreload.h"

static void    Usage              (void);
static HRESULT GetEntryPointAddr  (const char*, DWORD*);
static HRESULT WriteEntryCode     (BYTE*, DWORD);
static HRESULT WriteLDPreloadCode (BYTE*, DWORD, const BYTE*, DWORD, const char*);

/*
 * Number of bytes of entry code that we will initially overwrite
 */
#define NUM_ENTRY_CODE_BYTES     7

/*
 * Number of bytes of code/data that is used to perform the LD_PRELOAD
 * functionality
 */
#define NUM_LDPRELOAD_CODE_BYTES (512 + NUM_ENTRY_CODE_BYTES)

/*
 * Invoked name of EXE.
 */
static const char* g_argv0 = NULL;


/*
 * usage
 *
 * Prints a usage message and exits the application.
 */
static void
Usage(void)
{
	fprintf(stderr, "Usage: %s <EXE> <DLL>\n", g_argv0);
	exit(1);
}


/*
 * GetEntryPointAddr
 *
 * Gets the address of the EXE's entry point: the point at which the EXE
 * will begin executing.
 */
static HRESULT
GetEntryPointAddr(
	const char*	szEXE,
	DWORD*		pdwEntryAddr)
{
	HRESULT				hr = S_OK;
	HANDLE				hFile = INVALID_HANDLE_VALUE;
	HANDLE				hFileMapping = INVALID_HANDLE_VALUE;
	LPVOID				lpFileBase = NULL;
	PIMAGE_DOS_HEADER	pDOSHeader;
   	PIMAGE_NT_HEADERS	pNTHeader;

	*pdwEntryAddr = 0;

	hFile = CreateFile(szEXE, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	ChkTruePrintLastError(hFile != INVALID_HANDLE_VALUE, "CreateFile");

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	ChkTruePrintLastError(hFileMapping != INVALID_HANDLE_VALUE, "CreateFileMapping");

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	ChkTruePrintLastError(lpFileBase != INVALID_HANDLE_VALUE, "MapViewOfFile");

	pDOSHeader = (PIMAGE_DOS_HEADER) lpFileBase;

	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
		fprintf(stderr, "%s: Invalid signature\n", szEXE);
		ChkTrue(FALSE, E_FAIL);
		}

	pNTHeader = (PIMAGE_NT_HEADERS) ((DWORD) lpFileBase + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		{
		fprintf(stderr, "%s: NT EXE signature not present\n", szEXE);
		ChkTrue(FALSE, E_FAIL);
		}

	if (pNTHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
		{
		fprintf(stderr, "%s: Unsupported machine (0x%x)\n", szEXE, pNTHeader->FileHeader.Machine);
		ChkTrue(FALSE, E_FAIL);
		}

	if (pNTHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
		fprintf(stderr, "%s: NT optional header not present\n", szEXE);
		ChkTrue(FALSE, E_FAIL);
		}

	*pdwEntryAddr = (pNTHeader->OptionalHeader.ImageBase + pNTHeader->OptionalHeader.AddressOfEntryPoint);

Error:
	if (lpFileBase != NULL) {
		UnmapViewOfFile(lpFileBase);
		lpFileBase = NULL;
	}

	if (hFileMapping != INVALID_HANDLE_VALUE) {
		CloseHandle(hFileMapping);
		hFileMapping = INVALID_HANDLE_VALUE;
	}

	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	return hr;
}


/*
 * WriteEntryCode
 *
 * Writes the new entry code to the BYTE pointer given.  This entry code
 * should be exactly NUM_ENTRY_CODE_BYTES long (an assert will fire
 * otherwise).  This code simply jumps to the address given as a parameter
 * to this function, which is where the instructions for loading the DLL
 * will exist within the process.
 */
static HRESULT
WriteEntryCode(
	BYTE*	pbEntryCode,
	DWORD	dwLDPreloadInstrAddr)
{
	HRESULT	hr = S_OK;
	BYTE*	pbEntryCodeCounter = pbEntryCode;

	/* __asm mov eax, dwLDPreloadInstrAddr; */
	*pbEntryCodeCounter++ = 0xB8;
	*((DWORD*) pbEntryCodeCounter)++ = (DWORD) dwLDPreloadInstrAddr;

	/* __asm jmp eax; */
	*pbEntryCodeCounter++ = 0xFF;
	*pbEntryCodeCounter++ = 0xE0;

	assert(pbEntryCodeCounter - pbEntryCode == NUM_ENTRY_CODE_BYTES);

	return hr;
}


/*
 * WriteLDPreloadCode
 *
 * Writes the code which will call LoadLibrary and then restore the original
 * instructions back to the process entry point, then jumping back to the
 * entry point.
 */
static HRESULT
WriteLDPreloadCode(
	BYTE*		pbLDPreloadCode,
	DWORD		dwLDPreloadInstrAddr,
	const BYTE*	pbOrigEntryCode,
	DWORD		dwProcessEntryCodeAddr,
	const char*	szDLL)
{
	HRESULT			hr = S_OK;
	HMODULE			hmodKernelDLL = NULL;
	FARPROC			farprocLoadLibrary;
	FARPROC			farprocGetCurrentProcess;
	FARPROC			farprocWriteProcessMemory;
	DWORD			dwDataAreaStartAddr;
	DWORD			dwDataAreaDLLStringAddr; // address for DLL string within process
	int				nBytesDLLString;
	DWORD			dwDataAreaOrigInstrAddr; // address for original instructions within process
	int				nBytesOrigInstr;
	BYTE*			pbCurrentArrayPtr;
	const int		k_nDataAreaOffsetBytes = 400; // offset from dwLDPreloadInstrAddr where data area will start

	hmodKernelDLL = LoadLibrary("kernel32.dll");
	ChkTruePrintLastError(hmodKernelDLL != NULL, "LoadLibrary");

	farprocLoadLibrary = GetProcAddress(hmodKernelDLL, "LoadLibraryA");
	ChkTruePrintLastError(farprocLoadLibrary != NULL, "GetProcAddress");
	farprocGetCurrentProcess = GetProcAddress(hmodKernelDLL, "GetCurrentProcess");
	ChkTruePrintLastError(farprocGetCurrentProcess != NULL, "GetProcAddress");
	farprocWriteProcessMemory = GetProcAddress(hmodKernelDLL, "WriteProcessMemory");
	ChkTruePrintLastError(farprocWriteProcessMemory != NULL, "GetProcAddress");

	pbCurrentArrayPtr = pbLDPreloadCode;

	/*
	 * Initialize the addresses to the data area members.
	 */
	dwDataAreaStartAddr = dwLDPreloadInstrAddr + k_nDataAreaOffsetBytes;
	dwDataAreaDLLStringAddr = dwDataAreaStartAddr;
	nBytesDLLString = strlen(szDLL) + 1;
	dwDataAreaOrigInstrAddr = dwDataAreaDLLStringAddr + nBytesDLLString;
	nBytesOrigInstr = NUM_ENTRY_CODE_BYTES;

	/* Fill with 'int 3' instructions for safety */
	memset(pbCurrentArrayPtr, 0xCC, NUM_LDPRELOAD_CODE_BYTES);

	/*
	 * Write the instructions which call LoadLibrary() on szDLL within
	 * the process.
	 */

	/* __asm mov eax, lpDLLStringStart; */
	*pbCurrentArrayPtr++ = 0xB8;
	*((DWORD*) pbCurrentArrayPtr)++ = (DWORD) dwDataAreaDLLStringAddr;

	/* __asm push eax */
	*pbCurrentArrayPtr++ = 0x50;

	/* __asm mov eax, farprocLoadLibrary; */
	*pbCurrentArrayPtr++ = 0xB8;
	*((DWORD*) pbCurrentArrayPtr)++ = (DWORD) farprocLoadLibrary;

	/* __asm call eax; */
	*pbCurrentArrayPtr++ = 0xFF;
	*pbCurrentArrayPtr++ = 0xD0;

	/*
	 * Write the instructions which will copy the original instructions
	 * back to the process's entry point address.  Must use
	 * WriteProcessMemory() for security reasons.
	 */

	/* pushing arguments to WriteProcessMemory()... */

	// lpNumberOfBytesWritten == NULL
	/* __asm mov eax, 0x0; */
	*pbCurrentArrayPtr++ = 0xB8;
	*((DWORD*) pbCurrentArrayPtr)++ = (DWORD) 0x0;
	/* __asm push eax */
	*pbCurrentArrayPtr++ = 0x50;

	// nSize == nBytesOrigInstr
	/* __asm mov eax, nBytesOrigInstr; */
	*pbCurrentArrayPtr++ = 0xB8;
	*((DWORD*) pbCurrentArrayPtr)++ = (DWORD) nBytesOrigInstr;
	/* __asm push eax */
	*pbCurrentArrayPtr++ = 0x50;

	// lpBuffer == dwDataAreaOrigInstrAddr
	/* __asm mov eax, dwDataAreaOrigInstrAddr; */
	*pbCurrentArrayPtr++ = 0xB8;
	*((DWORD*) pbCurrentArrayPtr)++ = (DWORD) dwDataAreaOrigInstrAddr;
	/* __asm push eax */
	*pbCurrentArrayPtr++ = 0x50;

	// lpBaseAddress == dwProcessEntryCodeAddr
	/* __asm mov eax, dwProcessEntryCodeAddr; */
	*pbCurrentArrayPtr++ = 0xB8;
	*((DWORD*) pbCurrentArrayPtr)++ = (DWORD) dwProcessEntryCodeAddr;
	/* __asm push eax */
	*pbCurrentArrayPtr++ = 0x50;

	// GetCurrentProcess()
	/* __asm mov eax, farprocGetCurrentProcess; */
	*pbCurrentArrayPtr++ = 0xB8;
	*((DWORD*) pbCurrentArrayPtr)++ = (DWORD) farprocGetCurrentProcess;

	/* __asm call eax; */
	*pbCurrentArrayPtr++ = 0xFF;
	*pbCurrentArrayPtr++ = 0xD0;

	// hProcess == GetCurrentProcess() == eax
	/* __asm push eax */
	*pbCurrentArrayPtr++ = 0x50;

	/* Done pushing arguments, call WriteProcessMemory() */

	/* __asm mov eax, farprocWriteProcessMemory; */
	*pbCurrentArrayPtr++ = 0xB8;
	*((DWORD*) pbCurrentArrayPtr)++ = (DWORD) farprocWriteProcessMemory;
	
	/* __asm call eax; */
	*pbCurrentArrayPtr++ = 0xFF;
	*pbCurrentArrayPtr++ = 0xD0;
	
	/* Jump back to the processes's original entry point address */

	/* __asm mov eax, dwProcessEntryCodeAddr; */
	*pbCurrentArrayPtr++ = 0xB8;
	*((DWORD*) pbCurrentArrayPtr)++ = (DWORD) dwProcessEntryCodeAddr;

	/* __asm jmp eax; */
	*pbCurrentArrayPtr++ = 0xFF;
	*pbCurrentArrayPtr++ = 0xE0;

	/*
	 * Initialize the 'data area' within the process.
	 */

	pbCurrentArrayPtr = pbLDPreloadCode + k_nDataAreaOffsetBytes;
	
	/* szDLL string */
	memcpy(pbCurrentArrayPtr, szDLL, nBytesDLLString);
	pbCurrentArrayPtr += nBytesDLLString;

	/* origInstr */
	memcpy(pbCurrentArrayPtr, pbOrigEntryCode, nBytesOrigInstr);
	pbCurrentArrayPtr += nBytesOrigInstr;

Error:
	if (hmodKernelDLL != NULL)
		{
		FreeLibrary(hmodKernelDLL);
		hmodKernelDLL = NULL;
		}

	return hr;
}


/*
 * pwerror
 *
 * Mirrors the UNIX perror() call, but for Win32 system errors (i.e.
 * retrieved from GetLastError())
 */
void
pwerror(const char* szPrefix, DWORD dwErr)
{
	LPVOID	lpMsgBuf;

	FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			dwErr,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), /* Default language */
			(LPTSTR) &lpMsgBuf,
			0,
			NULL);

	fprintf(stderr, "%s: %s", szPrefix, (char*) lpMsgBuf);

	LocalFree(lpMsgBuf);
}


/*
 * main
 *
 * Does all the magic!
 */
int
main(int argc, char* argv[])
{
	HRESULT				hr = S_OK;
	char*				szEXE;
	char*				szDLL;
	STARTUPINFO			si;
	PROCESS_INFORMATION	pi;
	DWORD				dwEntryAddr;
	LPVOID				lpLDPreloadInstrStorage;
	BYTE				rgbOrigEntryCode[NUM_ENTRY_CODE_BYTES];
	BYTE				rgbEntryCode[NUM_ENTRY_CODE_BYTES];
	BYTE				rgbLDPreloadCode[NUM_LDPRELOAD_CODE_BYTES];
	DWORD				dwSuspendCount;

	g_argv0 = argv[0];

	if (argc != 3)
		Usage();

	szEXE = argv[1];
	szDLL = argv[2];
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(STARTUPINFO);
	memset(&pi, 0, sizeof(pi));

	/* Create process suspended */
	ChkTruePrintLastError(CreateProcess(szEXE, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi), szEXE);

	/* Get entry point of process */
	Chk(GetEntryPointAddr(szEXE, &dwEntryAddr));

	/* Allocate memory block */
	lpLDPreloadInstrStorage = VirtualAllocEx(pi.hProcess, NULL, 500, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	ChkTruePrintLastError(lpLDPreloadInstrStorage != NULL, "VirtualAllocEx");

	/* Copy original instructions from start addr to one memory block */
	ChkTruePrintLastError(ReadProcessMemory(pi.hProcess, (LPVOID) dwEntryAddr, rgbOrigEntryCode, NUM_ENTRY_CODE_BYTES, NULL), "ReadProcessMemory");

	/* Initialize rgbEntryCode (simple push arguments, jmp to memory block #2 code to entry point) */
	Chk(WriteEntryCode(rgbEntryCode, (DWORD) lpLDPreloadInstrStorage));

	/* Initialize rgbLDPreloadCode */
	Chk(WriteLDPreloadCode(rgbLDPreloadCode, (DWORD) lpLDPreloadInstrStorage, rgbOrigEntryCode, dwEntryAddr, szDLL));

	/* Write rgbEntryCode to program */
	ChkTruePrintLastError(WriteProcessMemory(pi.hProcess, (LPVOID) dwEntryAddr, rgbEntryCode, NUM_ENTRY_CODE_BYTES, NULL), "WriteProcessMemory");

	/* Write rgbLDPreloadCode to program */
	ChkTruePrintLastError(WriteProcessMemory(pi.hProcess, lpLDPreloadInstrStorage, rgbLDPreloadCode, NUM_LDPRELOAD_CODE_BYTES, NULL), "WriteProcessMemory");

	/* resume program */
	dwSuspendCount = ResumeThread(pi.hThread);
	ChkTruePrintLastError(dwSuspendCount != 0xFFFFFFFF, "ResumeThread");

	WaitForSingleObject(pi.hProcess, INFINITE);

Error:
	return SUCCEEDED(hr) ? 0 : -1;
}
