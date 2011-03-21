/*
 * **********************************************************
 * Copyright 2007 Rether Networks, Inc.  All rights reserved.
 * **********************************************************
 * This file is part of FVM (Feather weight Virtual machine) project.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
 */

/*
 * fvm_file.c --
 *
 *	This code file implements file-related system call functions in
 *  the FVM layer. FVM intercepts the original NT system calls and
 *  replaces them with these functions. In each of these functions,
 *  FVM first checks whether the calling process is associated with
 *  a VM's context. If yes, FVM maps the virtual file names to
 *  physical file names and then calls the original system call
 *  function. The virtual-to-physical mapping is based on the design
 *  of resource sharing and copy-on-write.
 */


#include <ntddk.h>
#include <stdlib.h>
#include <ntstrsafe.h>
#include "fvm_util.h"
#include "fvm_table.h"
#include "hooksys.h"
#include "fvm_vm.h"
#include "fvm_syscalls.h"
#include "fvm_fileInt.h"
#include "fvm_file.h"

#define FVM_FILE_POOL_TAG '2GAT'
extern BOOLEAN DpWriteAllowed(WCHAR *path,  ULONG vmId);


/*
 * Declarations of local functions implemented in this file.
 */

static BOOLEAN FvmFile_NameFromFileInfo(
	PVOID FileRecordPtr,
	FILE_INFORMATION_CLASS InfoClass,
	PWCHAR *FileNamePtr,
	PULONG NameLenPtr
);

static VOID FvmFile_SaveDirEntries(
	PVOID FileRecordPtr,
	FILE_INFORMATION_CLASS InfoClass,
	HANDLE DirHandle,
	ULONG VmId
);

static NTSTATUS FvmFile_ProcessDirEntries(
	PVOID FileRecordPtr,
	ULONG BufLength,
	FILE_INFORMATION_CLASS InfoClass,
	PWCHAR FullName,
	HANDLE DirHandle,
	ULONG VmId
);

static BOOLEAN FvmFile_IsSingleFileLookup(PUNICODE_STRING PathMask);

static NTSTATUS FvmFile_QueryLongPath(
	PWCHAR ParentName,
	PWCHAR ShortName,
	PWCHAR LongName
);


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NameFromFileInfo --
 *
 *      Get the file name and file name length from an entry returned by the
 *      NtQueryDirectoryFile function.
 *
 * Results:
 *      Return TRUE when FileNamePtr is set to point to the file name and
 *      NameLenPtr points to the file name length. Return FALSE if the
 *      InfoClass is invalid.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

BOOLEAN
FvmFile_NameFromFileInfo(PVOID FileRecordPtr,  /* Pointer to a file information
                                               * structure entry */
                        FILE_INFORMATION_CLASS InfoClass,
                        PWCHAR *FileNamePtr,  /* Pointer to the file name */
                        PULONG NameLenPtr)    /* Pointer to the name length */
{
	*FileNamePtr = NULL;
	*NameLenPtr = 0UL;

	switch (InfoClass) {

	case FileDirectoryInformation:
		*NameLenPtr = ((PFILE_DIRECTORY_INFORMATION)FileRecordPtr)
				->FileNameLength;
		*FileNamePtr = ((PFILE_DIRECTORY_INFORMATION)FileRecordPtr)
				->FileName;
      	break;

	case FileFullDirectoryInformation:
		*NameLenPtr = ((PFILE_FULL_DIR_INFORMATION)FileRecordPtr)
				->FileNameLength;
		*FileNamePtr = ((PFILE_FULL_DIR_INFORMATION)FileRecordPtr)
				->FileName;
		break;

	case FileBothDirectoryInformation:
		*NameLenPtr = ((PFILE_BOTH_DIR_INFORMATION)FileRecordPtr)
				->FileNameLength;
		*FileNamePtr = ((PFILE_BOTH_DIR_INFORMATION)FileRecordPtr)
				->FileName;
		break;

	case FileNamesInformation:
		*NameLenPtr = ((PFILE_NAMES_INFORMATION)FileRecordPtr)
				->FileNameLength;
		*FileNamePtr = ((PFILE_NAMES_INFORMATION)FileRecordPtr)
				->FileName;
		break;

	default:
		return FALSE;
	}
	return TRUE;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_SaveDirEntries --
 *
 *      Save the directory query result under the VM's namespace into a list.
 *      When FVM further queries the corresponding directory on the host
 *      namespace, it can remove file name entries shown in the list from
 *      the returned buffer.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      New entries of HandleTableEntry of a VM may be allocated to hold the
 *      file name entries.
 *
 *-----------------------------------------------------------------------------
 */

VOID
FvmFile_SaveDirEntries(PVOID FileRecordPtr, /* Pointer to a file information
                                            * structure entry */
	                  FILE_INFORMATION_CLASS InfoClass,
	                  HANDLE DirHandle,    /* Handle of the directory being
	                                        * traversed in VM's workspace */
	                  ULONG VmId)          /* ID of the VM context */
{
	PVOID pvRecord = FileRecordPtr;
	ULONG ulNextOfs;
	FVM_PHandleTableEntry tableEntryPtr = NULL;
//       WCHAR szName[_MAX_PATH*2];
       PWCHAR szName=NULL;
       ULONG sz_szName = _MAX_PATH*2*sizeof(WCHAR);
       

       szName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (szName == NULL) {
                     DbgPrint("FvmFile_SaveDirEntries: ExAllocateFromPagedLookasideList fail\n");  
	}
       ASSERT(szName);
	do {
		ULONG ulNameLen = 0UL;
		PWCHAR pName = NULL;
		

		if (!FvmFile_NameFromFileInfo(pvRecord, InfoClass, &pName,
				&ulNameLen)) {
			break;
		}

		RtlZeroMemory(szName, sz_szName);
		wcsncpy(szName, pName, ulNameLen >> 1);

		/*
		 * Entries representing parent directory and current directory
		 * are not saved.
		 */

		if ((wcscmp(szName, L".") != 0)&&(wcscmp(szName, L"..") != 0)) {
			FvmTable_HandleTableAddName(szName, DirHandle, VmId, &tableEntryPtr);
			//DbgPrint("Add Entry Name: %S.\n", szName);
		}
		ulNextOfs = *(PULONG)pvRecord;
		pvRecord = (PVOID)((PUCHAR)pvRecord + ulNextOfs);

	} while (ulNextOfs != 0UL);

       if (szName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, szName );
	}    
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_ProcessDirEntries --
 *
 *      Parse the returned directory query result buffer and remove file
 *      entries that exist in the delete log and the name list saved through
 *      FvmFile_SaveDirEntries. Use this function to remove any duplicated and
 *      deleted entries in the result of NtQueryDirectoryFile when the function
 *      is used on a directory under the host namespace.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      Certain file entries in the buffer pointed by FileRecordPtr may be
 *      removed.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_ProcessDirEntries(PVOID FileRecordPtr, /* Pointer to the returned file
                                               * information buffer */
                         ULONG BufLength,     /* Maximum length of the
                                               * buffer */
	                     FILE_INFORMATION_CLASS InfoClass,
	                     PWCHAR FullName,     /* Full path of the directory */
	                     HANDLE DirHandle,    /* Handle of the directory being
	                                           * traversed in VM's workspace */
	                     ULONG VmId)          /* ID of the VM context */
{
	PVOID pvRecord, pvPrevRecord;
	ULONG ulNextOfs;
	NTSTATUS rc = STATUS_SUCCESS;
       PWCHAR szName=NULL;
       ULONG sz_szName = _MAX_PATH*2*sizeof(WCHAR);

	pvPrevRecord = NULL;
	pvRecord = FileRecordPtr;
	szName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
	if (szName == NULL) {
		DbgPrint("FvmFile_ProcessDirEntries: ExAllocateFromPagedLookasideList fail\n");  
		return STATUS_NO_MEMORY;
	}
	//ASSERT(szName);

	do {
		ULONG ulNameLen = 0UL;
		PWCHAR pName = NULL;
		PWCHAR ptrName = NULL;

           

		RtlZeroMemory(szName, sz_szName);
		wcsncpy(szName,FullName, wcslen(FullName));//_MAX_PATH);

		if (szName[wcslen(szName) - 1] != L'\\') {
			wcscat(szName, L"\\");
		}
		ptrName = szName + wcslen(szName);

		if (!FvmFile_NameFromFileInfo(pvRecord, InfoClass, &pName,
				&ulNameLen)) {
			break;
		}

		/*
		 * szName is filled with the full path of a file entry
		 */

		wcsncat(szName, pName, ulNameLen >> 1);

		// DbgPrint("Directory List: %S\n", szName);
		if ((DirHandle && (pName[0] == L'.')) ||
				FvmTable_DeleteLogLookup(szName, VmId) ||
				(DirHandle && FvmTable_HandleTableLookupName(DirHandle, VmId,
				ptrName))) {

			//DbgPrint("Directory List: remove duplicated or \
			//	deleted entry: %S\n", szName);

			if (*(PULONG)pvRecord != 0) {
				ULONG ulOldLength;

				ulOldLength = *(PULONG)pvRecord;
				ulNextOfs = ulOldLength;

				memmove(pvRecord,
						(PVOID)((PUCHAR)pvRecord + *(PULONG)pvRecord),
						((PUCHAR)FileRecordPtr + BufLength) -
						((PUCHAR)pvRecord + *(PULONG)pvRecord));

            	BufLength -= ulOldLength;
            	continue;
			} else {
				if (pvPrevRecord != NULL) {
					*(PULONG)pvPrevRecord = 0;
				} else {
					rc = STATUS_NO_SUCH_FILE;
				}
				break;
			}
		}
		ulNextOfs = *(PULONG)pvRecord;
		pvPrevRecord = pvRecord;
		pvRecord = (PVOID)((PUCHAR)pvRecord + ulNextOfs);

	} while (ulNextOfs != 0UL);

       if (szName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, szName );
	}
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_IsSingleFileLookup --
 *
 *      Check the file name mask string in NtQueryDirectoryFile function to
 *      decide whether it will return single file entries or multiple file
 *      entries.
 *
 * Results:
 *      Return TRUE if the mask string specifies a single file name,
 *      otherwise return FALSE.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

BOOLEAN
FvmFile_IsSingleFileLookup(PUNICODE_STRING PathMask) /* Name mask in directory
                                                     * query call */
{
	PWSTR maskStr;
	UINT len, i = 0;

	if (PathMask == NULL || PathMask->Buffer == NULL) {
		return FALSE;
	}

	maskStr = PathMask->Buffer;
	len = PathMask->Length >> 1;

	while (i < len) {
		if (maskStr[i] == L'*') return FALSE;
		if (maskStr[i] == L'?') return FALSE;
      	if (maskStr[i] == L'<') return FALSE;
      	if (maskStr[i] == L'>') return FALSE;
      	i++;
	}
	return TRUE;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_QueryLongPath --
 *
 *      This function converts a DOS 8.3 file name (short file name) to a
 *      FAT32/NTFS file name (long file name).
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *      If returned successfully, a long path name is created in the buffer
 *      pointed by LongName.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_QueryLongPath(PWCHAR ParentName,  /* Name of the parent directory */
                     PWCHAR ShortName,   /* The DOS 8.3 short name */
                     PWCHAR LongName)    /* The resulted long name */
{
	NTSTATUS rc;
	ULONG bufSize;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	PUNICODE_STRING pathNamePtr = NULL;
	PWCHAR filePath = NULL;
	PHANDLE hFilePtr = NULL;
	PIO_STATUS_BLOCK ioStatusPtr = NULL;
	PFILE_BOTH_DIR_INFORMATION fileInfoPtr = NULL;
	ULONG len;
	bufSize = sizeof(OBJECT_ATTRIBUTES) + sizeof(UNICODE_STRING) +
			sizeof(HANDLE) + sizeof(IO_STATUS_BLOCK) +
			sizeof(FILE_BOTH_DIR_INFORMATION) + _MAX_PATH*2 +
			_MAX_PATH*2*2 + 2;

	rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(), &objAttrPtr, 0,
			&bufSize, MEM_COMMIT, PAGE_READWRITE);

	if (NT_SUCCESS(rc)) {
		(CHAR *)pathNamePtr = ((CHAR *)objAttrPtr) + sizeof(OBJECT_ATTRIBUTES);
		(CHAR *)hFilePtr = ((CHAR *)pathNamePtr) + sizeof(UNICODE_STRING);
		(CHAR *)ioStatusPtr = ((CHAR *)hFilePtr) + sizeof(HANDLE);
		(CHAR *)fileInfoPtr = ((CHAR *)ioStatusPtr) + sizeof(IO_STATUS_BLOCK);
		(CHAR *)filePath = ((CHAR *)fileInfoPtr) +
				sizeof(FILE_BOTH_DIR_INFORMATION) + _MAX_PATH*2;
		try{
			len = wcslen(ParentName);
			wcscpy(filePath, ParentName);
			wcscat(filePath, L"\\");
		} except(EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("******* %x %x len\n", filePath, ParentName, len);
			DbgPrint(("?????????????????? Exception occured in FvmFile_QueryLongPath\n"));
			return 0xC0000005;
		}
		RtlInitUnicodeString(pathNamePtr, filePath);

		InitializeObjectAttributes(objAttrPtr, pathNamePtr,
				OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);

        /*
         * Open the parent directory
         */

		rc = (winNtOpenFileProc)(hFilePtr,
				FILE_READ_DATA|FILE_LIST_DIRECTORY|SYNCHRONIZE,
				objAttrPtr,
				ioStatusPtr,
				FILE_SHARE_READ,
				FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT);

		if (!NT_SUCCESS(rc)) {
		   bufSize = 0;
			FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &bufSize,
					MEM_RELEASE);
			return rc;
		}

		wcscpy(filePath, ShortName);
		RtlInitUnicodeString(pathNamePtr, filePath);

		rc = (winNtQueryDirectoryFileProc)(*hFilePtr,
				NULL,
				NULL,
				NULL,
				ioStatusPtr,
				fileInfoPtr,
				sizeof(FILE_BOTH_DIR_INFORMATION)+_MAX_PATH*2,
				FileBothDirectoryInformation,
				TRUE,
				pathNamePtr,
				FALSE);

		if (NT_SUCCESS(rc)) {
			wcsncpy(LongName, fileInfoPtr->FileName,
					fileInfoPtr->FileNameLength >> 1);

			LongName[fileInfoPtr->FileNameLength >> 1] = 0;
		}

		ZwClose(*hFilePtr);
		bufSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &bufSize,
				MEM_RELEASE);
	}
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_GetLongPathName --
 *
 *      This function converts a full DOS 8.3 file name (short file name)
 *      to a FAT32/NTFS file name (long file name).
 *
 * Results:
 *      Return TRUE on success or NTSTATUS error code on failure.
 *      If returned successfully, a long path name replaces the short
 *      path name in the buffer pointed by FileName
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

BOOLEAN
FvmFile_GetLongPathName(PWCHAR FileName) /* The input is a short path name,
                                         * and output is a long path name */
{
	PWCHAR endPtr, startPtr;
	BOOLEAN isShort, copyFlag = FALSE;
	PWCHAR longName=NULL;//[_MAX_PATH*2];
	PWCHAR newPath=NULL;//[_MAX_PATH*2];
    BOOLEAN rc;

       longName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       ASSERT(longName);
      
	longName[0] = 0;

	/*
	 * We assume that the input file name is like "\??\x:\abc\xyz.txt"
	 * "\??\x:" has 6 characters
	 */

	wcsncat(longName, FileName, 6);
	endPtr = FileName + 6;

	if (*endPtr != L'\\') {
		rc = TRUE;
              goto NtExit;
	}
	endPtr++;

       newPath = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       ASSERT(newPath);

	while (*endPtr) {
		isShort = FALSE;
		startPtr = endPtr;
		endPtr = wcschr(startPtr, L'\\');

		if (endPtr) {
			*endPtr = 0;
			/*
			 * We are processing name of a directory, e.g. "abcdef~1\"
			 */
			if (endPtr - startPtr == 8 && startPtr[6] == L'~') {
				isShort = TRUE;
			}
		} else {
			/*
			 * We are processing name of a file, e.g. "abcdef~1.txt"
			 */
			if (wcslen(startPtr) >= 8 && startPtr[6] == L'~') {
				isShort = TRUE;
			}
		}

		if (isShort) {
			if (NT_SUCCESS(FvmFile_QueryLongPath(longName, startPtr,
					newPath))) {

				wcscat(longName, L"\\");
            	wcscat(longName, newPath);
            	copyFlag = TRUE;
			} else {
				if (endPtr) {
					*endPtr = L'\\';
				}
				rc = TRUE;
                            goto NtExit;
			}
		} else {
			wcscat(longName, L"\\");
			wcscat(longName, startPtr);
		}

		if (endPtr) {
			*endPtr = L'\\';
			endPtr++;
		} else {
			break;
		}
	}

	if (copyFlag) {
		/*
		 * Copy the long path name to the original input buffer.
		 */

		int sLen, dLen;
		//DbgPrint("Short name found:%S\n", FileName);
		//DbgPrint("Long name created:%S\n", longName);
		sLen = wcslen(FileName);
		dLen = wcslen(longName);

        		if (FileName[sLen-1] == L'\\' && longName[dLen-1] != L'\\') {
        			wcscpy(FileName, longName);
        			wcscat(FileName, L"\\");
        		} else {
        			wcscpy(FileName, longName);
        		}

	}
	rc = TRUE;

NtExit:
        if (longName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, longName );
	}   
        if (newPath) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, newPath );
	}   
        return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_IsOpenforWrite --
 *
 *      This function checks if the desired access flag in the NtCreateFile/
 *      NtOpenFile function indicates a write access. If the sharing flag
 *      does not allow shared read, the access is treated as write access
 *      as well.
 *
 * Results:
 *      Return TRUE if it is a write access; otherwise return FALSE.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

BOOLEAN FvmFile_IsOpenforWrite(ACCESS_MASK DesiredAccess,
							  ULONG ShareAccess,
							  ULONG OpenOptions)
{
	/*
	 * File write operations
	 */
	if (DesiredAccess & (GENERIC_WRITE|
			FILE_WRITE_DATA|
		    /*
            FILE_WRITE_ATTRIBUTES|
            STANDARD_RIGHTS_WRITE|
             */
            FILE_WRITE_EA|
            FILE_APPEND_DATA|
            DELETE|
            WRITE_DAC|
            WRITE_OWNER)) {
		return TRUE;
	}

	/*
	 * If a file is not allowed sharing for read, then we cannot do
	 * copy-on-write. Therefore, such access is treated as write access
	 * and is performed copy-on-write.
	 */

	if (!(ShareAccess & FILE_SHARE_READ)) {
		return TRUE;
	}

	if (OpenOptions & FILE_DELETE_ON_CLOSE) {
		return TRUE;
	}
	return FALSE;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_IsFileinFVM --
 *
 *      This function checks if a given file path represents a physical file
 *      path under the VM's workspace, e.g. "\??\x:\fvm\fvmID\c\abc\xyz.txt".
 *      If yes, the function obtains its virtual file path, e.g. in this case,
 *      "\??\c:\abc\xyz.txt".
 *
 * Results:
 *      Return TRUE if the file path is a physical path under the FVM
 *      workspace; otherwise return FALSE.
 *
 * Side effects:
 *      When returning TRUE, a buffer is allocated to hold the virtual file
 *      path.
 *
 *-----------------------------------------------------------------------------
 */


BOOLEAN
FvmFile_IsFileinFVM(PWCHAR VmFile,       /* A given file path */
                   ULONG VmId,          /* ID of a VM context */
                   PWCHAR *HostFilePtr) /* Output virtual file path */
{
	PWCHAR fvmName=NULL;//[_MAX_PATH*2];
	PWCHAR fnPtr, ptr1, ptr2;
	int len;
	
	
       fvmName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       ASSERT(fvmName);

	_snwprintf(fvmName, _MAX_PATH, L"%s\\%s",  pvms[VmId]->fileRoot,
	    pvms[VmId]->idStr);
	len = wcslen(fvmName);

	
	fnPtr = wcschr(VmFile, L':');

	if (fnPtr != NULL) {
           
		fnPtr--;

		/*
	 	* Check if the file path is a physical path under the FVM workspace.
	 	*/

		if (_wcsnicmp(fnPtr, fvmName, len) != 0) {
            ExFreeToPagedLookasideList( &FileFullPathLookaside, fvmName );
			return FALSE;
		}

		ptr1 = fnPtr + len;

		if (*ptr1 != L'\\') {
            ExFreeToPagedLookasideList( &FileFullPathLookaside, fvmName );
			return FALSE;
		}
		ptr1++;

		ptr2 = ptr1 + 1;

		


		
	}
	else if(_wcsnicmp(VmFile, L"\\Device\\LanmanR", 15)==0){
		WCHAR *p1, *p2;
		int count = 0;
		BOOLEAN ddofsAccess = FALSE;
		
	 //\Device\LanmanRedirector\192.168.20.134\tempdofs$\65CF8B5F70034F84ABF152B4A86534EA\C\Documents and Settings\lclam\Local Settings\Temporary Internet Files\Content.MSO\7868BCDB.ppt
		if (_wcsnicmp(&VmFile[25], pvms[VmId]->DDOFSIP, wcslen(pvms[VmId]->DDOFSIP)) == 0&&(pvms[VmId]->DDOFSIP[0]!=L'\0')){
			ddofsAccess = TRUE;		
		}
		else if (_wcsnicmp(&VmFile[25], pvms[VmId]->DDOFSDNS, wcslen(pvms[VmId]->DDOFSDNS)) == 0&&(pvms[VmId]->DDOFSDNS[0]!=L'\0')){
			ddofsAccess = TRUE;	
		}
		else if (_wcsnicmp(&VmFile[25], pvms[VmId]->DDOFSNETBIOS, wcslen(pvms[VmId]->DDOFSNETBIOS)) == 0&&(pvms[VmId]->DDOFSNETBIOS[0]!=L'\0')){
			ddofsAccess = TRUE;			
		}
		if (!ddofsAccess){
			ExFreeToPagedLookasideList( &FileFullPathLookaside, fvmName );
			return FALSE;
		}

		p1 = VmFile;
		while(*p1 != L'\0'){
			if (*p1 == L'\\'){
				count++;
				if (count == 5)
					break;
			}
			p1++;
		}
		if (count != 5){
			ExFreeToPagedLookasideList( &FileFullPathLookaside, fvmName );
				return FALSE;

		}

		p1++;
		if (_wcsnicmp(p1,  pvms[VmId]->idStr, 32) != 0){
			ExFreeToPagedLookasideList( &FileFullPathLookaside, fvmName );
				return FALSE;
		}
		ptr1 = p1+33;
		ptr2 = ptr1 + 1;		
	}
	else{
		ExFreeToPagedLookasideList( &FileFullPathLookaside, fvmName );
		//DbgPrint("FvmFile_IsfileinFvm: >>>>>>>>> %S\n", VmFile);
		return FALSE;

	}
	*HostFilePtr = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILE_POOL_TAG);
	if (*HostFilePtr) {
		_snwprintf(*HostFilePtr, _MAX_PATH, L"\\??\\%c:%s", *ptr1, ptr2);
	}
		
	ExFreeToPagedLookasideList( &FileFullPathLookaside, fvmName );
	
	return TRUE;
}

/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_IsPipeMailslotConnect --
 *
 *      This function checks if a given file path represents a named pipe or
 *      a mailslot.
 *
 * Results:
 *      Return TRUE if the file represents a named pipe or a mailslot;
 *      otherwise return FALSE.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

BOOLEAN
FvmFile_IsPipeMailslotConnect(PWCHAR FileName)
{
	if (FileName) {
		
		if (!_wcsnicmp(FileName, L"\\DosDevices\\pipe",
			wcslen(L"\\DosDevices\\pipe"))) {			
			return TRUE;
		}
		if (!_wcsnicmp(FileName, L"\\Device\\NamedPipe",
			wcslen(L"\\Device\\NamedPipe"))) {
			return TRUE;
		}
		if (!_wcsnicmp(FileName, L"\\Device\\Mailslot",
		    wcslen(L"\\Device\\Mailslot"))) {
			return TRUE;
		}
		if (!_wcsnicmp(FileName, L"\\??\\Mailslot",  //for access local mailslot from vm
		    wcslen(L"\\??\\Mailslot"))) {
			return TRUE;
		}		
		if (wcsstr(FileName, L"\\PIPE\\"))
			return TRUE;
		if (wcsstr(FileName, L"\\Pipe\\"))
			return TRUE;
		if (wcsstr(FileName, L"\\pipe\\"))
					return TRUE;
		/*
		if (wcsstr(_wcsupr(FileName), L"\\PIPE\\"))
			return TRUE;
			*/
	}
	return FALSE;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_AllowDeviceAccess --
 *
 *      This function compares the given device name with a set of hardcoded
 *      device names.
 *
 * Results:
 *      Return TRUE if the given device name is in the device name set;
 *      otherwise return FALSE.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

BOOLEAN
FvmFile_AllowDeviceAccess(PWCHAR FileLinkName, ULONG vmId, BOOLEAN *ddofsAccess)
{
	if(!FileLinkName)
		return FALSE;
	
	
	if (ddofsAccess)
		*ddofsAccess = FALSE;
	
	//DbgPrint("allow deviceaccess: %S\n", FileLinkName);
	
	if (wcsncmp(FileLinkName, L"\\??\\", 4) ==0){
		if (FileLinkName[5] == L':'){
			if (FileLinkName[4] == pvms[vmId]->DDOFSDRIVE[0]){
				if (ddofsAccess)
					*ddofsAccess = TRUE;
				return TRUE;
			}
			else{
				return FALSE;
			}				
		}

		if(_wcsnicmp(FileLinkName, L"\\??\\UNC\\",7 ) == 0){
			//DbgPrint("Access... %S#%S#%S \n", FileLinkName,pvms[vmId]->DDOFSIP,pvms[vmId]->DDOFSDNS,pvms[vmId]->DDOFSNETBIOS);								

			if (_wcsnicmp(&FileLinkName[8], pvms[vmId]->DDOFSIP, wcslen(pvms[vmId]->DDOFSIP)) == 0&&(pvms[vmId]->DDOFSIP[0]!=L'\0')){
				if (ddofsAccess)
						*ddofsAccess = TRUE;
				return TRUE;
			}
			else if (_wcsnicmp(&FileLinkName[8], pvms[vmId]->DDOFSDNS, wcslen(pvms[vmId]->DDOFSDNS)) == 0&&(pvms[vmId]->DDOFSDNS[0]!=L'\0')){
				if (ddofsAccess)
						*ddofsAccess = TRUE;	
				return TRUE;
			}
			else if (_wcsnicmp(&FileLinkName[8], pvms[vmId]->DDOFSNETBIOS, wcslen(pvms[vmId]->DDOFSNETBIOS)) == 0&&(pvms[vmId]->DDOFSNETBIOS[0]!=L'\0')){
				if (ddofsAccess)
						*ddofsAccess = TRUE;	
				return TRUE;
			}
		}
		//else
		//	return FALSE;
	}
	else if(_wcsnicmp(FileLinkName, L"\\Device\\LanmanR", 15)==0){
	 //\Device\LanmanRedirector\192.168.20.134\tempdofs$\65CF8B5F70034F84ABF152B4A86534EA\C\Documents and Settings\lclam\Local Settings\Temporary Internet Files\Content.MSO\7868BCDB.ppt
			if (_wcsnicmp(&FileLinkName[25], pvms[vmId]->DDOFSIP, wcslen(pvms[vmId]->DDOFSIP)) == 0&&(pvms[vmId]->DDOFSIP[0]!=L'\0')){
				if (ddofsAccess)
						*ddofsAccess = TRUE;
				return TRUE;
			}
			else if (_wcsnicmp(&FileLinkName[25], pvms[vmId]->DDOFSDNS, wcslen(pvms[vmId]->DDOFSDNS)) == 0&&(pvms[vmId]->DDOFSDNS[0]!=L'\0')){
				if (ddofsAccess)
						*ddofsAccess = TRUE;	
				return TRUE;
			}
			else if (_wcsnicmp(&FileLinkName[25], pvms[vmId]->DDOFSNETBIOS, wcslen(pvms[vmId]->DDOFSNETBIOS)) == 0&&(pvms[vmId]->DDOFSNETBIOS[0]!=L'\0')){
				if (ddofsAccess)
						*ddofsAccess = TRUE;	
				return TRUE;
			}
	}

	if (pvms[vmId]->handle && _wcsnicmp(FileLinkName, L"\\??\\UNC\\",7 ) == 0){					
		return FALSE;
	}
	
	//DbgPrint("Access... %S\n", FileLinkName);
	if (//!(_wcsnicmp(FileLinkName, L"\\??\\UNC\\",7 )==0 && wcsstr(FileLinkName, L"\\PIPE\\srvsvc")) &&		
		_wcsnicmp(FileLinkName, L"\\??\\UNC\\",7 )!=0 &&		//lclam
		_wcsnicmp(FileLinkName, L"\\Device\\LanmanRedirector", 24) != 0 &&  //network neigborhood lclam
		_wcsnicmp(FileLinkName, L"\\Device\\LanmanDatagramReceiver", 30) != 0 &&  //network neigborhood lclam
		_wcsicmp(FileLinkName, L"\\??\\RNIFVMDR") != 0 &&
    	_wcsicmp(FileLinkName, L"\\Device\\Tcp") != 0 &&
    	_wcsicmp(FileLinkName, L"\\Device\\IP") != 0 &&
    	_wcsicmp(FileLinkName, L"\\??\\PIPE\\wkssvc") != 0 &&
    	_wcsicmp(FileLinkName, L"\\??\\PIPE\\svcctl") != 0 &&
    	_wcsicmp(FileLinkName, L"\\??\\PIPE\\ntsvcs") != 0 &&
    	_wcsicmp(FileLinkName, L"\\??\\PIPE\\lsarpc") != 0 &&
    	_wcsicmp(FileLinkName, L"\\??\\Pipe\\DhcpClient") != 0 &&
    	_wcsicmp(FileLinkName, L"\\Device\\RasAcd") != 0 &&
    	_wcsicmp(FileLinkName, L"\\Device\\Afd\\AsyncConnectHlp") != 0 &&
		_wcsicmp(FileLinkName, L"\\Device\\KsecDD") != 0 &&
//		_wcsicmp(FileLinkName, L"\\Device\\NamedPipe\\Autodesk Licensing Service") != 0 &&		
    	_wcsicmp(FileLinkName, L"\\Device\\Afd\\Endpoint") != 0) {			

		return FALSE;
	} else {			
		return TRUE;
	}
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_CreateFVMRootDir --
 *
 *      Create the root file directory for the specified VM.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_CreateFVMRootDir(ULONG VmId)   /* ID of a VM */
{
	NTSTATUS rc = STATUS_SUCCESS;
	PWCHAR rootPath=NULL;//[_MAX_PATH*2];
	ULONG memSize, memSize1;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	PIO_STATUS_BLOCK ioStatusPtr = NULL;
	PHANDLE fileHandlePtr = NULL;

       rootPath = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       ASSERT(rootPath);

	pvms[VmId]->fileRootLink[0] = L'\0';

	if (_wcsnicmp(pvms[VmId]->fileRoot, L"\\??\\UNC", 6)== 0) {
			_snwprintf(rootPath, _MAX_PATH, L"%s\\%s", pvms[VmId]->fileRoot,
					pvms[VmId]->idStr);
		}
	else {
		_snwprintf(rootPath, _MAX_PATH, L"\\??\\%s\\%s", pvms[VmId]->fileRoot,
			pvms[VmId]->idStr);
	}
		DbgPrint("----create root path: %S\n", rootPath);

	rc = FvmUtil_InitializeVMObjAttributes(NULL, rootPath, &objAttrPtr, &memSize);
	if (!NT_SUCCESS(rc)) {
//		CHAR errStr[64];
//		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errStr));
		DbgPrint("FvmFile_CreateFVMRootDir ErrMem:%s\n",rc);
		goto NtExit;
	}

	memSize1 = sizeof(HANDLE) + sizeof(IO_STATUS_BLOCK);
	rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(), &(CHAR *)fileHandlePtr,
    		0, &memSize1, MEM_COMMIT, PAGE_READWRITE);

	if (NT_SUCCESS(rc)) {
		(CHAR *)ioStatusPtr = ((CHAR *)fileHandlePtr) + sizeof(HANDLE);
	} else {
	    memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
    		MEM_RELEASE);
		goto NtExit;
	}

	rc = winNtCreateFileProc(fileHandlePtr,
    		FILE_LIST_DIRECTORY|SYNCHRONIZE,
    		objAttrPtr,
    		ioStatusPtr,
    		NULL,
    		FILE_ATTRIBUTE_NORMAL,
    		FILE_SHARE_READ,
    		FILE_OPEN_IF,
    		FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
    		NULL,
    		0);


	if (NT_SUCCESS(rc)) {
		PWCHAR wFullName;
//		wFullName = ExAllocatePoolWithTag(PagedPool, MAXPATHLEN, FVM_FILE_POOL_TAG);
              wFullName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );

		if (wFullName) {
			/*
			 * Obtain the NT device name from the file handle
			 */

			if (FvmUtil_PathFromHandle(*fileHandlePtr, NULL, wFullName) != FALSE) {
				wcscpy(pvms[VmId]->fileRootLink, wFullName);
			}
//			ExFreePool(wFullName);
                     ExFreeToPagedLookasideList( &FileFullPathLookaside, wFullName );
		}
		ZwClose(*fileHandlePtr);
	}
	else {
			DbgPrint("Create file failed %x\n", rc);
	}

    memSize1 = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &(CHAR *)fileHandlePtr,
    		&memSize1, MEM_RELEASE);

    memSize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
    		MEM_RELEASE);
NtExit:    
       ExFreeToPagedLookasideList( &FileFullPathLookaside, rootPath );
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_MapPath --
 *
 *      Map a file path under a VM's namespace to the physical file path
 *      under the host's namespace.
 *
 * Results:
 *      Return TRUE if the virtual-to-physical name mapping is completed.
 *      The buffer DeskName will be filled with the physical file path.
 *      The function returns FALSE if there is an error.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

BOOLEAN
FvmFile_MapPathEx(PWCHAR SourceName,    /* full file path (virtual name) */
			ULONG VmId,		/* ID of the VM associated with the
							 * calling process
							 */
			PWCHAR DestName,      /* full file path (physical name)*/

			BOOLEAN   append)
{
	PWCHAR rootPtr, dirPtr;
		int nStr, nLen;
	
		/*	source Name: \??\UNC\host\share\xyz.txt"
			DeskName:	 \??\x:\fvmRoot\fvmID\UNC\host\share\xyz.txt"
		*/
	
		/*
		 * If the SourceName is "\??\c:\abc\xyz.txt", the DeskName should
		 * be, for example, "\??\x:\fvmRoot\fvmID\c\abc\xyz.txt"
		 */
		
		//DbgPrint("Source name: %S --- %S\n",pvms[VmId]->fileRoot, SourceName); __DDOFS_%.8x
		if (_wcsnicmp(pvms[VmId]->fileRoot, L"\\??\\UNC", 6)== 0) { //lclam for ddofs
			if (_wcsnicmp(SourceName, L"\\??\\UNC", 6)==0) {
				rootPtr = SourceName+4;
				if(SourceName[wcslen(SourceName)-1] == L'\\'){//do not append __DDOFS_ tag for folders
					_snwprintf(DestName, _MAX_PATH, L"%s\\%s\\%s", pvms[VmId]->fileRoot, pvms[VmId]->idStr, rootPtr);
				}
				else{
					if (pvms[VmId]->handle && append)
						_snwprintf(DestName, _MAX_PATH, L"%s\\%s\\%s__DDOFS_%.8x", pvms[VmId]->fileRoot, pvms[VmId]->idStr, rootPtr, pvms[VmId]->handle);
					else
						_snwprintf(DestName, _MAX_PATH, L"%s\\%s\\%s", pvms[VmId]->fileRoot, pvms[VmId]->idStr, rootPtr);
				}
				return TRUE;
			}
	
			
			rootPtr = wcschr(SourceName, L':');
			if (!rootPtr) {
				return FALSE;
			}
			
			nStr = rootPtr - SourceName - 1;
					
			DestName[0] = 0;
			nLen = wcslen(DestName);
	
			if (pvms[VmId]->handle && SourceName[wcslen(SourceName)-1] != L'\\' && append){//do not append __DDOFS_ tag for folders
				_snwprintf(DestName + nLen, _MAX_PATH - nStr, L"%s\\%s\\%c%s__DDOFS_%.8x",
						pvms[VmId]->fileRoot, pvms[VmId]->idStr, SourceName[nStr],
						rootPtr + 1, pvms[VmId]->handle);
			}
			else{
				_snwprintf(DestName + nLen, _MAX_PATH - nStr, L"%s\\%s\\%c%s",
						pvms[VmId]->fileRoot, pvms[VmId]->idStr, SourceName[nStr],
						rootPtr + 1);
			}
		}
		else{
			if (_wcsnicmp(SourceName, L"\\??\\UNC", 6)==0) {
				rootPtr = SourceName+4;
				if (pvms[VmId]->handle && append){
					_snwprintf(DestName, _MAX_PATH, L"\\??\\%s\\%s\\%s__DDOFS_%.8x", pvms[VmId]->fileRoot, pvms[VmId]->idStr, rootPtr,pvms[VmId]->handle);
				}
				else{
					_snwprintf(DestName, _MAX_PATH, L"\\??\\%s\\%s\\%s", pvms[VmId]->fileRoot, pvms[VmId]->idStr, rootPtr);
				}
				return TRUE;
			}
	
			rootPtr = wcschr(SourceName, L':');
			if (!rootPtr) {
				return FALSE;
			}
	
			nStr = rootPtr - SourceName - 1;
	
			wcsncpy(DestName, SourceName, nStr);
			DestName[nStr] = 0;
	
			nLen = wcslen(DestName);
			if (pvms[VmId]->handle && append &&0){
				_snwprintf(DestName + nLen, _MAX_PATH - nStr, L"%s\\%s\\%c%s__DDOFS_%.8x",
								pvms[VmId]->fileRoot, pvms[VmId]->idStr, SourceName[nStr],
								rootPtr + 1, pvms[VmId]->handle);					
			}
			else{
				_snwprintf(DestName + nLen, _MAX_PATH - nStr, L"%s\\%s\\%c%s",
					pvms[VmId]->fileRoot, pvms[VmId]->idStr, SourceName[nStr],
					rootPtr + 1);
			}
		}
		return TRUE;

}

BOOLEAN
FvmFile_MapPath(PWCHAR SourceName,    /* full file path (virtual name) */
			ULONG VmId,		/* ID of the VM associated with the
							 * calling process
							 */
			PWCHAR DestName)     /* full file path (physical name)*/

{
	return FvmFile_MapPathEx(SourceName, VmId, DestName, 0);
}

/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_MapPipeMailSlotPath --
 *
 *      Map the path of a named pipe or a mailslot under a VM's namespace
 *      to the physical path under the host's namespace.
 *
 * Results:
 *      Return TRUE if the virtual-to-physical name mapping is completed.
 *      The buffer DeskName will be filled with the physical file path.
 *      The function returns FALSE if there is an error.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

BOOLEAN
FvmFile_MapPipeMailSlotPath(PWCHAR SourceName, /* full path (virtual name) */
                           ULONG VmId,        /* ID of the VM associated
       					                                        * with the
       					                                        * calling process
       					                                        */
                           PWCHAR DestName)   /* full path (physical name)*/
{
	PWCHAR namePtr;
	namePtr = wcsrchr(SourceName, L'\\');
	if (!namePtr) {
		return FALSE;
	}
	
	if (!_wcsnicmp(SourceName, L"\\DosDevices\\pipe",
			wcslen(L"\\DosDevices\\pipe"))) {
			//_snwprintf(DestName, _MAX_PATH, L"\\Device\\NamedPipe\\FVM%u",  VmId);
			wcscpy(DestName, SourceName);
			return TRUE;
			
	}
		*namePtr = 0;
	_snwprintf(DestName, _MAX_PATH, L"%s\\FVM-%u\\%s", SourceName, VmId,
    		namePtr + 1);

	*namePtr = L'\\';
	return TRUE;
}


#ifndef USE_FS_MAP

/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtCreateFileT1 --
 *
 *      This function implements the FVM-provided NtCreateFile system call
 *      when the CreateDisposition argument is FILE_SUPERSEDE or
 *      FILE_OVERWRITE_IF. Since the two flags indicate that the target file
 *      will be overwritten anyway, we directly invoke the orignal NtCreateFile
 *      on the VM's private workspace. In the case of FILE_OVERWRITE_IF, we
 *      may also need to copy the file's attributes from the host environment.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtCreateFileT1(OUT PHANDLE FileHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN PLARGE_INTEGER AllocationSize,
		IN ULONG FileAttributes,
		IN ULONG ShareAccess,
		IN ULONG CreateDisposition,
		IN ULONG CreateOptions,
		IN PVOID EaBuffer,
		IN ULONG EaLength,
		IN PWCHAR FileLinkName,    /* virtual file path */
		IN PWCHAR VDirName,        /* mapped physical file
						                           * path */
		IN ULONG VmId)	/* ID of the VM's context */ {

	NTSTATUS rc, rc1;
	ULONG memSize, memSize1;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	PFILE_BASIC_INFORMATION fileBasicInfoPtr = NULL;
	PIO_STATUS_BLOCK ioStatusPtr = NULL;
	BOOLEAN copyAttr = FALSE;

	/*
	 * Get an object pointing to the private path of the file under
	 * a VM's workspace.
	 */
	rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, VDirName, &objAttrPtr,
		    &memSize);
	if (!NT_SUCCESS(rc)) {
		CHAR errStr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errStr));
		rc = STATUS_ACCESS_DENIED;
		goto ntExit;
	}

	/*
 	 * The difference between FILE_SUPERSEDE and FILE_OVERWRITE_IF is that
 	 * the latter preserves the file attributes if the file exists. Therefore,
 	 * if the file exists on the host environment but not in the VM, the
 	 * attributes should be duplicated to the file created in the VM.
	 */
	if (CreateOptions == FILE_OVERWRITE_IF) {
		memSize1 = sizeof(FILE_BASIC_INFORMATION);
		rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr,
			    0, &memSize1, MEM_COMMIT, PAGE_READWRITE);

		if (NT_SUCCESS(rc)) {
			rc = (winNtQueryAttributesFileProc)(
				    objAttrPtr, fileBasicInfoPtr);

			if (rc == STATUS_OBJECT_PATH_NOT_FOUND ||
			    rc == STATUS_OBJECT_NAME_NOT_FOUND) {
				/*
				 * If the file already exists in the VM's workspace, we do
				 * not need to worry about the file on the host environment.
				 * When it does not, exist we use copyAttr as a flag to
				 * indicate that we may need to copy the file attributes
				 * from the host environment.
				 */
				copyAttr = TRUE;
			}
			memSize1 = 0;
			FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr,
			    &memSize1, MEM_RELEASE);
		}
	}

	/*
	 * Create parent directories of the file under the VM's workspace.
	 */
	FvmUtil_CreateFileDir(FileLinkName, VDirName, VmId);

	rc = (winNtCreateFileProc)(FileHandle, DesiredAccess,
		    objAttrPtr, IoStatusBlock, AllocationSize,
    		FileAttributes, ShareAccess, CreateDisposition, CreateOptions,
    		EaBuffer, EaLength);

   memSize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
	    MEM_RELEASE);

	if (!NT_SUCCESS(rc)) {
		CHAR errStr[64];
		DbgPrint("CreateErrT1:%s\n", FvmUtil_ErrorString(rc, errStr));
	} else {
		if (copyAttr && !FvmTable_DeleteLogLookup(FileLinkName, VmId)) {
			memSize = sizeof(FILE_BASIC_INFORMATION) + sizeof(IO_STATUS_BLOCK);
			rc1 = FvmVm_AllocateVirtualMemory(NtCurrentProcess(),
				    &fileBasicInfoPtr, 0, &memSize, MEM_COMMIT,
				    PAGE_READWRITE);


			if (NT_SUCCESS(rc1)) {
				(char *)ioStatusPtr = ((char *)fileBasicInfoPtr) +
						    sizeof(FILE_BASIC_INFORMATION);
				rc1 = (winNtQueryAttributesFileProc)(ObjectAttributes,
					    fileBasicInfoPtr);

				if (NT_SUCCESS(rc1))
					/*
					 * If it is FILE_OVERWRITE_IF, and the file exists
					 * on the host environment, then we should copy the
					 * file attributes after the file is created in the VM.
					 */

					(winNtSetInformationFileProc)(*FileHandle, ioStatusPtr,
					    fileBasicInfoPtr, sizeof(FILE_BASIC_INFORMATION),
					    FileBasicInformation);

               memSize = 0;
					FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr,
					    &memSize, MEM_RELEASE);
			}
		}
		FvmTable_DeleteLogRemove(FileLinkName, VmId);
	}
ntExit:
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtCreateFileT2 --
 *
 *      This function implements the FVM-provided NtCreateFile system call
 *      when the CreateDisposition argument is FILE_OPEN or FILE_OVERWRITE.
 *      If there is already a file copy under the FVM's workspace, we invoke
 *      the original NtCreateFile on the private file copy. Otherwise,
 *      according to the desired access, we may need to do copy-on-write to
 *      prevent the original file on the host environment from being opened
 *      for write.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtCreateFileT2(OUT PHANDLE FileHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN PLARGE_INTEGER AllocationSize,
		IN ULONG FileAttributes,
		IN ULONG ShareAccess,
		IN ULONG CreateDisposition,
		IN ULONG CreateOptions,
		IN PVOID EaBuffer,
		IN ULONG EaLength,
		IN PWCHAR FileLinkName,    /* virtual file path */
		IN PWCHAR VDirName,        /* mapped physical file
									* path */
		IN ULONG VmId)             /* ID of the VM's context */
{
	NTSTATUS rc;
	ULONG memSize = _MAX_PATH*2;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;

	/*
	 * Get an object pointing to the private path of the file under
	 * a VM's workspace.
	 */

	rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, VDirName, &objAttrPtr,
		    &memSize);
	if (!NT_SUCCESS(rc)) {
		CHAR errStr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errStr));
		rc = STATUS_ACCESS_DENIED;
		goto ntExit;
	}

	rc = (winNtCreateFileProc)(
		    FileHandle, DesiredAccess,
		    objAttrPtr, IoStatusBlock,
		    AllocationSize, FileAttributes,
		    ShareAccess, CreateDisposition,
		    CreateOptions, EaBuffer, EaLength);

	/*
	 * If the file to be opened exists under the VM's workspace, no further
	 * processing is required.
	 */

	if (NT_SUCCESS(rc)) {
	   memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
		    MEM_RELEASE);
		goto ntExit;
	} else if (rc != STATUS_OBJECT_PATH_NOT_FOUND &&
		    rc != STATUS_OBJECT_NAME_NOT_FOUND) {
		   memSize = 0;
         FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
		     MEM_RELEASE);
         goto ntExit;
	}


	/*
	 * FILE_OPEN or FILE_OVERWRITE requires the file to be accessed exists.
	 * So we need to check if the file is already in the DeleteLog.
	 */

	if (!FvmTable_DeleteLogLookup(FileLinkName, VmId)) {
		/*
		 * Check if the process will open the file for write.
		 */

		if (CreateDisposition != FILE_OVERWRITE &&
		    !FvmFile_IsOpenforWrite(DesiredAccess, ShareAccess,
		    CreateOptions)) {
		   memSize = 0;
			FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize, MEM_RELEASE);
			goto winSysCall;
		}

		/*
		 * Copy the file to the VM's workspace and open it there.
		 */

		rc = FvmUtil_CopyFiletoVM(ObjectAttributes, FileLinkName, VDirName,
			    (BOOLEAN)(CreateOptions & FILE_DIRECTORY_FILE), FALSE, VmId);

		if (NT_SUCCESS(rc)) {
			rc = (winNtCreateFileProc)(FileHandle, DesiredAccess, objAttrPtr,
				    IoStatusBlock, AllocationSize, FileAttributes,
				    ShareAccess, CreateDisposition, CreateOptions,
				    EaBuffer, EaLength);

			if (!NT_SUCCESS(rc)) {
				CHAR errStr[64];
				DbgPrint("CreateErrT2:%s\n", FvmUtil_ErrorString(rc, errStr));
			}
		}
	}
	memSize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
	    MEM_RELEASE);
	goto ntExit;

winSysCall:
	rc = (winNtCreateFileProc)(
		    FileHandle, DesiredAccess, ObjectAttributes,
		    IoStatusBlock, AllocationSize, FileAttributes,
		    ShareAccess, CreateDisposition, CreateOptions,
		    EaBuffer, EaLength);
ntExit:
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtCreateFileT3 --
 *
 *      This function implements the FVM-provided NtCreateFile system call
 *      when the CreateDisposition argument is FILE_CREATE or FILE_OPEN_IF.
 *      In the case of FILE_CREATE, if there is already a file copy under
 *      the FVM's workspace or the host environment, the system call fails.
 *      Otherwise, the file is created under the FVM's workspace. In the case
 *      of FILE_OPEN_IF, we may need to do copy-on-write if the desired access
 *      is open for write.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtCreateFileT3(OUT PHANDLE FileHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN PLARGE_INTEGER AllocationSize,
		IN ULONG FileAttributes,
		IN ULONG ShareAccess,
		IN ULONG CreateDisposition,
		IN ULONG CreateOptions,
		IN PVOID EaBuffer,
		IN ULONG EaLength,
		IN PWCHAR FileLinkName,    /* virtual file path */
		IN PWCHAR VDirName,        /* mapped physical file
									* path
									*/
		IN ULONG VmId)             /* ID of the VM's context */
{
	NTSTATUS rc, rc1;
	ULONG memSize, memSize1, memSize2;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	PFILE_BASIC_INFORMATION fileBasicInfoPtr = NULL;
	PIO_STATUS_BLOCK ioStatusPtr = NULL;

	/*
	 * Get an object pointing to the private path of the file under
	 * a VM's workspace.
	 */
	rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, VDirName, &objAttrPtr,
		    &memSize);
	if (!NT_SUCCESS(rc)) {
		CHAR errStr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errStr));
		rc = STATUS_ACCESS_DENIED;
		goto ntExit;
	}

	memSize1 = sizeof(FILE_BASIC_INFORMATION);
	rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr, 0,
		    &memSize1, MEM_COMMIT, PAGE_READWRITE);

	if (!NT_SUCCESS(rc)) {
	   memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
		    MEM_RELEASE);
		rc = STATUS_ACCESS_DENIED;
		goto ntExit;
	}

	/*
	 * We use NtQueryAttributesFile to check whether the file exists in the VM's
	 * workspace.
	 */

	rc = (winNtQueryAttributesFileProc)(objAttrPtr, fileBasicInfoPtr);

	if (NT_SUCCESS(rc) || (rc != STATUS_OBJECT_PATH_NOT_FOUND &&
	    rc != STATUS_OBJECT_NAME_NOT_FOUND)) {
		if (CreateDisposition == FILE_CREATE) {
			/*
			 * The desired behavior of FILE_CREATE is to fail the request
			 * if a file with the same name exists.
			 */

			rc = STATUS_OBJECT_NAME_COLLISION;
		} else {
			/*
			 * If the CreateDisposition is FILE_OPEN_IF, we simply open the
			 * file from the VM's workspace.
			 */

			rc = (winNtCreateFileProc)(FileHandle, DesiredAccess,
				    objAttrPtr, IoStatusBlock, AllocationSize,
				    FileAttributes, ShareAccess, CreateDisposition,
				    CreateOptions, EaBuffer, EaLength);
		}
	    memSize1 = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr, &memSize1, MEM_RELEASE);
		memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize, MEM_RELEASE);
		goto ntExit;
	}

	if (FvmTable_DeleteLogLookup(FileLinkName, VmId)) {
		/*
		 * If the file has been deleted before (in the DeleteLog), we create the file
		 * in the VM's workspace.
		 */

        memSize1 = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr, &memSize1,
		    MEM_RELEASE);

		FvmUtil_CreateFileDir(FileLinkName, VDirName, VmId);

		rc = (winNtCreateFileProc)(FileHandle, DesiredAccess,
				objAttrPtr, IoStatusBlock, AllocationSize,
			    FileAttributes, ShareAccess, CreateDisposition,
			    CreateOptions, EaBuffer, EaLength);

      memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
		    MEM_RELEASE);

		if (NT_SUCCESS(rc)) {
			FvmTable_DeleteLogRemove(FileLinkName, VmId);
		}
		goto ntExit;
	}

   /*
    * We further check if there is a shared file existing on the host environment.
    */

   rc = (winNtQueryAttributesFileProc)(
            ObjectAttributes, fileBasicInfoPtr );

	if (NT_SUCCESS(rc) || (rc != STATUS_OBJECT_PATH_NOT_FOUND &&
	    rc != STATUS_OBJECT_NAME_NOT_FOUND)) {
		if (CreateDisposition == FILE_CREATE) {
			rc = STATUS_OBJECT_NAME_COLLISION;
		} else {
			if (!FvmFile_IsOpenforWrite(DesiredAccess, ShareAccess,
			    CreateOptions)) {
			    memSize1 = 0;
				FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr,
				    &memSize1, MEM_RELEASE);
				memSize = 0;
				FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
				    MEM_RELEASE);
				goto winSysCall;
			}

			/*
			 * We copy the file from the host environment to the VM's workspace
			 * and open it there.
			 */
			rc = FvmUtil_CopyFiletoVM(ObjectAttributes, FileLinkName, VDirName,
				    (BOOLEAN)(CreateOptions & FILE_DIRECTORY_FILE), FALSE, VmId);

			if (NT_SUCCESS(rc)) {
				rc = (winNtCreateFileProc)(FileHandle, DesiredAccess,
					    objAttrPtr, IoStatusBlock, AllocationSize,
					    FileAttributes, ShareAccess, CreateDisposition,
					    CreateOptions, EaBuffer, EaLength);
				if (!NT_SUCCESS(rc)) {
					CHAR errStr[64];
					DbgPrint("CreateErrT3:%s\n", FvmUtil_ErrorString(rc, errStr));
				}
			} else {
				/*
				 * If we cannot copy the file from the host environment, we can also
				 * create the file in the VM's workspace and set its attributes.
				 */

				FvmUtil_CreateFileDir(FileLinkName, VDirName, VmId);

				rc = (winNtCreateFileProc)(FileHandle, DesiredAccess,
					    objAttrPtr, IoStatusBlock, AllocationSize,
					    FileAttributes, ShareAccess, CreateDisposition,
					    CreateOptions, EaBuffer, EaLength);
				if (NT_SUCCESS(rc)) {
					memSize2 = sizeof(IO_STATUS_BLOCK);
					rc1 = FvmVm_AllocateVirtualMemory(NtCurrentProcess(),
						    &ioStatusPtr, 0, &memSize2, MEM_COMMIT,
						    PAGE_READWRITE);
					if (NT_SUCCESS(rc1)) {
						(winNtSetInformationFileProc) (*FileHandle, ioStatusPtr,
							    fileBasicInfoPtr, sizeof(FILE_BASIC_INFORMATION),
							    FileBasicInformation);
					    memSize2 = 0;
						FvmVm_FreeVirtualMemory(NtCurrentProcess(), &ioStatusPtr,
						    &memSize2, MEM_RELEASE);
					}
				}
			}
		}
	} else {
		/*
		 * If the file does not exist on the host environment as well as the VM's
		 * workspace, we will create the file in the VM's workspace.
		 */
		FvmUtil_CreateFileDir(FileLinkName, VDirName, VmId);

		rc = (winNtCreateFileProc)(FileHandle, DesiredAccess, objAttrPtr,
			    IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
			    CreateDisposition, CreateOptions, EaBuffer, EaLength);
		if (!NT_SUCCESS(rc)) {
			CHAR errStr[64];
			DbgPrint("CreateErrT3:%s\n", FvmUtil_ErrorString(rc, errStr));
		} else {
			FvmTable_DeleteLogRemove(FileLinkName, VmId);
		}
	}

    memSize1 = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr, &memSize1, MEM_RELEASE);
	memSize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize, MEM_RELEASE);
	goto ntExit;

winSysCall:
	rc = (winNtCreateFileProc)(FileHandle, DesiredAccess, ObjectAttributes,
			    IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
			    CreateDisposition, CreateOptions, EaBuffer, EaLength);
ntExit:
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtCreateFile --
 *
 *      This function is the FVM-provided NtCreateFile system call function.
 *      It checks the system call arguments to redirect access to regular
 *      files and special files, e.g. named pipe. It can also enable or
 *      disable accesses to devices, such as network access.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtCreateFile(OUT PHANDLE FileHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN PLARGE_INTEGER AllocationSize,
		IN ULONG FileAttributes,
		IN ULONG ShareAccess,
		IN ULONG CreateDisposition,
		IN ULONG CreateOptions,
		IN PVOID EaBuffer,
		IN ULONG EaLength) {
	NTSTATUS rc;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	ULONG vmId = INVALID_VMID;
	PWCHAR fnPtr = NULL;
	ULONG memSize = _MAX_PATH*2;

	WCHAR RegPath[_MAX_PATH*2]={L'\0'};

	InterlockedIncrement(&fvm_Calls_In_Progress);

	objAttrPtr = ObjectAttributes;
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		WCHAR fileLinkName[_MAX_PATH*2];
		WCHAR vDirName[_MAX_PATH*2];
		PWCHAR hostName, fvmName = NULL;

		if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
			goto winSysCall;
		}

		if (wcsstr(fileLinkName, L"lsarpc") != NULL)
			  goto winSysCall;
		if (wcsstr(fileLinkName, L"NtControlPipe") != NULL)
			  goto winSysCall;
		if (wcsstr(fileLinkName, L"srvsvc") != NULL)
			  goto winSysCall;
		if (wcsstr(fileLinkName, L"shadow") != NULL)
			  goto winSysCall;
		if (wcsstr(fileLinkName, L"sysmain.sdb") != NULL)
			  goto winSysCall;

		if (wcsstr(fileLinkName, L"systest") != NULL)
			  goto winSysCall;

		if (wcsstr(fileLinkName, L"MsiMsg") != NULL)
			  goto winSysCall;
		if (wcsstr(fileLinkName, L"msimain") != NULL)
			  goto winSysCall;

		if (!FvmIsLocalFileAccess(fileLinkName)) {
			/*
			 * The process is accessing a device file such as the network
			 * device or a named pipe.
			 */

			/*
			 * The following code redirects access to named pipe and mailslot
			 * under a VM's local namespace, while allowing all other types
			 * of device access.
			 */
		     if (FvmFile_IsPipeMailslotConnect(fileLinkName)) {
		        if (!FvmFile_MapPipeMailSlotPath(fileLinkName, vmId,
				    vDirName)) {
					goto winSysCall;
				}
				objAttrPtr = NULL;
				rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
					    &objAttrPtr, &memSize);
				if (!NT_SUCCESS(rc)) {
					rc = STATUS_ACCESS_DENIED;
					goto ntExit;
				}
				rc = (winNtCreateFileProc)(
					    FileHandle, DesiredAccess, objAttrPtr, IoStatusBlock,
					    AllocationSize, FileAttributes, ShareAccess,
					    CreateDisposition, CreateOptions, EaBuffer, EaLength);

                memSize = 0;
				FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
					    MEM_RELEASE);

				goto ntExit;
			} else {
				goto winSysCall;
			}
		}

		if (!FvmFile_GetLongPathName(fileLinkName)) {
			goto winSysCall;
		}

		if (FvmFile_IsFileinFVM(fileLinkName, vmId, &fnPtr)) {
			/*
			 * We found that the process attempts to access a file whose
			 * path is under a VM's workspace directory. This should rarely
			 * happen because a process should always operate on a virtual
			 * path instead of the FVM-renamed (physical) path. When it
			 * does happen, e.g. due to certain bug in the FVM's renaming
			 * mechanism, we should not perform further renaming here.
			 */

			objAttrPtr = NULL;
			/*
			 * Get an object pointing to the path of the original file
			 * shared on the host environment.
			 */

			rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, fnPtr,
				    &objAttrPtr, &memSize);
			if (!NT_SUCCESS(rc)) {
				rc = STATUS_OBJECT_PATH_NOT_FOUND;
				goto ntExit;
			}
			hostName = fnPtr;
			fvmName = fileLinkName;
		} else {
			fnPtr = NULL;
			hostName = fileLinkName;
			if (!FvmFile_MapPath(hostName, vmId, vDirName)) {
				goto winSysCall;
			}
			fvmName = vDirName;
		}

		switch (CreateDisposition) {
		case FILE_SUPERSEDE:
		case FILE_OVERWRITE_IF:
				rc = FvmFile_NtCreateFileT1(FileHandle, DesiredAccess,
					    objAttrPtr, IoStatusBlock, AllocationSize,
					    FileAttributes, ShareAccess, CreateDisposition,
					    CreateOptions, EaBuffer, EaLength, hostName,
					    fvmName, vmId);
				goto ntExit;

		case FILE_OPEN:
		case FILE_OVERWRITE:
				rc = FvmFile_NtCreateFileT2(FileHandle, DesiredAccess,
					    objAttrPtr, IoStatusBlock, AllocationSize,
					    FileAttributes, ShareAccess, CreateDisposition,
					    CreateOptions, EaBuffer, EaLength, hostName,
					    fvmName, vmId);
				goto ntExit;

		case FILE_CREATE:
		case FILE_OPEN_IF:
				rc = FvmFile_NtCreateFileT3(FileHandle, DesiredAccess,
					    objAttrPtr, IoStatusBlock, AllocationSize,
					    FileAttributes, ShareAccess, CreateDisposition,
					    CreateOptions, EaBuffer, EaLength, hostName,
					    fvmName, vmId);
				goto ntExit;
		}
	}
winSysCall:
	/*
	 * After detecting that a process is not associated with any VM,
	 * or after detecting an error, program controls are transferred to
	 * here and invokes the system call on the original file in the host
	 * environment.
	 */

	rc = (winNtCreateFileProc)(FileHandle, DesiredAccess, objAttrPtr,
		    IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		    CreateDisposition,
            CreateOptions, EaBuffer, EaLength);

ntExit:
		
	if (objAttrPtr && objAttrPtr != ObjectAttributes) {
	    memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize, MEM_RELEASE);
	}
	if (fnPtr) {
		ExFreePool(fnPtr);
	}

	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtOpenFile --
 *
 *      This function is the FVM-provided NtOpenFile system call function.
 *      It checks the system call arguments to redirect access to regular
 *      files and special files, e.g. named pipe. It can also enable or
 *      disable accesses to devices, such as network access. The implemen-
 *      tation is equivalent to NtCreateFile when the CreateDisposition is
 *      FILE_OPEN.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtOpenFile(OUT PHANDLE FileHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN ULONG ShareMode,
		IN ULONG OpenMode) {
	NTSTATUS rc;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	ULONG vmId = INVALID_VMID;
	PWCHAR fnPtr = NULL;
	ULONG memSize = _MAX_PATH*2, memSizeFvm = _MAX_PATH*2;
	POBJECT_ATTRIBUTES fvmObjPtr = NULL;

	WCHAR RegPath[_MAX_PATH*2]={L'\0'};

	InterlockedIncrement(&fvm_Calls_In_Progress);

	objAttrPtr = ObjectAttributes;
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		WCHAR fileLinkName[_MAX_PATH*2];
		WCHAR vDirName[_MAX_PATH*2];
		PWCHAR hostName, fvmName = NULL;

		if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
			goto winSysCall;
		}

		if (!FvmIsLocalFileAccess(fileLinkName)) {
			/*
			 * The process is accessing a device file such as the network
			 * device or a named pipe.
			 */


			/*
			 * The following code redirects access to named pipe and mailslot
			 * under a VM's local namespace, while allowing all other types
			 * of device access.
			 */
			if (FvmFile_IsPipeMailslotConnect(fileLinkName)) {
				if (!FvmFile_MapPipeMailSlotPath(fileLinkName, vmId,
				    vDirName)) {
					goto winSysCall;
				}

				objAttrPtr = NULL;
				rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
					    &objAttrPtr, &memSize);
				if (!NT_SUCCESS(rc)) {
					rc = STATUS_ACCESS_DENIED;
					goto ntExit;
				}

				rc = (winNtOpenFileProc)(FileHandle, DesiredAccess, objAttrPtr,
					    IoStatusBlock, ShareMode, OpenMode);

	            memSize = 0;
				FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
				    MEM_RELEASE);

				if (NT_SUCCESS(rc)) {
					goto ntExit;
				} else {
					objAttrPtr = ObjectAttributes;
					goto winSysCall;
	            }
			} else {
				goto winSysCall;
			}
		}

		if (!FvmFile_GetLongPathName(fileLinkName)) {
			goto winSysCall;
		}

		if (FvmFile_IsFileinFVM(fileLinkName, vmId, &fnPtr)) {
			/*
			 * See comments near the same function inside FvmFile_NtCreateFile
			 * in this code file.
			 */

			objAttrPtr = NULL;
			/*
			 * Get an object pointing to the path of the original file
			 * shared on the host environment.
			 */

			rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, fnPtr,
				    &objAttrPtr, &memSize);
			if (!NT_SUCCESS(rc)) {
				rc = STATUS_OBJECT_PATH_NOT_FOUND;
				goto ntExit;
			}
			hostName = fnPtr;
			fvmName = fileLinkName;
		} else {
			fnPtr = NULL;
			hostName = fileLinkName;

			if (!FvmFile_MapPath(hostName, vmId, vDirName)) {
				goto winSysCall;
			}
			fvmName = vDirName;
		}

		if (objAttrPtr == ObjectAttributes) {
			/*
			 * Get an object pointing to the private path of the file under
			 * a VM's workspace.
			 */

			rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
				    &fvmObjPtr, &memSizeFvm);
			if (!NT_SUCCESS(rc)) {
				CHAR errStr[64];
				DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errStr));
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}
		} else {
			fvmObjPtr = ObjectAttributes;
		}

		/*
		 * Try to open the file using a file path mapped to a VM's workspace.
		 */
		rc = (winNtOpenFileProc)(FileHandle, DesiredAccess, fvmObjPtr,
			    IoStatusBlock, ShareMode, OpenMode);

		/*
		 * If the file exists in a VM's workspace, simply return the opening
		 * result.
		 */

		if (NT_SUCCESS(rc)) {
			goto ntExit;
		} else {
			if (rc != STATUS_OBJECT_PATH_NOT_FOUND &&
			    rc != STATUS_OBJECT_NAME_NOT_FOUND) {
				goto ntExit;
			}
		}

		/*
		 * The file to be opened does not exist on the VM's workspace.
		 * So we go to the host environment and decide if a copy-on-write
		 * is necessary.
		 */

		if (!FvmTable_DeleteLogLookup(hostName, vmId)) {
			if (!FvmFile_IsOpenforWrite(DesiredAccess, ShareMode, OpenMode))
				goto winSysCall;

			/*
			 * If a file is to be opened for write, we copy the file to the
			 * VM's private workspace. This operation includes copying the
			 * parent directory, the file itself and file attributes.
			 */

			rc = FvmUtil_CopyFiletoVM(objAttrPtr, hostName, fvmName,
			    (BOOLEAN)(OpenMode & FILE_DIRECTORY_FILE), TRUE, vmId);

			if (NT_SUCCESS(rc)) {
				/*
				 * Try to open the file in the VM's workspace again.
				 */

				rc = (winNtOpenFileProc)(FileHandle, DesiredAccess, fvmObjPtr,
					    IoStatusBlock, ShareMode, OpenMode );
				if (!NT_SUCCESS(rc)) {
					CHAR errStr[64];
					DbgPrint("OpenErr2:%s\n", FvmUtil_ErrorString(rc, errStr));
				}
			}
		}
		goto ntExit;
	}

winSysCall:
	/*
	 * After detecting that a process is not associated with any VM,
	 * or after detecting an error, program controls are transferred to
	 * here and invokes the system call on the original file in the host
	 * environment.
	 */

	rc = (winNtOpenFileProc)(FileHandle, DesiredAccess, objAttrPtr,
		    IoStatusBlock, ShareMode, OpenMode);

ntExit:
	if (fvmObjPtr && fvmObjPtr != ObjectAttributes) {
	   memSizeFvm = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fvmObjPtr, &memSizeFvm, MEM_RELEASE);
	}
	if (objAttrPtr && objAttrPtr != ObjectAttributes) {
	   memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize, MEM_RELEASE);
	}
	if (fnPtr) {
		ExFreePool(fnPtr);
	}

	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtQueryAttributesFile --
 *
 *      This function is the FVM-provided NtQueryAttributesFile system call
 *      function. If there is already a file existing under the FVM's
 *      workspace, we renames the file name argument to access the private
 *      file copy.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtQueryAttributesFile(
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PFILE_BASIC_INFORMATION FileInformation) {
	NTSTATUS rc;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	ULONG vmId = INVALID_VMID;
	PWCHAR fnPtr = NULL;
	ULONG memSize = _MAX_PATH*2, memSizeFvm = _MAX_PATH*2;
	POBJECT_ATTRIBUTES fvmObjPtr = NULL;

	InterlockedIncrement(&fvm_Calls_In_Progress);

	objAttrPtr = ObjectAttributes;
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		PWCHAR binPath = NULL;
		WCHAR fileLinkName[_MAX_PATH*2];
		WCHAR vDirName[_MAX_PATH*2];
		PWCHAR hostName, fvmName = NULL;

		if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
			goto winSysCall;
		}

		if (!FvmIsLocalFileAccess(fileLinkName)) {
			goto winSysCall;
		}

		if (!FvmFile_GetLongPathName(fileLinkName)) {
			goto winSysCall;
		}

		if (FvmFile_IsFileinFVM(fileLinkName, vmId, &fnPtr)) {
			/*
			 * See comments near the same function inside FvmFile_NtCreateFile
			 * in this code file.
			 */
			objAttrPtr = NULL;
			rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, fnPtr,
				    &objAttrPtr, &memSize);
			if (!NT_SUCCESS(rc)) {
				rc = STATUS_OBJECT_PATH_NOT_FOUND;
				goto ntExit;
			}
			hostName = fnPtr;
			fvmName = fileLinkName;
		} else {
			fnPtr = NULL;
			hostName = fileLinkName;

			if (!FvmFile_MapPath(hostName, vmId, vDirName)) {
				goto winSysCall;
			}
			fvmName = vDirName;
		}

#if DBG_QUERYATTRIBUTESFILE
		binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILE_POOL_TAG);
		if (binPath == NULL)
			goto winSysCall;
		FvmUtil_GetBinaryPathName(binPath);
		DbgPrint("NtQueryAttributesFile : Application Name - %S\n", binPath);
		ExFreePool(binPath);
		DbgPrint("               Arguments - %S\n", hostName);
		DbgPrint("               New file name - %S\n", fvmName);
#endif

		if (objAttrPtr == ObjectAttributes) {
			rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
				    &fvmObjPtr, &memSizeFvm);
			if (!NT_SUCCESS(rc))
				goto winSysCall;
		} else {
			fvmObjPtr = ObjectAttributes;
		}

		/*
		 * Try to access the file in the VM's workspace.
		 */

		rc = (winNtQueryAttributesFileProc)(fvmObjPtr, FileInformation);

		/*
		 * If the file exists in a VM's workspace, simply return the query
		 * result.
		 */

		if (NT_SUCCESS(rc))
			goto ntExit;
		if (rc != STATUS_OBJECT_PATH_NOT_FOUND &&
		    rc != STATUS_OBJECT_NAME_NOT_FOUND)
			goto ntExit;

		if (FvmTable_DeleteLogLookup(hostName, vmId)) {
			rc = STATUS_OBJECT_PATH_NOT_FOUND;
			goto ntExit;
		}
	}
winSysCall:
	rc = (winNtQueryAttributesFileProc)(objAttrPtr, FileInformation);
ntExit:

	if (fvmObjPtr && fvmObjPtr != ObjectAttributes) {
	   memSizeFvm = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fvmObjPtr, &memSizeFvm,
		    MEM_RELEASE);
	}
	if (objAttrPtr && objAttrPtr != ObjectAttributes) {
	   memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
			MEM_RELEASE);
	}
	if (fnPtr) {
		ExFreePool(fnPtr);
	}

	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtQueryFullAttributesFile --
 *
 *      This function is the FVM-provided NtQueryFullAttributesFile system
 *      call function. If there is already a file existing under the FVM's
 *      workspace, we renames the file name argument to access the private
 *      file copy.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtQueryFullAttributesFile(
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation) {
	NTSTATUS rc;
	POBJECT_ATTRIBUTES objAttrPtr = NULL, fvmObjPtr = NULL;
	ULONG memSize = _MAX_PATH*2, memSizeFvm = _MAX_PATH*2;
	ULONG vmId = INVALID_VMID;
	PWCHAR fnPtr = NULL;

	InterlockedIncrement(&fvm_Calls_In_Progress);

	objAttrPtr = ObjectAttributes;
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		PWCHAR binPath = NULL;
		WCHAR fileLinkName[_MAX_PATH*2];
		WCHAR vDirName[_MAX_PATH*2];
		PWCHAR hostName, fvmName = NULL;

		if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
			goto winSysCall;
		}
		if (!FvmIsLocalFileAccess(fileLinkName)) {
			goto winSysCall;
		}
		if (!FvmFile_GetLongPathName(fileLinkName)) {
			goto winSysCall;
		}

		if (FvmFile_IsFileinFVM(fileLinkName, vmId, &fnPtr)) {
			/*
			 * See comments near the same function inside FvmFile_NtCreateFile
			 * in this code file.
			 */

			objAttrPtr = NULL;
			rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, fnPtr, &objAttrPtr, &memSize);
			if (!NT_SUCCESS(rc)) {
			rc = STATUS_OBJECT_PATH_NOT_FOUND;
			goto ntExit;
		}
		hostName = fnPtr;
		fvmName = fileLinkName;

	} else {
		fnPtr = NULL;
		hostName = fileLinkName;

		if (!FvmFile_MapPath(hostName, vmId, vDirName)) {
			goto winSysCall;
		}
		fvmName = vDirName;
	}

#if DBG_QUERYFULLATTRIBUTESFILE
	binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILE_POOL_TAG);
	if (binPath == NULL) goto winSysCall;
	FvmUtil_GetBinaryPathName(binPath);
	DbgPrint("NtQueryFullAttributesFile : Application Name - %S\n", binPath);
	ExFreePool(binPath);

	DbgPrint("               Arguments - %S\n", hostName);
	DbgPrint("               New file name - %S\n", fvmName);
#endif

	if (objAttrPtr == ObjectAttributes) {
		rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
			    &fvmObjPtr, &memSizeFvm);
		if (!NT_SUCCESS(rc))
		 	goto winSysCall;
		} else {
			fvmObjPtr = ObjectAttributes;
		}

		/*
		 * Try to access the file in the VM's workspace.
		 */
		rc = (winNtQueryFullAttributesFileProc)(fvmObjPtr, FileInformation);

		/*
		 * If the file exists in a VM's workspace, simply return the query
		 * result.
		 */
		if (NT_SUCCESS(rc))
			goto ntExit;
		if (rc != STATUS_OBJECT_PATH_NOT_FOUND &&
		    rc != STATUS_OBJECT_NAME_NOT_FOUND)
			goto ntExit;

		if (FvmTable_DeleteLogLookup(hostName, vmId)) {
		    rc = STATUS_OBJECT_PATH_NOT_FOUND;
			goto ntExit;
		}
	}
winSysCall:
	rc = (winNtQueryFullAttributesFileProc)(objAttrPtr, FileInformation);
ntExit:

	if (fvmObjPtr && fvmObjPtr != ObjectAttributes) {
	   memSizeFvm = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fvmObjPtr, &memSizeFvm,
		    MEM_RELEASE);
	}
	if (objAttrPtr && objAttrPtr != ObjectAttributes) {
	   memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
		    MEM_RELEASE);
	}
	if (fnPtr) {
		ExFreePool(fnPtr);
	}

	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtDeleteFile --
 *
 *      This function is the FVM-provided NtDeleteFile system call function.
 *      If the target file exists on the host environment but not in the VM's
 *      workspace, we save the file path into the DeleteLog and mark it as
 *      having been deleted. Please note that this system call function is
 *      rarely invoked because the Win32 subsystem uses NtSetInformationFile
 *      to delete a file.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtDeleteFile(
		IN POBJECT_ATTRIBUTES ObjectAttributes) {

	NTSTATUS rc;
	ULONG vmId = INVALID_VMID;
	POBJECT_ATTRIBUTES objAttrPtr = NULL, fvmObjPtr = NULL;
	ULONG memSize = _MAX_PATH*2, memSizeFvm = _MAX_PATH*2;
	PWCHAR fnPtr = NULL;

	InterlockedIncrement(&fvm_Calls_In_Progress);

	objAttrPtr = ObjectAttributes;
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		PWCHAR binPath = NULL;
		WCHAR fileLinkName[_MAX_PATH*2];
		WCHAR vDirName[_MAX_PATH*2];
		PWCHAR hostName = NULL, fvmName = NULL;
		PFILE_BASIC_INFORMATION fileBasicInfoPtr = NULL;
		ULONG memSize1;

		if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
			goto winSysCall;
		}
		if (!FvmIsLocalFileAccess(fileLinkName)) {
			goto winSysCall;
		}
		if (!FvmFile_GetLongPathName(fileLinkName)) {
			goto winSysCall;
		}

		if (FvmFile_IsFileinFVM(fileLinkName, vmId, &fnPtr)) {
			/*
			 * See comments near the same function inside FvmFile_NtCreateFile
			 * in this code file.
			 */

			objAttrPtr = NULL;
			rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, fnPtr, &objAttrPtr, &memSize);
			if (!NT_SUCCESS(rc)) {
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}
			hostName = fnPtr;
			fvmName = fileLinkName;
		} else {
			fnPtr = NULL;
			hostName = fileLinkName;

			if (!FvmFile_MapPath(hostName, vmId, vDirName)) {
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}
			fvmName = vDirName;
		}

#if DBG_DELETEFILE
		binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILE_POOL_TAG);
		if (binPath == NULL) {
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
		FvmUtil_GetBinaryPathName(binPath);
		DbgPrint("NtDeleteFile : Application Name - %S\n", binPath);
		ExFreePool(binPath);

		DbgPrint("               Arguments - %S\n", hostName);
		DbgPrint("               New file name - %S\n", fvmName);
#endif
		if (objAttrPtr == ObjectAttributes) {
			rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
				    &fvmObjPtr, &memSizeFvm);
			if (!NT_SUCCESS(rc))
				goto ntExit;
		} else {
			fvmObjPtr = ObjectAttributes;
		}

		/*
		 * Try to delete the file under the VM's workspace.
		 */
		rc = (winNtDeleteFileProc)(fvmObjPtr);

		if (NT_SUCCESS(rc)) {
			FvmTable_DeleteLogAdd(hostName, vmId);
			goto ntExit;
		}

		if (rc != STATUS_OBJECT_PATH_NOT_FOUND &&
		    rc != STATUS_OBJECT_NAME_NOT_FOUND)
			goto ntExit;

		/*
		 * Check if the file has already been deleted (in the DeleteLog)
		 * before.
		 */

		if (FvmTable_DeleteLogLookup(hostName, vmId)) {
			rc = STATUS_OBJECT_PATH_NOT_FOUND;
			goto ntExit;
		}

		memSize1 = sizeof(FILE_BASIC_INFORMATION);
		rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(),
			    &fileBasicInfoPtr, 0, &memSize1, MEM_COMMIT,
			    PAGE_READWRITE);

		if (!NT_SUCCESS(rc)) {
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}

		/*
		 * We use NtQueryAttributesFile to find out if the file exists
		 * on the host environment.
		 */
		rc = (winNtQueryAttributesFileProc)(objAttrPtr, fileBasicInfoPtr);

        memSize1 = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr, &memSize1,
		    MEM_RELEASE);

		if (NT_SUCCESS(rc)||(rc != STATUS_OBJECT_PATH_NOT_FOUND &&
		    rc != STATUS_OBJECT_NAME_NOT_FOUND)) {
			/*
			 * We assume that if the file exists on the host directory,
			 * then it can be deleted.
			 */

			FvmTable_DeleteLogAdd(hostName, vmId);
			rc = STATUS_SUCCESS;
		}
		goto ntExit;
	}
winSysCall:
	/*
	 * After detecting that a process is not associated with any VM,
	 * or after detecting an error, program controls are transferred to
	 * here and invokes the system call on the original file in the host
	 * environment.
	 */

	rc = (winNtDeleteFileProc)(objAttrPtr);

ntExit:
	if (fvmObjPtr && fvmObjPtr != ObjectAttributes) {
	   memSizeFvm = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fvmObjPtr,
		    &memSizeFvm, MEM_RELEASE);
	}
	if (objAttrPtr && objAttrPtr != ObjectAttributes) {
	   memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
		    MEM_RELEASE);
	}
	if (fnPtr) {
		ExFreePool(fnPtr);
	}

	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}
#endif

/*
*-----------------------------------------------------------------------------
*
*
*
*
*-----------------------------------------------------------------------------
*/


void FvmFile_GetHostShortPathName(
	PWCHAR lookupName, 
	ULONG FileInformationBufferLength, 
	PFILE_BOTH_DIR_INFORMATION inBuffer)
{

	PUNICODE_STRING pathMaskStr = NULL;
	PWCHAR pathMaskBuf = NULL;
	ULONG memSizeMask = 0;
	UINT len;
	NTSTATUS rc1;
	PWCHAR wFullName = NULL;
	PWCHAR ptr1 = NULL, ptr2 = NULL;
	ULONG memSize;
	PHANDLE hostDirHandle = NULL;
	HANDLE hostDir;
	PIO_STATUS_BLOCK ioStatusPtr = NULL;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	PUNICODE_STRING pathName = NULL;
	PWCHAR vDirUser = NULL;
	FVM_PHandleTableEntry handleEntry = NULL;
	PFILE_BOTH_DIR_INFORMATION FileInformationBuffer = NULL;
	PWCHAR fileNamePtr;
	
	len = wcslen(lookupName);
	
	memSize = sizeof(HANDLE) + sizeof(IO_STATUS_BLOCK) +
		    sizeof(OBJECT_ATTRIBUTES) + sizeof(UNICODE_STRING)
		    + len*2 + 4 + FileInformationBufferLength+512;

	rc1 = FvmVm_AllocateVirtualMemory(NtCurrentProcess(),
					    &(char *)hostDirHandle, 0, &memSize, MEM_COMMIT,
					    PAGE_READWRITE);

	if (NT_SUCCESS(rc1)) {
		(char *)ioStatusPtr = ((char *)hostDirHandle) +
	    sizeof(HANDLE);
		(char *)objAttrPtr = ((char *)ioStatusPtr) +
	    sizeof(IO_STATUS_BLOCK);
		(char *)pathName = ((char *)objAttrPtr) +
	    sizeof(OBJECT_ATTRIBUTES);
		(char *)fileNamePtr = ((char *)pathName)+sizeof(UNICODE_STRING);
		(char *)FileInformationBuffer = ((char *)fileNamePtr)+512;
		(char *)vDirUser = ((char *)FileInformationBuffer) +  FileInformationBufferLength;

		wcsncpy(vDirUser, lookupName, len);
		vDirUser[len] = 0;

		if (vDirUser[len-1] != L'\\')
			wcscat(vDirUser, L"\\");

			RtlInitUnicodeString(pathName, vDirUser);
			InitializeObjectAttributes(objAttrPtr, pathName,
		    OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
	} else {
		CHAR errStr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc1, errStr));
		return;
	}

	rc1 = (winNtOpenFileProc)(
	    hostDirHandle,
	    FILE_READ_DATA|FILE_LIST_DIRECTORY|SYNCHRONIZE,
	    objAttrPtr, ioStatusPtr, FILE_SHARE_READ,
		    FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT );

	if (!NT_SUCCESS(rc1)) {
		//CHAR errStr[64];
		//DbgPrint("-->lap Err2: %S %s\n", lookupName, FvmUtil_ErrorString(rc1, errStr));
		
		goto ntExit;
		
	}
	
	 
	wcsncpy(fileNamePtr, ((PFILE_BOTH_DIR_INFORMATION)inBuffer)->FileName, 
				((PFILE_BOTH_DIR_INFORMATION)inBuffer)->FileNameLength/2);
	fileNamePtr[((PFILE_BOTH_DIR_INFORMATION)inBuffer)->FileNameLength/2] = L'\0';

	
	RtlInitUnicodeString(pathName, fileNamePtr);
	
	rc1 = (winNtQueryDirectoryFileProc)(*hostDirHandle,
									0, 0, 0,
									ioStatusPtr, FileInformationBuffer,
									FileInformationBufferLength, 3,
									TRUE, pathName, FALSE);

	if (!NT_SUCCESS(rc1)) {
		CHAR errStr[64];
		DbgPrint("---->GetHostShortPath: %s --%S-->%S\n", FvmUtil_ErrorString(rc1, errStr), lookupName, fileNamePtr);
		
		goto ntExit;
		
	}


	ZwClose(*hostDirHandle);
	
	/* if a file exits in the host, use the the host short path name*/
	inBuffer->ShortNameLength = FileInformationBuffer->ShortNameLength;
	wcsncpy(inBuffer->ShortName, FileInformationBuffer->ShortName, FileInformationBuffer->ShortNameLength/2);


ntExit:
	memSize = 0;
					
	FvmVm_FreeVirtualMemory(NtCurrentProcess(),
	&(char *)hostDirHandle, &memSize, MEM_RELEASE);
	
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtQueryDirectoryFile --
 *
 *      This function is the FVM-provided NtQueryDirectoryFile system call
 *      function. When the file handle represents a directory under the FVM's
 *      workspace, the directory query result should be a union of the result
 *      on this directory, and the query result on the corresponding directory
 *      on the host environment. In this function, we first query the
 *      directory in the FVM workspace until there are no more matching
 *      file entries. Then we continue to query the directory on the host
 *      environment, and remove file entries that have been queried already
 *      from the result set.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtQueryDirectoryFile(IN HANDLE FileHandle,
		IN HANDLE EventHandle OPTIONAL,
		IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
		IN PVOID IoApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID FileInformationBuffer,
		IN ULONG FileInformationBufferLength,
		IN FILE_INFORMATION_CLASS FileInfoClass,
		IN BOOLEAN ReturnOnlyOneEntry,
		IN PUNICODE_STRING PathMask OPTIONAL,
		IN BOOLEAN RestartQuery) {
	NTSTATUS rc;
	ULONG vmId = INVALID_VMID;
       PWCHAR lookupName= NULL;//[_MAX_PATH*2];

	InterlockedIncrement(&fvm_Calls_In_Progress);

	if (EventHandle != NULL || IoApcRoutine != NULL) {
		goto winSysCall;
	}

	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		int k = 0;
		UINT len;
		NTSTATUS rc1;
		PWCHAR wFullName = NULL;
		PWCHAR ptr1 = NULL, ptr2 = NULL;
		ULONG memSize;
		PHANDLE hostDirPtr = NULL;
		HANDLE hostDir;
		PIO_STATUS_BLOCK ioStatusPtr = NULL;
		POBJECT_ATTRIBUTES objAttrPtr = NULL;
		PUNICODE_STRING pathName = NULL;
		PWCHAR vDirUser = NULL;
		FVM_PHandleTableEntry handleEntry = NULL;

              lookupName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
     		if (lookupName == NULL)
			goto winSysCall;

		wFullName = ExAllocatePoolWithTag(PagedPool, MAXPATHLEN, FVM_FILE_POOL_TAG);
		if (wFullName == NULL)
			goto winSysCall;

		/*
		 * Get the the directory name from the file handle
		 */
		if (FvmUtil_PathFromHandle(FileHandle, NULL, wFullName) == FALSE) {
			ExFreePool(wFullName);
			DbgPrint("QueryDirectory: %x, could not find the name", FileHandle);
			goto winSysCall;
		}
		//DbgPrint("QuryDirectoryFile: %S", wFullName);
		
		if (wcslen(wFullName) == 0) {
			ExFreePool(wFullName);
			goto winSysCall;
		}

#if DBG_QUERYDIRECTORYFILE
		binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILE_POOL_TAG);
		if (binPath == NULL) {
			ExFreePool(wFullName);
			goto winSysCall;
		}
		FvmUtil_GetBinaryPathName(binPath);
		DbgPrint("NtQueryDirectoryFile : Application Name - %S\n", binPath);
		ExFreePool(binPath);
		DbgPrint("               Arguments - %S\n", wFullName);
#endif

		/*
		 * Check if the directory is on the host environment. If yes, we
		 * only need to query the directory and remove entries shown in
		 * the DeleteLog. There is no corresponding directory in the VM's
		 * workspace.
		 */

		len = wcslen(pvms[vmId]->fileRootLink);
		if ((_wcsnicmp(wFullName, pvms[vmId]->fileRootLink, len) != 0) ||
			(wcscmp(wFullName, pvms[vmId]->fileRootLink) == 0)) {
			/*
			 * Convert the directory name from "\Device\HarddiskVolumeX\abc"
			 * to "\??\c:\abc", for example.
			 */

			FvmUtil_GetDriveFromDevice(wFullName, lookupName);
			ExFreePool(wFullName);

			k = 0;
			do {
				rc = (winNtQueryDirectoryFileProc)(FileHandle, EventHandle,
					    IoApcRoutine, IoApcContext, IoStatusBlock,
					    FileInformationBuffer, FileInformationBufferLength,
					    FileInfoClass, ReturnOnlyOneEntry, PathMask,
					    RestartQuery);

				if (NT_SUCCESS(rc)) {
					/*
					 * Remove deleted entries from the returned buffer.
					 */

					rc = FvmFile_ProcessDirEntries(FileInformationBuffer,
						    FileInformationBufferLength, FileInfoClass,
						    lookupName, NULL, vmId);
				} else {
					break;
				}
				RestartQuery = FALSE;
				/*
				 * If all the returned entries are removed(STATUS_NO_SUCH_FILE), we query at most 30
				 * times.
				 */

			} while (ReturnOnlyOneEntry && (rc == STATUS_NO_SUCH_FILE) &&
			    (++k < 30));
			goto ntExit;
		}

		/*
		 * Now we know that the directory is in the VM's workspace.
		 */
			
		//ptr1 = wFullName + len + 1;
		//ptr2 = ptr1 + 1;
		//_snwprintf(lookupName, _MAX_PATH, L"\\??\\%c:%s", *ptr1, ptr2);
			
			

		ptr1 = wFullName + len + 1;
			if (_wcsnicmp(ptr1, L"UNC\\", 4) == 0){
			_snwprintf(lookupName, _MAX_PATH, L"\\??\\%s", ptr1);
		}
		else {			
			ptr2 = ptr1 + 1;
		  	//Get the virtual path of the directory
		 	_snwprintf(lookupName, _MAX_PATH, L"\\??\\%c:%s", *ptr1, ptr2);
		}
		
		//DbgPrint("--1 query directory file			 Arguments - %S %S\n", wFullName, lookupName);
		ExFreePool(wFullName);

		/*
		 * We use a handle table to map the directory in the VM's workspace
		 * to the corresponding directory on the host environment. The table
		 * is empty when we query the directory in the VM's workspace. When
		 * all the entries in the directory have been returned, we may need
		 * to continue query the corresponding directory on the host
		 * environment. The handle table maintains the mapping between handles
		 * of the two directories, and the file entries returned when querying
		 * the VM directory.
		 */

		hostDir = NULL;
		handleEntry = FvmTable_HandleTableLookup(FileHandle, vmId, &hostDir);

		/*
		 * Given a directory handle, if we can find a matched entry in the
		 * handle table, and the hostDir field is not empty, we then know that
		 * we have finished the directory query on the VM's workspace, and
		 * we should use the hostDir handle to continue query the directory
		 * on the host environment.
		 */

		if (handleEntry && hostDir) {
			k = 0;
			do {
				rc = (winNtQueryDirectoryFileProc)(hostDir, EventHandle,
					    IoApcRoutine, IoApcContext, IoStatusBlock,
					    FileInformationBuffer,
					    FileInformationBufferLength, FileInfoClass,
					    ReturnOnlyOneEntry, PathMask, RestartQuery);

				if (NT_SUCCESS (rc)) {
					/*
					 * Remove duplicated or deleted entries. Duplicated entries
					 * mean the file entries that have been returned when
					 * querying the VM's directory.
					 */
					rc = FvmFile_ProcessDirEntries(FileInformationBuffer,
						    FileInformationBufferLength, FileInfoClass,
						    lookupName, FileHandle, vmId);
				} else {
					break;
				}

				RestartQuery = FALSE;
			} while (ReturnOnlyOneEntry && (rc == STATUS_NO_SUCH_FILE)
			    && (++k < 30));
		} else {
			/*
			 * Query the directory under the VM's workspace using the given
			 * directory handle.
			 */
			rc = (winNtQueryDirectoryFileProc)(FileHandle, EventHandle,
				    IoApcRoutine, IoApcContext, IoStatusBlock,
				    FileInformationBuffer, FileInformationBufferLength,
				    FileInfoClass, ReturnOnlyOneEntry, PathMask,
				    RestartQuery);

			if (NT_SUCCESS(rc)) {
				/*
				 * If the directory query is expected to return multiple
				 * entries, we should save the directory query mask and
				 * all the returned file names.
				 */


				/* lclam: disable the short path*/
				if (FileInfoClass == 3){										

					/* if a file is created in a fvm, do not return the short path */
						
					
					if (((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->ShortNameLength !=0){
						((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->ShortNameLength =0;	
						/* if a file exits in both fvm and the host, return the short path of the host file*/
 						FvmFile_GetHostShortPathName(lookupName, FileInformationBufferLength, FileInformationBuffer);
					}
				}


				if (!FvmFile_IsSingleFileLookup(PathMask)) {
					FvmTable_HandleTableAddMask(PathMask, FileHandle, vmId);
					FvmFile_SaveDirEntries(FileInformationBuffer, FileInfoClass,
					    FileHandle, vmId);
				}
			} else if (rc == STATUS_NO_SUCH_FILE || rc ==
			    STATUS_NO_MORE_FILES) {
				/*
				 * If no more entries can be returned, we should open the directory on the
				 * host environment and query that directory.
				 */

				PUNICODE_STRING pathMaskStr = NULL;
				PWCHAR pathMaskBuf = NULL;
				ULONG memSizeMask = 0;

				if(wcsstr(lookupName, L"\\Local Settings\\Temporary Internet Files"))
									goto ntExit;

				len = wcslen(lookupName);
				memSize = sizeof(HANDLE) + sizeof(IO_STATUS_BLOCK) +
						    sizeof(OBJECT_ATTRIBUTES) + sizeof(UNICODE_STRING)
						    + len*2 + 4;

				rc1 = FvmVm_AllocateVirtualMemory(NtCurrentProcess(),
					    &(char *)hostDirPtr, 0, &memSize, MEM_COMMIT,
					    PAGE_READWRITE);

				if (NT_SUCCESS(rc1)) {
					(char *)ioStatusPtr = ((char *)hostDirPtr) +
					    sizeof(HANDLE);
					(char *)objAttrPtr = ((char *)ioStatusPtr) +
					    sizeof(IO_STATUS_BLOCK);
					(char *)pathName = ((char *)objAttrPtr) +
					    sizeof(OBJECT_ATTRIBUTES);
					(char *)vDirUser = ((char *)pathName) +
					    sizeof(UNICODE_STRING);

					wcsncpy(vDirUser, lookupName, len);
					vDirUser[len] = 0;

					if (vDirUser[len-1] != L'\\')
						wcscat(vDirUser, L"\\");

					RtlInitUnicodeString(pathName, vDirUser);
					InitializeObjectAttributes(objAttrPtr, pathName,
					    OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
				} else {
					CHAR errStr[64];
					DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc1, errStr));
					goto ntExit;
				}

				rc1 = (winNtOpenFileProc)(
					    hostDirPtr,
					    FILE_READ_DATA|FILE_LIST_DIRECTORY|SYNCHRONIZE,
					    objAttrPtr, ioStatusPtr, FILE_SHARE_READ,
					    FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT );

				if (!NT_SUCCESS(rc1)) {
					CHAR errStr[64];
					DbgPrint("-->lclam Err2: -->%s\n", FvmUtil_ErrorString(rc1, errStr));
					memSize = 0;
					FvmVm_FreeVirtualMemory(NtCurrentProcess(),
					    &(char *)hostDirPtr, &memSize, MEM_RELEASE);
					goto ntExit;
				}

				hostDir = *hostDirPtr;

				/*
				 * Add the mapping between the two handles into the handle
				 * table.
				 */

				handleEntry = FvmTable_HandleTableAdd(FileHandle, hostDir, vmId);
				memSize = 0;
				FvmVm_FreeVirtualMemory(NtCurrentProcess(), &(char *)hostDirPtr,
				    &memSize, MEM_RELEASE);

				/*
				 * If a path mask exists, we should use it as the path mask
				 * for the first query on the host directory; otherwise, we just
				 * use the current PathMask parameter.
				 */
				if (handleEntry && handleEntry->pathMask) {
					len = wcslen(handleEntry->pathMask);
					memSizeMask = sizeof(UNICODE_STRING) + len*2 + 2;
					rc1 = FvmVm_AllocateVirtualMemory(NtCurrentProcess(),
						    &(char *)pathMaskStr, 0, &memSizeMask, MEM_COMMIT,
						    PAGE_READWRITE);

					if (NT_SUCCESS(rc1)) {
						(char *)pathMaskBuf = ((char *)pathMaskStr) +
						    sizeof(UNICODE_STRING);

						wcsncpy(pathMaskBuf, handleEntry->pathMask, len);
						pathMaskBuf[len] = 0;

						RtlInitUnicodeString(pathMaskStr, pathMaskBuf);
					} else {
						pathMaskStr = NULL;
					}
				}

				/*
				 * Query the corresponding directory on the host environment.
				 */
				k = 0;
				do {
					if (pathMaskStr) {
						rc = (winNtQueryDirectoryFileProc)(hostDir,
							    EventHandle, IoApcRoutine, IoApcContext,
							    IoStatusBlock, FileInformationBuffer,
							    FileInformationBufferLength, FileInfoClass,
							    ReturnOnlyOneEntry, pathMaskStr, RestartQuery);
					} else {
						rc = (winNtQueryDirectoryFileProc)(
							    hostDir, EventHandle, IoApcRoutine,
							    IoApcContext, IoStatusBlock,
							    FileInformationBuffer,
							    FileInformationBufferLength, FileInfoClass,
							    ReturnOnlyOneEntry, PathMask, RestartQuery);
					}

					if (NT_SUCCESS (rc)) {
						/*
						 * Remove duplicated or deleted entries
						 */
						rc = FvmFile_ProcessDirEntries(FileInformationBuffer,
							    FileInformationBufferLength, FileInfoClass,
							    lookupName, FileHandle, vmId);
					} else {
						break;
					}

					RestartQuery = FALSE;
				} while (ReturnOnlyOneEntry && (rc == STATUS_NO_SUCH_FILE) &&
					    (++k < 30));

				if (pathMaskStr) {
				   memSizeMask = 0;
					FvmVm_FreeVirtualMemory(NtCurrentProcess(),
					    &(char *)pathMaskStr, &memSizeMask,
					    MEM_RELEASE);
				}
			}
		}
		goto ntExit;
	}

winSysCall:
	rc = (winNtQueryDirectoryFileProc)(
		    FileHandle, EventHandle,
			IoApcRoutine, IoApcContext,
		    IoStatusBlock, FileInformationBuffer,
		    FileInformationBufferLength, FileInfoClass,
		    ReturnOnlyOneEntry, PathMask, RestartQuery);
ntExit:
       if(lookupName){
           ExFreeToPagedLookasideList( &FileFullPathLookaside, lookupName );
        }
	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtQueryInformationFile --
 *
 *      This function is the FVM-provided NtQueryInformationFile system call
 *      function. The system call can be used to obtain the file path from
 *      a given file handle. Since we may have renamed the file path at the
 *      file opening time, we should check the returned file path and convert
 *      it back to the virtual file path in the VM's namespace.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtQueryInformationFile(IN HANDLE FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID FileInformationBuffer,
		IN ULONG FileInformationBufferLength,
		IN FILE_INFORMATION_CLASS FileInfoClass) {
	NTSTATUS rc;
	ULONG vmId = INVALID_VMID;
       PWCHAR fvmDir= NULL;//[_MAX_PATH*2];

	InterlockedIncrement(&fvm_Calls_In_Progress);

	rc = (winNtQueryInformationFileProc)(FileHandle, IoStatusBlock,
		    FileInformationBuffer, FileInformationBufferLength, FileInfoClass);

	if (!NT_SUCCESS(rc) || FileInfoClass != FileNameInformation) {
		goto ntExit;
	}

	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		PWCHAR binPath = NULL;
		PWCHAR wFullName = NULL, ptr;	
		PFILE_NAME_INFORMATION fnInfoPtr;
		UINT len;

              fvmDir = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if(fvmDir == NULL){
                     rc = STATUS_ACCESS_DENIED;
                     goto ntExit;
              }
              
		wFullName = ExAllocatePoolWithTag(PagedPool, _MAX_PATH*2, FVM_FILE_POOL_TAG);
		if (wFullName == NULL) {
                     rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
		wFullName[0] = 0;

		/*
		 * We get the returned file name by parsing the returned
		 * buffer.
		 */

		fnInfoPtr = (PFILE_NAME_INFORMATION)FileInformationBuffer;
		len = fnInfoPtr->FileNameLength >> 1;

		if (fnInfoPtr && fnInfoPtr->FileName) {
			wcsncat(wFullName, fnInfoPtr->FileName, len);
		}

#if DBG_QUERYINFORMATIONFILE
		binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILE_POOL_TAG);
		if (binPath == NULL) {
			ExFreePool(wFullName);
			goto ntExit;
		}
		FvmUtil_GetBinaryPathName(binPath);
		DbgPrint("NtQueryInformationFile : Application Name - %S\n", binPath);
		ExFreePool(binPath);
		DbgPrint("               Arguments - %S\n", wFullName);
#endif
		//DbgPrint("NtQueryInformationFile :  - %S\n", wFullName);

		/*
		 * We assume the file name is returned in full path(without drive name,
		 * refer to DDK documentation), e.g. "\abc\xyz.txt"
		 */

		/*
		 * Get the directory path of the VM's workspace, e.g. "\fvm\fvmID"
		 */

		swprintf(fvmDir, L"%s\\%s", pvms[vmId]->fileRoot + 2,
		    pvms[vmId]->idStr);

		/*
		 * If the name represents a file inside the VM's workspace, we should
		 * rename it back to a "virtual name" to make the application see the
		 * desired file name.
		 */

		len = wcslen(fvmDir);
		if (_wcsnicmp(wFullName, fvmDir, len) != 0) {
			ExFreePool(wFullName);
			goto ntExit;
		}

		ptr = wFullName + len + 2;
		if (*ptr == L'\\') {
			wcscpy(wFullName, ptr);
		} else {
			wcscpy(wFullName, L"\\");
		}

		len = wcslen(wFullName);
		wcsncpy(fnInfoPtr->FileName, wFullName, len);
		fnInfoPtr->FileNameLength = len << 1;

		ExFreePool(wFullName);
	}
ntExit:
       if (fvmDir) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, fvmDir );
	}  
	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtSetInformationFile --
 *
 *      This function is the FVM-provided NtSetInformationFile system call
 *      function. The system call can be used to rename or delete a file from
 *      a given file handle. In these two cases, the path of the file to be
 *      deleted is saved into the DeleteLog. In addition, the target file of
 *      the renaming request is created in the VM's workspace.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtSetInformationFile(IN HANDLE FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN PVOID FileInformationBuffer,
		IN ULONG FileInformationBufferLength,
		IN FILE_INFORMATION_CLASS FileInfoClass) {
	NTSTATUS rc = STATUS_ACCESS_DENIED;
    PWCHAR lookupName = NULL;
    PWCHAR newFileName = NULL;
    PWCHAR vDirName = NULL;
    PWCHAR wFullName = NULL;
	KPROCESSOR_MODE mode;
			

	InterlockedIncrement(&fvm_Calls_In_Progress);

	/*
	 * We only need to process the system call when the FileInfoClass
	 * is FileRenameInformation or FileDispositionInformation.
	 */

	if (FileInfoClass == FileRenameInformation ||
	    FileInfoClass == FileDispositionInformation) {
		ULONG vmId = INVALID_VMID;

		vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());


		mode = ExGetPreviousMode();

		if (vmId != INVALID_VMID) {
			PWCHAR ptr1 = NULL, ptr2 = NULL;
			UINT len;
			PFILE_RENAME_INFORMATION fileRenInfoPtr = NULL, fileRenamePtr = NULL;
			ULONG memSize;
                      
                      wFullName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
                      if (wFullName == NULL) {
                            DbgPrint("FvmFile_NtSetInformationFile: ExAllocateFromPagedLookasideList fail\n");  
        			rc = STATUS_ACCESS_DENIED;
        			goto ntExit;
        		}

/*			wFullName = ExAllocatePoolWithTag(PagedPool, MAXPATHLEN, FVM_FILE_POOL_TAG);
			if (wFullName == NULL) {
				goto ntExit;
			}*/

			/*
			 * Get the file name from the file handle
			 */

			if (!FvmUtil_PathFromHandle(FileHandle, NULL, wFullName)) {
//				ExFreePool(wFullName);
				goto ntExit;
			}

			if (wcslen(wFullName) == 0) {
//				ExFreePool(wFullName);
				goto ntExit;
			}

			//DbgPrint("---------------> %S\n", wFullName);
			
			/*
			 * Check if the file is under the VM's workspace directory
			 */
                     newFileName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
                      if (newFileName == NULL) {
                            DbgPrint("FvmFile_NtSetInformationFile: ExAllocateFromPagedLookasideList fail\n");  
        			rc = STATUS_ACCESS_DENIED;
        			goto ntExit;
        		}
                      
			wcscpy(newFileName, pvms[vmId]->fileRootLink);
			len = wcslen(newFileName);
			if (_wcsnicmp(wFullName, newFileName, len) != 0) {
//				ExFreePool(wFullName);
				//goto ntExit;
				goto winSysCall; //lclam need workd here
			}

			ptr1 = wFullName + len + 1;
			ptr2 = ptr1 + 1;

			/*
			 * Get the virtual path of the file.
			 */
                    lookupName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
                      if (lookupName == NULL) {
                            DbgPrint("FvmFile_NtSetInformationFile: ExAllocateFromPagedLookasideList fail\n");            
        			rc = STATUS_ACCESS_DENIED;
        			goto ntExit;
        		}
                      
			_snwprintf(lookupName, _MAX_PATH, L"\\??\\%c:%s", *ptr1, ptr2);
//			ExFreePool(wFullName);

#if DBG_SETINFORMATIONFILE
			binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILE_POOL_TAG);
			if (binPath == NULL)
				goto winSysCall;
			FvmUtil_GetBinaryPathName(binPath);
			DbgPrint("NtSetInformationFile : Application Name - %S\n", binPath);
			ExFreePool(binPath);

			DbgPrint("               Arguments - %S\n", lookupName);
#endif

			if (FileInfoClass == FileRenameInformation) {

				fileRenInfoPtr = FileInformationBuffer;

				/*
				 * We assume that the target file of the renaming is not
				 * represented by a partial name.
				 */

			DbgPrint("+++++++++++> %S\n", fileRenInfoPtr->FileName);
			if (fileRenInfoPtr->RootDirectory)
				goto winSysCall;

			newFileName[0] = 0;
			wcsncat(newFileName, fileRenInfoPtr->FileName,
			    fileRenInfoPtr->FileNameLength >> 1);


			DbgPrint("???????????? origina: %S --->%S\n", wFullName, newFileName);

			/*
			 * The target file name is also a virtual path, so we map it to
			 * the physical path.
			 */
                    vDirName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
                      if (vDirName == NULL) {
                            DbgPrint("FvmFile_NtSetInformationFile: ExAllocateFromPagedLookasideList fail\n");  
        			rc = STATUS_ACCESS_DENIED;
        			goto ntExit;
        		}

			if (!FvmFile_MapPath(newFileName, vmId, vDirName)) {
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}

			memSize = sizeof(FILE_RENAME_INFORMATION) + wcslen(vDirName)*2 + 2;
			rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(), &fileRenamePtr, 0,
				    &memSize, MEM_COMMIT, PAGE_READWRITE);

			if (NT_SUCCESS(rc)) {
				fileRenamePtr->ReplaceIfExists =
				    fileRenInfoPtr->ReplaceIfExists;
				fileRenamePtr->RootDirectory = NULL;
				fileRenamePtr->FileNameLength = wcslen(vDirName)*2;
				wcsncpy(fileRenamePtr->FileName, vDirName, wcslen(vDirName));
            } else {
				CHAR errStr[64];
				DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errStr));
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}

			FvmUtil_CreateFileDir(newFileName, vDirName, vmId);

			/*
			 * We rename the file to the target file under the VM's workspace.
			 */

			DbgPrint("origina: %S --->%S\n", wFullName, newFileName);
			rc = (winNtSetInformationFileProc)(FileHandle, IoStatusBlock,
				    fileRenamePtr, memSize, FileInfoClass);
			if(!DpWriteAllowed(newFileName, vmId)){
					rc = STATUS_ACCESS_DENIED;
				
			}

         memSize = 0;
			FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileRenamePtr,
			    &memSize, MEM_RELEASE);

			
			if (NT_SUCCESS(rc)) {
				FvmTable_DeleteLogRemove(newFileName, vmId);
#ifdef USE_FS_MAP
				FvmTable_FVMFileListAddFullPath(newFileName+4, vmId);
#endif

				
			}
#ifdef NTSETINFORMATIONFILE

			//FvmUtil_GetOriginalFileName(
			if (mode != KernelMode) {
				PWCHAR binname;
				char *ptr;
				IO_STATUS_BLOCK Iosb;
				
				binname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
				if(binname){
					FvmUtil_GetBinaryPathName(binname);									
					if(pvms[vmId]->logHandle && !wcsstr(binname, L"fvmshell.exe")){	
						ticks tm = getticks();
						FvmUtil_GetOriginalFileName(wFullName, PATHSIZE, vmId);
						ptr = (char *)vDirName;
						RtlStringCbPrintfA(ptr, PATHSIZE, "%I64u, NtRenameFile, %u, %S, %S\r\n", tm.QuadPart, 
							(ULONG)PsGetCurrentProcessId(), wFullName, newFileName);
						ZwWriteFile(pvms[vmId]->logHandle, NULL, NULL, NULL, &Iosb, (void*)ptr, strlen(ptr)*sizeof(char), NULL, NULL);																				
					}

					ExFreePool(binname);
				}
			}	
#endif
			
		} else {
			/*
			 * We delete the file under the VM's workspace.
			 */

			rc = (winNtSetInformationFileProc)(FileHandle, IoStatusBlock,
				    FileInformationBuffer, FileInformationBufferLength,
				    FileInfoClass);
#ifdef NTSETINFORMATIONFILE
			if (mode != KernelMode) {
				PWCHAR binname;
				char *ptr;
				IO_STATUS_BLOCK Iosb;
				
				binname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
				if(binname){
					FvmUtil_GetBinaryPathName(binname);									
					if(pvms[vmId]->logHandle && !wcsstr(binname, L"fvmshell.exe")){	
						ticks tm = getticks();
						FvmUtil_GetOriginalFileName(wFullName, PATHSIZE, vmId);
						ptr = (char *)binname;
						RtlStringCbPrintfA(ptr, PATHSIZE, "%I64u, NtDeleteFile, %u, %S, %u\r\n", 
							tm.QuadPart, (ULONG)PsGetCurrentProcessId(), wFullName, rc);
						ZwWriteFile(pvms[vmId]->logHandle, NULL, NULL, NULL, &Iosb, (void*)ptr, strlen(ptr)*sizeof(char), NULL, NULL);																				
					}

					ExFreePool(binname);
				}
			}	
#endif
		}

         if (NT_SUCCESS(rc)) {
            /*
             * We update the DeleteLog after a file is deleted
             * or renamed.
             */

            //DbgPrint("File Deleted or Renamed:%S\n", lookupName);
            FvmTable_DeleteLogAdd(lookupName, vmId);
#ifdef USE_FS_MAP
			if(FileInfoClass == FileDispositionInformation){
				PFILE_DISPOSITION_INFORMATION fd = (PFILE_DISPOSITION_INFORMATION)FileInformationBuffer;
			//	DbgPrint("fdisposition: %d\n", fd->DeleteFile);
			}
			else
	            FvmTable_FVMFileListDelete(lookupName+4, vmId);
#endif
         }
         goto ntExit;
      }
   }
winSysCall:
	rc = (winNtSetInformationFileProc)(FileHandle, IoStatusBlock,
		    FileInformationBuffer, FileInformationBufferLength,
		    FileInfoClass);
ntExit:
   
       if (wFullName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, wFullName );
	}   
       if (newFileName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, newFileName );
	}
       if (lookupName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, lookupName );
	}             
       if (vDirName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vDirName );
	}
	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;

}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtQueryVolumeInformationFile --
 *
 *      This function is the FVM-provided NtQueryVolumeInformationFile system
 *      call function. The system call is used to query the volume information
 *      from a given file handle. If the file handle represents a file in
 *      FVM's workspace directory, which is located on a different volume from
 *      the original file on the host environment, we must query the correct
 *      volume using a file handle representing the corresponding file on the
 *      host environment.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtQueryVolumeInformationFile(IN HANDLE FileHandle,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID VolumeInformation,
		IN ULONG VolumeInformationLength,
		IN FS_INFORMATION_CLASS VolumeInformationClass) {
	NTSTATUS rc;
	ULONG vmId = INVALID_VMID;
       PWCHAR lookupName= NULL;//[_MAX_PATH*2];

	InterlockedIncrement(&fvm_Calls_In_Progress);

	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		PWCHAR binPath;
		PWCHAR wFullName;
		PWCHAR ptr1, ptr2;
		UINT len;
		ULONG memSize;
		PHANDLE hostDirPtr = NULL;
		HANDLE hostDir;
		PIO_STATUS_BLOCK ioStatusPtr = NULL;
		PUNICODE_STRING pathName = NULL;
		PWCHAR vDirUser = NULL;
		POBJECT_ATTRIBUTES objAttrPtr = NULL;

              lookupName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (lookupName == NULL) {
			goto winSysCall;
		}

		wFullName = ExAllocatePoolWithTag(PagedPool, MAXPATHLEN, FVM_FILE_POOL_TAG);
		if (wFullName == NULL) {
			goto winSysCall;
		}

		/*
		 * We get the file name from the file handle
		 */

		if (FvmUtil_PathFromHandle(FileHandle, NULL, wFullName) == FALSE) {
			ExFreePool(wFullName);
			goto winSysCall;
		}

		if (wcslen(wFullName) == 0) {
			ExFreePool(wFullName);
			goto winSysCall;
		}

#if DBG_QUERYVOLUMEINFORMATIONFILE
		binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILE_POOL_TAG);
		if (binPath == NULL) {
			ExFreePool(wFullName);
			goto winSysCall;
		}
		FvmUtil_GetBinaryPathName(binPath);
		DbgPrint("NtQueryVolumeInformationFile : Application Name - %S\n",
		    binPath);
		ExFreePool(binPath);

		DbgPrint("              Arguments - %S\n", wFullName);
#endif

		/*
		 * The returned file name looks like "\Device\HarddiskVolumeX\abc\xyz.txt".
		 * The "fileRootLink" field stores the name of the VM's root directory in
		 * similar format. So we can compare the returned name with the
		 * "fileRootLink" to know if the file is located in the VM.
		 */

		len = wcslen(pvms[vmId]->fileRootLink);
		if (_wcsnicmp(wFullName, pvms[vmId]->fileRootLink, len) != 0) {
			ExFreePool(wFullName);
			goto winSysCall;
		}

		ptr1 = wFullName + len + 1;
		ptr2 = ptr1 + 1;

		/*
		 * Get the virtual path of the file
		 */

		//_snwprintf(lookupName, _MAX_PATH, L"\\??\\%c:%s", *ptr1, ptr2);
		_snwprintf(lookupName, _MAX_PATH, L"\\??\\%c:", *ptr1);

		//DbgPrint(" 1 ----------->Name: %S :::: %S\n", lookupName, wFullName);
		ExFreePool(wFullName);

		/*
		 * If the volume name in the virtual path is different from the volume
		 * name of the VM's root directory, we should query the volume name
		 * in the virtual path instead.
		 */

		if (_wcsnicmp(pvms[vmId]->fileRoot, lookupName+4, 2) == 0) {
			goto winSysCall;
		}

		len = wcslen(lookupName);
		memSize = sizeof(HANDLE) + sizeof(IO_STATUS_BLOCK) +
				    sizeof(OBJECT_ATTRIBUTES) + sizeof(UNICODE_STRING) +
				    len*2 + 4;

		rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(),
			    &(char *)hostDirPtr, 0, &memSize, MEM_COMMIT,
			    PAGE_READWRITE);

		if (NT_SUCCESS(rc)) {
			(char *)ioStatusPtr = ((char *)hostDirPtr) + sizeof(HANDLE);
			(char *)objAttrPtr = ((char *)ioStatusPtr) +
			    sizeof(IO_STATUS_BLOCK);
			(char *)pathName = ((char *)objAttrPtr) +
			    sizeof(OBJECT_ATTRIBUTES);
			(char *)vDirUser = ((char *)pathName) +
			    sizeof(UNICODE_STRING);

			wcsncpy(vDirUser, lookupName, len);
			vDirUser[len] = 0;

			if (vDirUser[len-1] == L':')
				wcscat(vDirUser, L"\\");

			RtlInitUnicodeString(pathName, vDirUser);
			InitializeObjectAttributes(objAttrPtr, pathName,
			    OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);
		} else {
			CHAR errStr[64];
			DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errStr));
			goto winSysCall;
		}

		/*
		 * Open the file on the host environment using the virtual path.
		 */

		rc = (winNtOpenFileProc)(hostDirPtr, FILE_READ_DATA|SYNCHRONIZE,
			    objAttrPtr, ioStatusPtr, FILE_SHARE_READ,
			    FILE_SYNCHRONOUS_IO_NONALERT);

		if (!NT_SUCCESS(rc)) {
			CHAR errStr[64];
			//DbgPrint("Err1:%s %S\n", FvmUtil_ErrorString(rc, errStr),wFullName);
			DbgPrint("NtQueryVolumInformation, Err1: %x %S\n", rc, vDirUser);
			memSize = 0;
			FvmVm_FreeVirtualMemory(NtCurrentProcess(), &(char *)hostDirPtr,
			    &memSize, MEM_RELEASE);
			goto winSysCall;
		}

		hostDir = *hostDirPtr;
		memSize = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &(char *)hostDirPtr,
		    &memSize, MEM_RELEASE);

		/*
		 * We use the returned file handle to obtain the correct volume
		 * information. Then we close the file handle.
		 */

		rc = (winNtQueryVolumeInformationFileProc)(hostDir, IoStatusBlock,
			    VolumeInformation, VolumeInformationLength,
			    VolumeInformationClass);

		ZwClose(hostDir);
		goto ntExit;
	}
winSysCall:
	rc = (winNtQueryVolumeInformationFileProc)(
		    FileHandle, IoStatusBlock, VolumeInformation,
		    VolumeInformationLength, VolumeInformationClass);
ntExit:
       if (lookupName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, lookupName );
	}  
	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtCreateNamedPipeFile --
 *
 *      This function is the FVM-provided NtCreateNamedPipeFile system call
 *      function. It checks the name of the pipe to be created, and maps it
 *      from the VM's namespace to the host namespace before invoking the
 *      original NtCreateNamedPipeFile system call function.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtCreateNamedPipeFile(OUT PHANDLE FileHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN ULONG ShareAccess,
		IN ULONG CreateDisposition,
		IN ULONG CreateOptions,
		IN ULONG NamedPipeType,
		IN ULONG ReadMode,
		IN ULONG CompletionMode,
		IN ULONG MaxInstances,
		IN ULONG InBufferSize,
		IN ULONG OutBufferSize,
		IN PLARGE_INTEGER DefaultTimeOut) {

	NTSTATUS rc;
//	WCHAR fileLinkName[_MAX_PATH*2];
//	WCHAR vDirName[_MAX_PATH*2];
       PWCHAR fileLinkName = NULL;
       PWCHAR vDirName = NULL;
	ULONG memSize = _MAX_PATH*2;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	ULONG vmId = 0;

      InterlockedIncrement(&fvm_Calls_In_Progress);
    
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if(vmId == INVALID_VMID) {
		goto winSysCall;
	}
    
       fileLinkName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
      if (fileLinkName == NULL) {
            DbgPrint("NtCreateNamedpipe: ExAllocateFromPagedLookasideList fail\n");
	    rc = STATUS_ACCESS_DENIED;
	    goto ntExit;
      }
      
	if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
		goto winSysCall;
	}
	//if(wcsstr(fileLinkName, L"OSL_PIPE"))
	
		//		goto winSysCall;
       vDirName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
      if (vDirName == NULL) {
           DbgPrint("NtCreateNamedpipe: ExAllocateFromPagedLookasideList fail\n");
	    rc = STATUS_ACCESS_DENIED;
	    goto ntExit;
      } 
	if (!FvmFile_MapPipeMailSlotPath(fileLinkName, vmId, vDirName)) {
		goto winSysCall;
	}
	//DbgPrint("NtCreateNamedpipe: %S %S\n", fileLinkName, vDirName);

	rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName, &objAttrPtr,
		    &memSize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errStr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errStr));*/
		DbgPrint("ErrMem:%x\n", rc);
		goto winSysCall;
	}

	rc = (winNtCreateNamedPipeFileProc)(FileHandle,
		    DesiredAccess, objAttrPtr, IoStatusBlock,
		    ShareAccess, CreateDisposition, CreateOptions,
		    NamedPipeType, ReadMode, CompletionMode,
		    MaxInstances, InBufferSize, OutBufferSize,
		    DefaultTimeOut);

    memSize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
	    MEM_RELEASE);
	goto ntExit;

winSysCall:
	/*
	 * After detecting that a process is not associated with any VM,
	 * or after detecting an error, program controls are transferred
	 * here and invokes the system call on the original file in the host
	 * environment.
	 */

	rc = (winNtCreateNamedPipeFileProc)(FileHandle, DesiredAccess,
		    ObjectAttributes, IoStatusBlock, ShareAccess,
		    CreateDisposition, CreateOptions, NamedPipeType,
		    ReadMode, CompletionMode, MaxInstances,
		    InBufferSize, OutBufferSize, DefaultTimeOut);

ntExit:
	
       if (fileLinkName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, fileLinkName );
	}     
       if (vDirName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vDirName );
	}         
       InterlockedDecrement(&fvm_Calls_In_Progress);
	   /*
	if(vmId != INVALID_VMID) {
		DbgPrint("create named pipe code: %d\n", rc);
	}*/
	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtCreateMailslotFile --
 *
 *      This function is the FVM-provided NtCreateMailslotFile system call
 *      function. It checks the Mailslot name and maps it from the VM's
 *      namespace to the host namespace before invoking the original
 *      NtCreateMailslotFile system call function.
 *
 * Results:
 *      Return STATUS_SUCCESS on success or NTSTATUS error code on failure.
 *
 * Side effects:
 *      None.
 *
 *-----------------------------------------------------------------------------
 */

NTSTATUS
FvmFile_NtCreateMailslotFile(OUT PHANDLE FileHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN ULONG CreateOptions,
		IN ULONG InBufferSize,
		IN ULONG MaxMessageSize,
		IN PLARGE_INTEGER ReadTimeout OPTIONAL) {
	NTSTATUS rc;
	ULONG memSize = _MAX_PATH*2;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	ULONG vmId = 0;
       PWCHAR fileLinkName = NULL;
       PWCHAR vDirName = NULL; 

	InterlockedIncrement(&fvm_Calls_In_Progress);

	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());
	if (vmId == INVALID_VMID) {
		goto winSysCall;
	}

       fileLinkName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (fileLinkName == NULL) {
              DbgPrint("FvmFile_NtCreateMailslotFile: ExAllocateFromPagedLookasideList fail\n");  
	       rc = STATUS_ACCESS_DENIED;
		goto ntExit;
       }

	if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
		goto winSysCall;
	}

       vDirName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vDirName == NULL) {
              DbgPrint("FvmFile_NtCreateMailslotFile: ExAllocateFromPagedLookasideList fail\n"); 
		rc = STATUS_ACCESS_DENIED;
		goto ntExit;
	}
              
	if (!FvmFile_MapPipeMailSlotPath(fileLinkName, vmId, vDirName)) {
		goto winSysCall;
	}

#if DBG_CREATEMAILSLOTFILE
	binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILE_POOL_TAG);
	if (binPath == NULL) {
		goto winSysCall;
	}
	FvmUtil_GetBinaryPathName(binPath);
	DbgPrint("NtCreateMailslotFile : Application Name - %S\n", binPath);
	ExFreePool(binPath);

	DbgPrint("               Arguments - %S\n", fileLinkName);

	accessStr = ExAllocatePoolWithTag(PagedPool, _MAX_PATH*2, FVM_FILE_POOL_TAG);
	if (accessStr) {
		DbgPrint("               Access - %s\n", AccessString(DesiredAccess,
		    accessStr));
		ExFreePool(accessStr);
	}

	DbgPrint("               New file name - %S\n", vDirName);
#endif

	rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName, &objAttrPtr, &memSize);
	if (!NT_SUCCESS(rc)) {
		CHAR errStr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errStr));
		goto winSysCall;
	}

	rc = (winNtCreateMailslotFileProc)(FileHandle, DesiredAccess, objAttrPtr,
		    IoStatusBlock, CreateOptions, InBufferSize, MaxMessageSize,
		    ReadTimeout);

    memSize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize, MEM_RELEASE);
	goto ntExit;

winSysCall:
	/*
	 * After detecting that a process is not associated with any VM,
	 * or after detecting an error, program controls are transferred to
	 * here and invokes the system call on the original file in the host
	 * environment.
	 */

	rc = (winNtCreateMailslotFileProc)(FileHandle, DesiredAccess,
		    ObjectAttributes, IoStatusBlock, CreateOptions,
		    InBufferSize, MaxMessageSize, ReadTimeout);
ntExit:
       if (fileLinkName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, fileLinkName );
	}     
       if (vDirName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vDirName );
	}    
	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}

typedef struct _FILE_PIPE_WAIT_FOR_BUFFER {
    LARGE_INTEGER   Timeout;
    ULONG           NameLength;
    BOOLEAN         TimeoutSpecified;
    WCHAR           Name[1];
} FILE_PIPE_WAIT_FOR_BUFFER, *PFILE_PIPE_WAIT_FOR_BUFFER;


NTSTATUS FvmFile_NtFsControlFile(
    IN HANDLE  FileHandle,
    IN HANDLE  Event OPTIONAL,
    IN PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
    IN PVOID  ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN ULONG  FsControlCode,
    IN PVOID  InputBuffer OPTIONAL,
    IN ULONG  InputBufferLength,
    OUT PVOID  OutputBuffer OPTIONAL,
    IN ULONG  OutputBufferLength
    )
{
	ULONG vmId = 0;
	NTSTATUS rc;
	HANDLE	procHandle;
	int	size;
	PFILE_PIPE_WAIT_FOR_BUFFER pipeBuffer;
	PFILE_PIPE_WAIT_FOR_BUFFER newPipeBuffer = NULL;
	
	WCHAR fvmName[10];
	ULONG *newBufferSize;
	
	
	InterlockedIncrement(&fvm_Calls_In_Progress);
	
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());
	if (vmId == INVALID_VMID) {
		goto winSysCall;
	}

	if(FsControlCode != 0x110018)// FSCTL_PIPE_WAIT
		goto winSysCall;

	pipeBuffer = (PFILE_PIPE_WAIT_FOR_BUFFER) InputBuffer;

	DbgPrint("waitbuffersize: %d inputbuffersize: %d, name length: %d\n", sizeof(FILE_PIPE_WAIT_FOR_BUFFER), InputBufferLength, pipeBuffer->NameLength);
	/*
	wcsncpy(msg, pipeBuffer->Name, pipeBuffer->NameLength);
	msg[pipeBuffer->NameLength] = L'\0';
	DbgPrint("FvmFile_NtFsControlFile %S", msg);
*/
	/* Allocate virtual memory from the process user space
	 */

	swprintf(fvmName, L"FVM%u\\", vmId);
	size = InputBufferLength+wcslen(fvmName)*sizeof(WCHAR)+sizeof(ULONG);
	procHandle = NtCurrentProcess();

	
	rc = FvmVm_AllocateVirtualMemory(procHandle, &newPipeBuffer, 0, &size,
		    MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (rc != STATUS_SUCCESS) {
		DbgPrint("--memory allocation problem(%d,NtOpenKey)\n",(ULONG)PsGetCurrentProcessId());
		goto NtExit;
	}

	(char *)newBufferSize = (char*)newPipeBuffer+size-sizeof(ULONG);

	memcpy(newPipeBuffer, InputBuffer, sizeof(FILE_PIPE_WAIT_FOR_BUFFER)-sizeof(WCHAR));
	newPipeBuffer->NameLength = pipeBuffer->NameLength+wcslen(fvmName)*sizeof(WCHAR);
	newPipeBuffer->Name[0] = L'\0';
	wcscat(newPipeBuffer->Name, fvmName);
	wcsncat(newPipeBuffer->Name, pipeBuffer->Name, pipeBuffer->NameLength/sizeof(WCHAR));
	*newBufferSize = size-sizeof(ULONG);
	DbgPrint("new waitbuffersize: %d inputbuffersize: %d, name length: %d fvmsize: %d\n", sizeof(FILE_PIPE_WAIT_FOR_BUFFER), 
				*newBufferSize, newPipeBuffer->NameLength,wcslen(fvmName)*sizeof(WCHAR) );

	rc = winNtFsControlFileProc(FileHandle, Event, ApcRoutine, ApcContext, 
								IoStatusBlock, FsControlCode, newPipeBuffer, *newBufferSize, OutputBuffer, OutputBufferLength);

	newPipeBuffer->Name[newPipeBuffer->NameLength >> 1] = L'\0';
	DbgPrint("NtFsControlFile: %x %S", rc, newPipeBuffer->Name);
	size = 0;
	FvmVm_FreeVirtualMemory(procHandle, &newPipeBuffer, &size,
			    MEM_RELEASE);
	goto NtExit;
	
winSysCall:
	rc = winNtFsControlFileProc(FileHandle, Event, ApcRoutine, ApcContext, 
								IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
NtExit:
		
	
	InterlockedDecrement(&fvm_Calls_In_Progress);
	

		
	return rc;

}

