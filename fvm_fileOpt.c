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
 * fvm_fileOpt.c --
 *
 *	This code file implements a few file-related system call functions
 *  in the FVM layer. Different from the same set of functions
 *  implemented in fvm_file.c, the virtual-to-physical name mapping is
 *  determined by looking up a binary tree that stores all the name of
 *  files copied to a VM's workspace. As a result, no system call is
 *  made to test if the VM already has a private copy of a given file.
 *  This optimization can reduce the system call interception overhead
 *  in virtual-to-physical mapping.
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include "fvm_util.h"
#include "fvm_table.h"
#include "hooksys.h"
#include "fvm_vm.h"
#include "fvm_syscalls.h"
#include "fvm_fileInt.h"
#include "fvm_file.h"

#define FVM_FILEOPT_POOL_TAG '3GAT'


NTSTATUS DpGetAllowedUserFolders(UNICODE_STRING *localSettings, UNICODE_STRING *appData, UNICODE_STRING *cookies)
{
   NTSTATUS Status;

   RTL_QUERY_REGISTRY_TABLE ParamTable[4];
  
  	
   RtlZeroMemory(ParamTable, sizeof(RTL_QUERY_REGISTRY_TABLE) * 3);

   ParamTable[0].QueryRoutine = NULL;
   ParamTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
   ParamTable[0].Name = L"Local Settings";
   ParamTable[0].EntryContext = localSettings;
   ParamTable[0].DefaultType = REG_NONE;
 //  ParamTable[0].DefaultData = &L"\0";
 //  ParamTable[0].DefaultLength = 2;

  

   ParamTable[1].QueryRoutine = NULL;
   ParamTable[1].Flags = RTL_QUERY_REGISTRY_DIRECT;
   ParamTable[1].Name = L"AppData";
   ParamTable[1].EntryContext =appData;
   ParamTable[1].DefaultType = REG_NONE;
  // ParamTable[1].DefaultData = &L"\0";
  // ParamTable[1].DefaultLength = 2;

   ParamTable[2].QueryRoutine = NULL;
   ParamTable[2].Flags = RTL_QUERY_REGISTRY_DIRECT;
   ParamTable[2].Name = L"Cookies";
   ParamTable[2].EntryContext = cookies;
   ParamTable[2].DefaultType = REG_NONE;
  // ParamTable[2].DefaultData = &L"\0";
  // ParamTable[2].DefaultLength = 2;


   ParamTable[3].QueryRoutine = NULL;
   ParamTable[3].Name = NULL;

   Status=RtlQueryRegistryValues(RTL_REGISTRY_USER,
                                 L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                                 ParamTable,
                                 NULL,
                                 NULL);
   
/*
	if(Status == STATUS_SUCCESS){
		//localSettings->Buffer[localSettings->Length] = L'\0';
		//appData->Buffer[appData->Length] = L'\0';
		//cookies->Buffer[cookies->Length] = L'\0';
	  	DbgPrint("local: %S --- app: %S  --- coo: %S\n", localSettings->Buffer, appData->Buffer, cookies->Buffer);
	  	DbgPrint("---%d %d %d\n", localSettings->Length, appData->Length, cookies->Length);
		}
   	else
		DbgPrint("--------------failed\n");
	
	*/
   return Status;
}
NTSTATUS DpGetAllowedAllUserFolders(UNICODE_STRING *appData)
{
   NTSTATUS Status;

   RTL_QUERY_REGISTRY_TABLE ParamTable[4];
  
  	
   RtlZeroMemory(ParamTable, sizeof(RTL_QUERY_REGISTRY_TABLE) * 3);

   ParamTable[0].QueryRoutine = NULL;
   ParamTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
   ParamTable[0].Name = L"Common AppData";
   ParamTable[0].EntryContext = appData;
   ParamTable[0].DefaultType = REG_NONE;
 


   ParamTable[3].QueryRoutine = NULL;
   ParamTable[3].Name = NULL;

   Status=RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
                                 L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                                 ParamTable,
                                 NULL,
                                 NULL);
/*
   if(Status == STATUS_SUCCESS){
		
	  	
	  	DbgPrint("---%d %S\n", appData->Length, appData->Buffer);
		}
   	else
		DbgPrint("--------------failed\n");*/
		

   return Status;
}

BOOLEAN DpWriteAllowed(WCHAR *path,  ULONG vmId)
{

	HANDLE	procHandle;
	NTSTATUS	rc;
	int size;
	BOOLEAN ret;
	WCHAR *ptr;
	UNICODE_STRING *localSettings, *appData, *cookies;


	//return TRUE;
	if (pvms[vmId]->handle == 0)
		return TRUE;
	
	procHandle = NtCurrentProcess();
	
	localSettings= NULL;
	size = 300 * 6;
	rc = FvmVm_AllocateVirtualMemory(procHandle, &localSettings, 0, &size,
					MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	if (rc != STATUS_SUCCESS) {
		DbgPrint("--memory allocation problem(%d,NtOpenKey)\n",(ULONG)PsGetCurrentProcessId());
		return FALSE;
	}
	RtlZeroMemory(localSettings, 1800);

	(char *)appData = ((char *)localSettings)+600;
	(char *)cookies = ((char *)appData)+600;
	DpGetAllowedUserFolders(localSettings, appData, cookies);
		

	if(path[0] == L'\\' && path[1]== L'?')
		ptr = &path[4];
	else
		ptr = path;
		
	if( localSettings->Length >0){
		if(_wcsnicmp(ptr, localSettings->Buffer, localSettings->Length/2)==0){
			ret = TRUE;

			//DbgPrint("loca %S\n", ptr);
			goto NtExit;
		}
	}
	else{
		if(wcsstr(path, L"\\Local Settings\\")){
			ret = TRUE;
			goto NtExit;

		}
	}
		
	if(appData->Length>0){
		if(_wcsnicmp(ptr, appData->Buffer, appData->Length/2)==0){
			ret = TRUE;
			//DbgPrint("appData\n");
			goto NtExit;
		}
	}
	else{
		if(wcsstr(path, L"\\Application Data\\")){
			ret = TRUE;
			goto NtExit;
		
		}
	}
	if(cookies->Length>0){
		if(_wcsnicmp(ptr, cookies->Buffer, cookies->Length/2)==0){
			ret = TRUE;
			//DbgPrint("Cookies\n");
			goto NtExit;
		}
		
	}
	else{
		if(wcsstr(path, L"\\Cookies\\")){
			ret = TRUE;
			goto NtExit;

		}
	}
	RtlZeroMemory(localSettings, 1800);

	
	DpGetAllowedAllUserFolders(appData);
	if(appData->Length>0){
			if(_wcsnicmp(ptr, appData->Buffer, appData->Length/2)==0){
				ret = TRUE;
				//DbgPrint("appData %S\n", ptr);
				goto NtExit;
			}
		}
	else{
		if(wcsstr(path, L"\\All Users\\Application Data\\")){
			ret = TRUE;
			goto NtExit;
			
		}
	}

	ptr+=2;
	
	if(_wcsnicmp(ptr, L"\\Program Files\\", 15)==0){
				ret = TRUE;
				//DbgPrint("appData\n");
				goto NtExit;
	}
	
	if(_wcsnicmp(ptr, L"\\Documents and Settings\\", 23)==0 && wcsstr(ptr, L"'s Documents\\") == NULL){
					ret = TRUE;
					//DbgPrint("appData\n");
					goto NtExit;
		}

	ret = FALSE;
NtExit:
	size = 0;
	FvmVm_FreeVirtualMemory(procHandle, &localSettings, &size, MEM_RELEASE);
	//DbgPrint("%x--------- %S\n",ret, path);
	return ret;
}
#ifdef USE_FS_MAP

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
                       IN PWCHAR FileLinkName, /* virtual file path */
                       IN PWCHAR VDirName,     /* mapped physical file path */
                       IN POBJECT_ATTRIBUTES ObjAttr,
                                               /* Pointer to OBJECT_ATTRIBUTES
                                                * structure for VDirName */
                       IN ULONG VmId)          /* ID of the VM's context */
{
	NTSTATUS rc, rc1;
	ULONG memSize;
	PFILE_BASIC_INFORMATION fileBasicInfoPtr = NULL;
	PIO_STATUS_BLOCK ioStatusPtr = NULL;

	/*
	 * Create parent directories of the file under the VM's workspace.
	 */

	FvmUtil_CreateFileDir(FileLinkName, VDirName, VmId);

	rc = (winNtCreateFileProc)(FileHandle,
			DesiredAccess,
			ObjAttr,
			IoStatusBlock,
			AllocationSize,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			EaBuffer,
			EaLength);

	if (!NT_SUCCESS(rc)) {
		CHAR errStr[64];
		DbgPrint("CreateErrT1:%s\n", FvmUtil_ErrorString(rc, errStr));
	} else {
		if (!FvmTable_DeleteLogLookup(FileLinkName, VmId)) {
			if (CreateOptions == FILE_OVERWRITE_IF) {
			    /*
			     * The difference between FILE_SUPERSEDE and FILE_OVERWRITE_IF
			     * is that the latter preserves the file attributes if the file
			     * exists. Therefore, if the file exists on the host environment
			     * but not in the VM, the attributes should be duplicated to
			     * the file created in the VM.
			     */

				memSize = sizeof(FILE_BASIC_INFORMATION)
						+ sizeof(IO_STATUS_BLOCK);
				rc1 = FvmVm_AllocateVirtualMemory(NtCurrentProcess(),
						&fileBasicInfoPtr, 0, &memSize, MEM_COMMIT,
						PAGE_READWRITE);


				if (NT_SUCCESS(rc1)) {
					(CHAR *)ioStatusPtr = ((CHAR *)fileBasicInfoPtr)
							+ sizeof(FILE_BASIC_INFORMATION);

					rc1 = (winNtQueryAttributesFileProc)(ObjectAttributes,
							fileBasicInfoPtr);

					if (NT_SUCCESS(rc1)) {
						(winNtSetInformationFileProc)(*FileHandle,
								ioStatusPtr,
								fileBasicInfoPtr,
								sizeof(FILE_BASIC_INFORMATION),
								FileBasicInformation);
					}
					memSize = 0;
					FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr,
							&memSize, MEM_RELEASE);
				}
			}
		} else {
			FvmTable_DeleteLogRemove(FileLinkName, VmId);
		}
        /*
         * Add the full path of the file into the FVM file tree in memory.
	     * We assume the file path starts with "\??\" (4 characters), such
	     * as "\??\c:\abc".
         */

		FvmTable_FVMFileListAddFullPath(FileLinkName + 4, VmId);
	}
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
                       IN PWCHAR FileLinkName, /* virtual file path */
                       IN PWCHAR VDirName,     /* mapped physical file path */
                       IN POBJECT_ATTRIBUTES ObjAttr,
                                               /* Pointer to OBJECT_ATTRIBUTES
                                                * structure for VDirName */
                       IN ULONG VmId)          /* ID of the VM's context */
{
	NTSTATUS rc = STATUS_OBJECT_PATH_NOT_FOUND;

    /*
     * FILE_OPEN or FILE_OVERWRITE requires the file to be accessed exists.
     * So we first check if the file is already in the DeleteLog.
     */
     
	if (!FvmTable_DeleteLogLookup(FileLinkName, VmId)) {
		if (CreateDisposition != FILE_OVERWRITE
				&& !FvmFile_IsOpenforWrite(DesiredAccess, ShareAccess,
				CreateOptions)) {
            /*
             * We already know there is no corresponding file in the VM.
             * So we can simply open the file on the host environment
             * for a read-only access.
             */

			rc = (winNtCreateFileProc)(FileHandle,
					DesiredAccess,
					ObjectAttributes,
					IoStatusBlock,
					AllocationSize,
					FileAttributes,
					ShareAccess,
					CreateDisposition,
					CreateOptions,
					EaBuffer,
					EaLength);
			if(rc == STATUS_OBJECT_PATH_NOT_FOUND){
				rc = (winNtCreateFileProc)(FileHandle,
						DesiredAccess,
						ObjAttr,
						IoStatusBlock,
						AllocationSize,
						FileAttributes,
						ShareAccess,
						CreateDisposition,
						CreateOptions,
						EaBuffer,
						EaLength);
			}
			return rc;

		} else {
            /*
             * Copy the file to the VM's workspace and open it.
             */

			rc = FvmUtil_CopyFiletoVM(ObjectAttributes, FileLinkName, VDirName,
					(BOOLEAN)(CreateOptions & FILE_DIRECTORY_FILE), FALSE,
					VmId);

		
			rc = (winNtCreateFileProc)(FileHandle,
						DesiredAccess,
						ObjAttr,
						IoStatusBlock,
						AllocationSize,
						FileAttributes,
						ShareAccess,
						CreateDisposition,
						CreateOptions,
						EaBuffer,
						EaLength);
	
		}
	}
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
                       IN PWCHAR FileLinkName, /* Virtual file path */
                       IN PWCHAR VDirName,     /* Mapped physical file path */
                       IN POBJECT_ATTRIBUTES ObjAttr,
                                               /* Pointer to OBJECT_ATTRIBUTES
                                                * structure for VDirName */
                       IN ULONG VmId)          /* ID of the VM's context */
{
	NTSTATUS rc, rc1;
	ULONG memSize1, memSize2;
	PFILE_BASIC_INFORMATION fileBasicInfoPtr = NULL;
	PIO_STATUS_BLOCK ioStatusPtr = NULL;

	if (FvmTable_DeleteLogLookup(FileLinkName, VmId)) {
		/*
		 * If the file has been deleted, the system call is going to create
		 * the file again.
		 */

		FvmUtil_CreateFileDir(FileLinkName, VDirName, VmId);

		rc = (winNtCreateFileProc)(FileHandle,
				DesiredAccess,
				ObjAttr,
				IoStatusBlock,
				AllocationSize,
				FileAttributes,
				ShareAccess,
				CreateDisposition,
				CreateOptions,
				EaBuffer,
				EaLength);

		if (NT_SUCCESS(rc)) {
			FvmTable_DeleteLogRemove(FileLinkName, VmId);
			FvmTable_FVMFileListAddFullPath(FileLinkName + 4, VmId);
		}
		goto ntExit;
	}

	memSize1 = sizeof(FILE_BASIC_INFORMATION);
	rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr, 0,
			&memSize1, MEM_COMMIT, PAGE_READWRITE);

	if (!NT_SUCCESS(rc)) {
		rc = STATUS_ACCESS_DENIED;
		goto ntExit;
	}

    /*
     * We use ID_NTQUERYATTRIBUTESFILE to check whether the file exists on
     * the host environment.
     */

	rc = (winNtQueryAttributesFileProc)(ObjectAttributes, fileBasicInfoPtr);

	if (NT_SUCCESS(rc) || (rc != STATUS_OBJECT_PATH_NOT_FOUND
			&& rc != STATUS_OBJECT_NAME_NOT_FOUND)) {

		if (CreateDisposition == FILE_CREATE) {
			/*
			 * The desired behavior of FILE_CREATE is to fail the request
			 * if a file with the same name exists.
			 */

			rc = STATUS_OBJECT_NAME_COLLISION;
		} else {
			if (!FvmFile_IsOpenforWrite(DesiredAccess, ShareAccess,
					CreateOptions)) {
			   memSize1 = 0;
				FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr,
						&memSize1, MEM_RELEASE);
				goto winSysCall;
			}

            /*
             * Copy the file on the host environment to the VM's workspace.
             */

			rc = FvmUtil_CopyFiletoVM(ObjectAttributes, FileLinkName, VDirName,
					(BOOLEAN)(CreateOptions & FILE_DIRECTORY_FILE), FALSE,
					VmId);

			if (NT_SUCCESS(rc)) {
				rc = (winNtCreateFileProc)(FileHandle,
						DesiredAccess,
						ObjAttr,
						IoStatusBlock,
						AllocationSize,
						FileAttributes,
						ShareAccess,
						CreateDisposition,
						CreateOptions,
						EaBuffer,
						EaLength);

				if (!NT_SUCCESS(rc)) {
//					CHAR errStr[64];
//					DbgPrint("CreateErrT3:%s\n", FvmUtil_ErrorString(rc, errStr));
					DbgPrint("CreateErrT3:%x\n", rc);
				}
			} else {
				/*
				 * Copying file failed, so we simply create a file with the
				 * same attributes in the VM.
				 */

				FvmUtil_CreateFileDir(FileLinkName, VDirName, VmId);

				rc = (winNtCreateFileProc)(FileHandle,
						DesiredAccess,
						ObjAttr,
						IoStatusBlock,
						AllocationSize,
						FileAttributes,
						ShareAccess,
						CreateDisposition,
						CreateOptions,
						EaBuffer,
						EaLength);

				if (NT_SUCCESS(rc)) {
					memSize2 = sizeof(IO_STATUS_BLOCK);
					rc1 = FvmVm_AllocateVirtualMemory(NtCurrentProcess(),
							&ioStatusPtr, 0, &memSize2, MEM_COMMIT,
							PAGE_READWRITE);

					if (NT_SUCCESS(rc1)) {
						(winNtSetInformationFileProc)(*FileHandle,
								ioStatusPtr,
								fileBasicInfoPtr,
								sizeof(FILE_BASIC_INFORMATION),
								FileBasicInformation);

                        memSize2 = 0;
						FvmVm_FreeVirtualMemory(NtCurrentProcess(), &ioStatusPtr,
								&memSize2,  MEM_RELEASE);
					}
				}
			}
		}
	} else {
		/*
		 * No file with the same name exists on the host environment, so we
		 * create a file in the VM's workspace.
		 */

		FvmUtil_CreateFileDir(FileLinkName, VDirName, VmId);

		rc = (winNtCreateFileProc)(FileHandle,
				DesiredAccess,
				ObjAttr,
				IoStatusBlock,
				AllocationSize,
				FileAttributes,
				ShareAccess,
				CreateDisposition,
				CreateOptions,
				EaBuffer,
				EaLength);

		if (!NT_SUCCESS(rc)) {
			CHAR errStr[64];
			DbgPrint("CreateErrT3:%s\n", FvmUtil_ErrorString(rc, errStr));
		} else {
			FvmTable_DeleteLogRemove(FileLinkName, VmId);
			FvmTable_FVMFileListAddFullPath(FileLinkName + 4, VmId);
		}
	}

   memSize1 = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr, &memSize1,
			MEM_RELEASE);
	goto ntExit;

winSysCall:
	rc = (winNtCreateFileProc)(FileHandle,
			DesiredAccess,
			ObjectAttributes,
			IoStatusBlock,
			AllocationSize,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			EaBuffer,
			EaLength);
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
                     IN ULONG EaLength)
{
	NTSTATUS rc;
	ULONG vmId = INVALID_VMID;
	PWCHAR fnPtr = NULL;
	ULONG memSize = _MAX_PATH*2, memSizeFvm = _MAX_PATH*2;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;  /* Object pointing to the shared
	                                        * host file */
	POBJECT_ATTRIBUTES fvmObjPtr = NULL;   /* Object pointing to the private
	                                        * FVM file */
        PWCHAR fileLinkName = NULL;
       PWCHAR  vDirName = NULL;   
	ACCESS_MASK newDesiredAccess;
	
	InterlockedIncrement(&fvm_Calls_In_Progress);

	objAttrPtr = ObjectAttributes;
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		PWCHAR binPath = NULL;
		PCHAR accessStr = NULL;
//		WCHAR fileLinkName[_MAX_PATH*2];	
//		WCHAR vDirName[_MAX_PATH*2];
		PWCHAR hostName, fvmName = NULL;
		BOOLEAN hostQuery = FALSE;

//              fileLinkName = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILEOPT_POOL_TAG);
              fileLinkName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (fileLinkName == NULL) {
                     DbgPrint("FvmFile_NtCreateFile: ExAllocateFromPagedLookasideList fail\n");  
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
//              vDirName = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_FILEOPT_POOL_TAG);
              vDirName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (vDirName == NULL) {
                     DbgPrint("FvmFile_NtCreateFile: ExAllocateFromPagedLookasideList fail\n"); 
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}


		if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
			goto winSysCall; //
		}
		//DbgPrint("create file: %S\n", fileLinkName);
				
		if(wcsstr(fileLinkName, L"{A2D06C82-9ABF-403E-B83A-BBC77DF9FAD9}"))
				goto winSysCall;
		if(_wcsnicmp(fileLinkName, L"\\Device\\", 8)==0) {//Netbios"))
			if (_wcsnicmp(fileLinkName+8, L"Netbios", 7)==0)  
				goto winSysCall;
			
			if (_wcsnicmp(fileLinkName+8, L"KSENUM#", 7)==0)  
							goto winSysCall;
		}
		if(wcsstr(fileLinkName, L"shadow"))
				goto winSysCall;
		

		if(wcsstr(fileLinkName, L"\\SystemRoot\\AppPatch"))
				goto winSysCall;
		
		
		if(wcsstr(fileLinkName, L"AvgAviLdr")) //for avgantivirus
			goto winSysCall;

		if (_wcsnicmp(fileLinkName, L"\\??\\root#system#",16 )==0){//device
			goto winSysCall;
		}

		//end fix of pro/e
		
		if (ExGetPreviousMode() == KernelMode) {
			//DbgPrint("kernel level-- NtCreteFile:  %S\n", fileLinkName);
			goto winSysCall;
		}
		//goto winSysCall;
//#ifdef RPCSS
		if(FvmVm_isRpcssProcess((ULONG)PsGetCurrentProcessId(),vmId)){
			if(wcsstr(fileLinkName,L"NtControlPipe")){
				//DbgPrint("%d, svchost process donnot rename %S\n",PsGetCurrentProcessId(),fileLinkName);
				goto winSysCall;
			}
		}
//#endif
		if (!FvmIsLocalFileAccess(fileLinkName, vmId)) {
			/*
			 * The process is accessing a device file such as the network
			 * device or a named pipe.
			 */

		#if 1
			/*
			 * Disable all the device access except certain network access.
			 */
			 BOOLEAN ddofsAccess;
			 BOOLEAN pipMailslotAccess = FvmFile_IsPipeMailslotConnect(fileLinkName);
	
			 
			if (!FvmFile_AllowDeviceAccess(fileLinkName, vmId, &ddofsAccess)) {

            //DbgPrint("Create Non-File Argument:-------------------%S\n",fileLinkName);

				if (wcsstr(fileLinkName, L"\\PIPE\\srvsvc")){
					IoStatusBlock->Status = STATUS_ACCESS_DENIED;
					rc = STATUS_ACCESS_DENIED;
					goto ntExit;
				}
				
			} else {
				if (!ddofsAccess){
					//DbgPrint("++++++++++++++ %S", fileLinkName);
					objAttrPtr = ObjectAttributes;
					goto winSysCall;
				}else{
				
					if (!pipMailslotAccess) {
						
						if (CreateOptions&FILE_DIRECTORY_FILE){  //skip folders
							objAttrPtr = ObjectAttributes;
							goto winSysCall;
						}
						else if(fileLinkName[wcslen(fileLinkName)-1] == L'\\'){ //skip folders
							objAttrPtr = ObjectAttributes;
							goto winSysCall;
						}
						else{
						
							objAttrPtr = NULL;
							
							if (pvms[vmId]->handle){																
								swprintf(vDirName, L"%s__DDOFS_%.8x", fileLinkName, pvms[vmId]->handle);							
							}
							else
								swprintf(vDirName, L"%s", fileLinkName);

							
							rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
									&objAttrPtr, &memSize);
							if (!NT_SUCCESS(rc)) {
								rc = STATUS_ACCESS_DENIED;
								goto ntExit;
							}
				
							rc = (winNtCreateFileProc)(
									FileHandle,
									DesiredAccess,
									objAttrPtr,
									IoStatusBlock,
									AllocationSize,
									FileAttributes,
									ShareAccess,
									CreateDisposition,
									CreateOptions,
									EaBuffer,
									EaLength);
				
							memSize = 0;
							FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
									MEM_RELEASE);
				
							goto ntExit;
						}
							
					}
				}
			}
		#endif

            /*
             * The following code redirects access to named pipe and mailslot
             * under a VM's local namespace, while allowing all other types
             * of device access.
             */

			if (pipMailslotAccess) {
				if (!FvmFile_MapPipeMailSlotPath(fileLinkName, vmId,
						vDirName)) {
					goto winSysCall;
				}

				//DbgPrint("New device name:%S\n", vDirName);
				objAttrPtr = NULL;
				rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
						&objAttrPtr, &memSize);
	            if (!NT_SUCCESS(rc)) {
					rc = STATUS_ACCESS_DENIED;
					goto ntExit;
				}

				rc = (winNtCreateFileProc)(
						FileHandle,
						DesiredAccess,
						objAttrPtr,
						IoStatusBlock,
						AllocationSize,
						FileAttributes,
						ShareAccess,
						CreateDisposition,
						CreateOptions,
						EaBuffer,
						EaLength);

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
				//goto winSysCall;
				IoStatusBlock->Status = STATUS_ACCESS_DENIED;
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
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

			if (FvmTable_FVMFileListLookup(fnPtr + 4, vmId)) {
	            /*
	             * We assume the file path starts with "\??\" (4 characters),
	             * such as "\??\c:\abc".
	             */

				goto winSysCall;
			} else {
				/*
				 * We need to get an object pointing to the path of the
				 * original file shared on the host environment.
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
				fvmObjPtr = ObjectAttributes;

				goto hostQuery;
			}
		} else {
			fnPtr = NULL;
			hostName = fileLinkName;

			if (!FvmFile_MapPathEx(hostName, vmId, vDirName, TRUE)) {
				goto winSysCall;
			}
		
			fvmName = vDirName;

			/*
			 * Get an object pointing to the private path of the file under
			 * a VM's workspace.
			 */

			rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
					&fvmObjPtr, &memSizeFvm);

			if (!NT_SUCCESS(rc)) {
#if 0
				CHAR errStr[64];
				DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errStr));
#else
                            DbgPrint("ErrMem:%x\n", rc);
#endif
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}

			if (!FvmTable_FVMFileListLookup(hostName + 4, vmId)) {
				goto hostQuery;
			} else {
				rc = (winNtCreateFileProc)(
						FileHandle,
						DesiredAccess,
						fvmObjPtr,
						IoStatusBlock,
						AllocationSize,
						FileAttributes,
						ShareAccess,
						CreateDisposition,
						CreateOptions,
						EaBuffer,
						EaLength);
				goto ntExit;
			}
		}

#if DBG_CREATEFILE
		binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2,
		    FVM_FILEOPT_POOL_TAG);
		if (binPath == NULL) {
			goto winSysCall;
		}
		FvmUtil_GetBinaryPathName(binPath);
		DbgPrint("NtCreateFile : Application Name - %S\n", binPath);
		ExFreePool(binPath);

		DbgPrint("               Arguments - %S\n", hostName);
		accessStr = ExAllocatePoolWithTag( PagedPool, _MAX_PATH*2,
			FVM_FILEOPT_POOL_TAG);
		if (accessStr) {
			DbgPrint("               Access - %s\n",
					AccessString(DesiredAccess, accessStr));
			ExFreePool(accessStr);
		}
		DbgPrint("               New file name - %S\n", fvmName);
#endif

hostQuery:
        /*
         * The file to be accessed does not exist on the VM's workspace.
         * So we go to the host environment and decide if a copy-on-write
         * is necessary. We divide the system call processing into three
         * cases, which are processed by three functions separately. Please
         * refer to the DDK documentation to understand the CreateDisposition
         * argument.
         */

		//newDesiredAccess = DesiredAccess;
	#if 0
		DbgPrint("create file: %x --- %x %x %x %x %x %x---> %x %x %S\n",CreateDisposition,

		FILE_SUPERSEDE,
		FILE_CREATE,
		FILE_OPEN,
		FILE_OPEN_IF,
		FILE_OVERWRITE,
		FILE_OVERWRITE_IF,
		 DesiredAccess, CreateDisposition, hostName);
	#endif

	    if(pvms[vmId]->handle)
		if (DesiredAccess & (GENERIC_WRITE|	FILE_WRITE_DATA| FILE_WRITE_EA| FILE_APPEND_DATA|  DELETE|  WRITE_DAC|     WRITE_OWNER)) 
			if(!DpWriteAllowed(hostName, vmId)){
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}

	
		
		
		switch (CreateDisposition) {
		case FILE_SUPERSEDE:
		case FILE_OVERWRITE_IF:
				//DbgPrint("1 create file:  ... %S %S\n", hostName, fvmName);
				if(!DpWriteAllowed(hostName, vmId)){
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}
			rc = FvmFile_NtCreateFileT1(
					FileHandle,
					DesiredAccess,
					objAttrPtr,
					IoStatusBlock,
					AllocationSize,
					FileAttributes,
					ShareAccess,
					CreateDisposition,
					CreateOptions,
					EaBuffer,
					EaLength,
					hostName,
					fvmName,
					fvmObjPtr,
					vmId);
			goto ntExit;

		
		case FILE_OVERWRITE:
			if(!DpWriteAllowed(hostName, vmId)){
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}
		case FILE_OPEN:
			//	DbgPrint("2 create file:  ... %S %S\n", hostName, fvmName);
			rc = FvmFile_NtCreateFileT2(
					FileHandle,
					DesiredAccess,
					objAttrPtr,
					IoStatusBlock,
					AllocationSize,
					FileAttributes,
					ShareAccess,
					CreateDisposition,
					CreateOptions,
					EaBuffer,
					EaLength,
					hostName,
					fvmName,
					fvmObjPtr,
					vmId);
			goto ntExit;

		case FILE_CREATE:
			if(!DpWriteAllowed(hostName, vmId)){
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}
		case FILE_OPEN_IF:
			//	DbgPrint("3 create file:  ... %S %S\n", hostName, fvmName);
			rc = FvmFile_NtCreateFileT3(
					FileHandle,
					DesiredAccess,
					objAttrPtr,
					IoStatusBlock,
					AllocationSize,
					FileAttributes,
					ShareAccess,
					CreateDisposition,
					CreateOptions,
					EaBuffer,
					EaLength,
					hostName,
					fvmName,
					fvmObjPtr,
					vmId);
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

	rc = (winNtCreateFileProc)(
			FileHandle,
			DesiredAccess,
			objAttrPtr,
			IoStatusBlock,
			AllocationSize,
			FileAttributes,
			ShareAccess,
			CreateDisposition,
			CreateOptions,
			EaBuffer,
			EaLength);
ntExit:
#ifdef NTCREATEFILE
	if (vmId != INVALID_VMID){
		KPROCESSOR_MODE mode;
		mode = ExGetPreviousMode();
		if (mode != KernelMode && rc == STATUS_SUCCESS) {
			char operation[20];
			WCHAR *logFileName = L"NULL";
			char *logs;
			IO_STATUS_BLOCK Iosb;
				
			if (IoStatusBlock->Information == FILE_CREATED)
				RtlStringCbPrintfA(operation, sizeof(operation), "created");
			else if (IoStatusBlock->Information == FILE_OPENED)
				RtlStringCbPrintfA(operation, sizeof(operation), "opened");
			else if (IoStatusBlock->Information == FILE_OVERWRITTEN||IoStatusBlock->Information==FILE_SUPERSEDED)
				RtlStringCbPrintfA(operation, sizeof(operation), "replaced");
			else
				RtlStringCbPrintfA(operation, sizeof(operation), "failed");
		
			//pid, file name, filehandle, operation, return
			if (fileLinkName){
				logFileName = fileLinkName;
			}
			
			logs = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
			if (logs == NULL) {
				DbgPrint("NtClose: ExAllocateFromPagedLookasideList fail\n");  
			}
			else{
				PWCHAR nptr = (PWCHAR) logs;
				FvmUtil_GetBinaryPathName(nptr);
				if(!wcsstr(nptr, L"fvmshell.exe") && !wcsstr(fileLinkName, L"\\??\\RNIFVMDR")){
					ticks tm = getticks();
					
					RtlStringCbPrintfA(logs, PATHSIZE, 
						"%I64u, NtCreateFile, %u, %u, %S, %s, %u\r\n",tm.QuadPart, (ULONG)PsGetCurrentProcessId(), 
						(rc==STATUS_SUCCESS)?*FileHandle:0, fileLinkName, operation,  rc);
					ZwWriteFile(pvms[vmId]->logHandle, NULL, NULL, NULL, &Iosb, (void*)logs, strlen(logs)*sizeof(char), NULL, NULL);
				}
				ExFreePool(logs);
			}
		}
	}
#endif		

	
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
       if (fileLinkName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, fileLinkName );
	}     
       if (vDirName) {
//		ExFreePool(vDirName);
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vDirName );
	}     
	
//	if (vmId != INVALID_VMID) 		DbgPrint("CreateFile Code: %x", rc);


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
                   IN ULONG OpenMode)
{
	NTSTATUS rc;
	ULONG vmId = INVALID_VMID;
	PWCHAR fnPtr = NULL;
	ULONG memSize = _MAX_PATH*2, memSizeFvm = _MAX_PATH*2;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	POBJECT_ATTRIBUTES fvmObjPtr = NULL;
       PWCHAR fileLinkName = NULL;
       PWCHAR vDirName = NULL;       
	InterlockedIncrement(&fvm_Calls_In_Progress);

	objAttrPtr = ObjectAttributes;
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {		
//		WCHAR fileLinkName[_MAX_PATH*2];
//		WCHAR vDirName[_MAX_PATH*2];
		PWCHAR hostName, fvmName = NULL;

              fileLinkName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (fileLinkName == NULL) {
                     DbgPrint("FvmFile_NtOpenFile: ExAllocateFromPagedLookasideList fail\n");  
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
              vDirName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (vDirName == NULL) {
                     DbgPrint("FvmFile_NtOpenFile: ExAllocateFromPagedLookasideList fail\n"); 
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
              
		if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
			goto winSysCall;
		}
		//DbgPrint("OpenFile %S\n",	fileLinkName);

						
		if(wcsstr(fileLinkName, L"\\SystemRoot\\Prefetch"))
			goto winSysCall;

		if (ExGetPreviousMode() == KernelMode) {
				//DbgPrint("kernel level -- NtOpenFile: %S\n", fileLinkName);
				goto winSysCall;
		}
	
		
// #ifdef RPCSS
		if(FvmVm_isRpcssProcess((ULONG)PsGetCurrentProcessId(),vmId)){
				if(wcsstr(fileLinkName,L"DosDevices\\pipe")){
					DbgPrint("%d, svchost process donnot rename %S\n",PsGetCurrentProcessId(),fileLinkName);
					goto winSysCall;
				}
		}
//#endif 
		if (!FvmIsLocalFileAccess(fileLinkName, vmId)) {
			/*
			 * The process is accessing a device file such as the network
			 * device or a named pipe.
			 */

		#if 1
			/*
			 * Disable all the device access except certain network access.
			 */
			 BOOLEAN ddofsAccess;
			
			BOOLEAN pipMailslotAccess = FvmFile_IsPipeMailslotConnect(fileLinkName);

			if (!FvmFile_AllowDeviceAccess(fileLinkName, vmId, &ddofsAccess)) {				
				//DbgPrint("Open Non-File Argument:-------------------%S\n",		fileLinkName);
				/*
				IoStatusBlock->Status = STATUS_ACCESS_DENIED;
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
				*/
			} else {
				if (!ddofsAccess){
					objAttrPtr = ObjectAttributes;
					goto winSysCall;
				}else{
				
					if (!pipMailslotAccess ) {
						
						if (OpenMode &FILE_DIRECTORY_FILE){
							objAttrPtr = ObjectAttributes;
							goto winSysCall;
						}
						else if(fileLinkName[wcslen(fileLinkName)-1] == L'\\'){ //skip folders
							objAttrPtr = ObjectAttributes;
							goto winSysCall;
						}
						else{
							
							objAttrPtr = NULL;						
							if (pvms[vmId]->handle){															
								swprintf(vDirName, L"%s__DDOFS_%.8x", fileLinkName, pvms[vmId]->handle);								
							}
							else
								swprintf(vDirName, L"%s", fileLinkName);
							
							rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
									&objAttrPtr, &memSize);
							if (!NT_SUCCESS(rc)) {
								rc = STATUS_ACCESS_DENIED;
								goto ntExit;
							}
				
							rc = (winNtOpenFileProc)(
								FileHandle,
								DesiredAccess,
								objAttrPtr,
								IoStatusBlock,
								ShareMode,
								OpenMode);
							memSize = 0;
							FvmVm_FreeVirtualMemory(NtCurrentProcess(), &objAttrPtr, &memSize,
									MEM_RELEASE);
				
							goto ntExit;
							
						}
					}
				}	
			}
		#endif
            /*
             * The following code redirects access to named pipe and mailslot
             * under a VM's local namespace, while allowing all other types
             * of device access.
             */

			if (pipMailslotAccess ) {
				if (!FvmFile_MapPipeMailSlotPath(fileLinkName, vmId,
						vDirName)) {
					goto winSysCall;
				}
				// DbgPrint("New device name:%S\n", vDirName);

				objAttrPtr = NULL;
				rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
						&objAttrPtr, &memSize);

				if (!NT_SUCCESS(rc)) {
					rc = STATUS_ACCESS_DENIED;
					goto ntExit;
				}

				rc = (winNtOpenFileProc)(
						FileHandle,
						DesiredAccess,
						objAttrPtr,
						IoStatusBlock,
						ShareMode,
						OpenMode);
		
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
				//goto winSysCall;
				IoStatusBlock->Status = STATUS_ACCESS_DENIED;
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
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

			if (FvmTable_FVMFileListLookup(fnPtr + 4, vmId)) {
				goto winSysCall;
			} else {
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
				fvmObjPtr = ObjectAttributes;
				goto hostQuery;
			}
		} else{
			fnPtr = NULL;
			hostName = fileLinkName;
			
			if (!FvmFile_MapPathEx(hostName, vmId, vDirName, TRUE)) {
				goto winSysCall;
			}
			fvmName = vDirName;

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
			
			//C:\Documents and Settings\Administrator\Local Settings\Temporary Internet Files\Content.IE5
			if (!FvmTable_FVMFileListLookup(hostName + 4, vmId)){// && wcsstr(fvmName,L"Temporary Internet Files\\Content") == NULL) {
				goto hostQuery;
			} else {	
			
				rc = (winNtOpenFileProc)(
						FileHandle,
						DesiredAccess,
						fvmObjPtr,
						IoStatusBlock,
						ShareMode,
						OpenMode);

				goto ntExit;
				
			}
			
		}

#if DBG_OPENFILE
		binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2,
		    FVM_FILEOPT_POOL_TAG);
		if (binPath == NULL) {
			goto winSysCall;
		}
		FvmUtil_GetBinaryPathName(binPath);
		DbgPrint("NtOpenFile : Application Name - %S\n", binPath);
		ExFreePool(binPath);
		DbgPrint("               Arguments - %S\n", hostName);
		accessStr = ExAllocatePoolWithTag( PagedPool, _MAX_PATH*2,
			FVM_FILEOPT_POOL_TAG);
		if (accessStr) {
			DbgPrint("               Access - %s\n",
					AccessString(DesiredAccess, accessStr));
			ExFreePool(accessStr);
		}
		DbgPrint("               New file name - %S\n", fvmName);
#endif


hostQuery:
        /*
         * The file to be opened does not exist on the VM's workspace.
         * So we go to the host environment and decide if a copy-on-write
         * is necessary.
         */       

		if (!FvmTable_DeleteLogLookup(hostName, vmId)) {
			if (!FvmFile_IsOpenforWrite(DesiredAccess, ShareMode, OpenMode))
				goto winSysCall;

		
			if(!DpWriteAllowed(hostName, vmId)){
				rc = STATUS_ACCESS_DENIED;
				goto ntExit;
			}

            /*
             * If a file is to be opened for write, we copy the file to the
             * VM's private workspace. This operation includes copying the
             * parent directory, the file itself and file attributes.
             */
				//DbgPrint("OpenFile %S\n",		fileLinkName);

			rc =  FvmUtil_CopyFiletoVM(objAttrPtr, hostName, fvmName,
					(BOOLEAN)(OpenMode & FILE_DIRECTORY_FILE), TRUE, vmId);

			if (NT_SUCCESS(rc)) {
				rc = (winNtOpenFileProc)(
						FileHandle,
						DesiredAccess,
						fvmObjPtr,
						IoStatusBlock,
						ShareMode,
						OpenMode);

				if (!NT_SUCCESS(rc)) {
					CHAR errStr[64];
					DbgPrint("OpenErr2:%s\n", FvmUtil_ErrorString(rc, errStr));
				}
			}
		} else {
			rc = STATUS_OBJECT_PATH_NOT_FOUND;
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

	rc = (winNtOpenFileProc)(
			FileHandle,
			DesiredAccess,
			objAttrPtr,
			IoStatusBlock,
			ShareMode,
			OpenMode);

ntExit:

#ifdef NTOPENFILE
	if (vmId != INVALID_VMID){





		KPROCESSOR_MODE mode;
		mode = ExGetPreviousMode();
		if (mode != KernelMode && rc == STATUS_SUCCESS) {
			
			WCHAR *logFileName = L"NULL";
			char *logs;
			IO_STATUS_BLOCK Iosb;
				
			
			//pid, file name, filehandle, operation, return
			if (fileLinkName){
				logFileName = fileLinkName;
			}
			
			logs = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
			if (logs == NULL) {
				DbgPrint("NtClose: ExAllocateFromPagedLookasideList fail\n");  
			}
			else{
				PWCHAR nptr = (PWCHAR) logs;
				FvmUtil_GetBinaryPathName(nptr);
				if(!wcsstr(nptr, L"fvmshell.exe") && !wcsstr(fileLinkName, L"\\??\\RNIFVMDR")){
					ticks tm = getticks();
					//sprintf(logs, "NtCreateFile %u, %u, %S, %s, %u\r\n",(ULONG)PsGetCurrentProcessId(), (rc==STATUS_SUCCESS)?*FileHandle:0, fileLinkName, operation,  rc);
					RtlStringCbPrintfA(logs, PATHSIZE,
					"%I64u, NtOpenFile, %u, %u, %S, %u\r\n",tm.QuadPart, (ULONG)PsGetCurrentProcessId(),
					(rc==STATUS_SUCCESS)?*FileHandle:0, fileLinkName, rc);
					ZwWriteFile(pvms[vmId]->logHandle, NULL, NULL, NULL, &Iosb, (void*)logs, strlen(logs)*sizeof(char), NULL, NULL);
				}
				ExFreePool(logs);
			}
		}
	/*
			WCHAR *logFileName = L"NULL";
			
			//pid, file name, filehandle,  return
			if (fileLinkName){
				logFileName = fileLinkName;
			}
			
	
			DbgPrint("     NtOpenFile(%d, %x, %S, %x)\n",(ULONG)PsGetCurrentProcessId(),(rc==STATUS_SUCCESS)?*FileHandle:0, fileLinkName, rc);
			*/
		}
#endif
	
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
	
       if (fileLinkName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, fileLinkName );
	}     
       if (vDirName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vDirName );
	}      		
	   if (vmId != INVALID_VMID) {
		   
		   //DbgPrint("OpenFile Code: %x\n", rc);
		   if (NT_SUCCESS(rc))
			   FvmTable_HandleTableRemoveEx(*FileHandle, vmId,1);
	   }

	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}



NTSTATUS FvmFile_NtReadFile(
    IN HANDLE  FileHandle,
    IN HANDLE  Event  OPTIONAL,
    IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL,
    IN PVOID  ApcContext  OPTIONAL,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  Buffer,
    IN ULONG  Length,
    IN PLARGE_INTEGER  ByteOffset  OPTIONAL,
    IN PULONG  Key  OPTIONAL
    )
{
	NTSTATUS rc;
	ULONG vmid = INVALID_VMID;
	ULONG  pid = -1;
	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	rc = winNtReadFileProc(FileHandle,
							Event,
							ApcRoutine,
							ApcContext,
							IoStatusBlock,
							Buffer,
							Length,
							ByteOffset,
							Key);
#ifdef NTREADFILE
	if (FileHandle){
			
			KPROCESSOR_MODE mode;
			mode = ExGetPreviousMode();
			
		
			if (mode != KernelMode && vmid != INVALID_VMID) {
				PWCHAR wFullName = NULL;
				PWCHAR name = NULL;
				char * logs;
				IO_STATUS_BLOCK Iosb;
				PWCHAR nptr;
				ticks  tm;
				
				wFullName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
				logs = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
				if (wFullName == NULL || logs == NULL) {
					DbgPrint("NtClose: ExAllocateFromPagedLookasideList fail\n");  
				}
				else{
					wFullName[0] = L'\0';
					if (FvmUtil_PathFromHandle(FileHandle, NULL, wFullName)) {
						if ( wFullName[0] != L'\0'){
							if (wFullName[1]==L'R' && wFullName[2] == L'E' && wFullName[3] == L'G')
								name = NULL;// wcsstr(wFullName, L"Registry");
							else{
								FvmUtil_GetOriginalFileName(wFullName, PATHSIZE, vmid);
								name = wFullName;
							}
						}
					}							
				}
	
				nptr = (PWCHAR) logs;
				FvmUtil_GetBinaryPathName(nptr);
				if(!wcsstr(nptr, L"fvmshell.exe")){
					tm = getticks();
					RtlStringCbPrintfA(logs, PATHSIZE, 
						"%I64u, NtReadFile, %u, %u, %S, %u, %u, %u, %u, %u\r\n",tm.QuadPart, (ULONG)PsGetCurrentProcessId(), 
						FileHandle, name, Buffer, Length, ByteOffset, IoStatusBlock->Information, rc);
					ZwWriteFile(pvms[vmid]->logHandle, NULL, NULL, NULL, &Iosb, (void*)logs, strlen(logs)*sizeof(char), NULL, NULL);
				}
				
				if(wFullName)
					ExFreePool(wFullName);
				if(logs)
					ExFreePool(logs);
				
			}
			
			
		}
#endif

	return rc;
}

NTSTATUS FvmFile_NtWriteFile(
    IN HANDLE  FileHandle,
    IN HANDLE  Event  OPTIONAL,
    IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL,
    IN PVOID  ApcContext  OPTIONAL,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    IN PVOID  Buffer,
    IN ULONG  Length,
    IN PLARGE_INTEGER  ByteOffset  OPTIONAL,
    IN PULONG  Key  OPTIONAL
    )
{
	NTSTATUS rc;
	ULONG vmid = INVALID_VMID;
	ULONG  pid = -1;
	KPROCESSOR_MODE mode;

	
	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	rc = winNtWriteFileProc(
		 	FileHandle,
			Event,
			ApcRoutine,
			ApcContext,
			IoStatusBlock,
			Buffer,
			Length,
			ByteOffset,
			Key
		);
#ifdef NTWRITEFILE
	mode = ExGetPreviousMode();		
/*
	if (FileHandle && mode != KernelMode){
				PWCHAR wFullName = NULL;
				PWCHAR name = NULL;
				WCHAR log[500];
				IO_STATUS_BLOCK Iosb;
				if (vmid != INVALID_VMID) {
				
					wFullName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
					if (wFullName == NULL) {
						DbgPrint("NtClose: ExAllocateFromPagedLookasideList fail\n");  
					}
					else{
						wFullName[0] = L'\0';
						if (FvmUtil_PathFromHandle(FileHandle, NULL, wFullName)) {
							if ( wFullName[0] != L'\0'){
								if (wFullName[1]==L'R' && wFullName[2] == L'E' && wFullName[3] == L'G')
									name = NULL;// wcsstr(wFullName, L"Registry");
								else{
									FvmUtil_GetOriginalFileName(wFullName, vmid);
									name = wFullName;
								}
							}
						}							
					}
		
				
					swprintf(log, L"    NtWriteFile(%d, %x %s, buffer: %x, Leng: %d, Off: %x, write: %d, %x)\r\n",(ULONG)PsGetCurrentProcessId(), FileHandle, name, Buffer, Length, ByteOffset, IoStatusBlock->Information, rc);
					ZwWriteFile(pvms[vmid]->logHandle, NULL, NULL, NULL, &Iosb, (void*)log, wcslen(log)*sizeof(WCHAR), NULL, NULL);
					if(wFullName)
						ExFreePool(wFullName);
				}
				
				
			}
			*/

if (FileHandle){
			
			KPROCESSOR_MODE mode;
			mode = ExGetPreviousMode();
			
		
			if (mode != KernelMode && vmid != INVALID_VMID) {
				PWCHAR wFullName = NULL;
				PWCHAR name = NULL;
				char * logs;
				IO_STATUS_BLOCK Iosb;
				FILE_FS_DEVICE_INFORMATION device_info;
				PWCHAR nptr;
				//BOOLEAN isRemovable = FALSE; 
/*
				if (NT_SUCCESS(
					ZwQueryVolumeInformationFile( FileHandle, &Iosb, 
					&device_info, sizeof(device_info), FileFsDeviceInformation )) &&
					(device_info.Characteristics & FILE_REMOVABLE_MEDIA)){
					DbgPrint("Writing to removable media\n");
					isRemovable = TRUE;
				}
*/
				
				wFullName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
				logs = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
				if (wFullName == NULL || logs == NULL) {
					DbgPrint("NtClose: ExAllocateFromPagedLookasideList fail\n");  
				}
				else{
					wFullName[0] = L'\0';
					if (FvmUtil_PathFromHandle(FileHandle, NULL, wFullName)) {
						if ( wFullName[0] != L'\0'){
							if (wFullName[1]==L'R' && wFullName[2] == L'E' && wFullName[3] == L'G')
								name = NULL;// wcsstr(wFullName, L"Registry");
							else{
								FvmUtil_GetOriginalFileName(wFullName, PATHSIZE, vmid);
								name = wFullName;
							}
						}
					}							
				}
				nptr = (PWCHAR) logs;
				FvmUtil_GetBinaryPathName(nptr);
				if(!wcsstr(nptr, L"fvmshell.exe")){
					ticks tm = getticks();
					RtlStringCbPrintfA(logs, PATHSIZE, "%I64u, NtWriteFile, %u, %u, %S, %u, %u, %u, %u, %u\r\n",
						tm.QuadPart, (ULONG)PsGetCurrentProcessId(), FileHandle, name, Buffer, Length, ByteOffset, 
						IoStatusBlock->Information, rc);								
					ZwWriteFile(pvms[vmid]->logHandle, NULL, NULL, NULL, &Iosb, (void*)logs, strlen(logs)*sizeof(char), NULL, NULL);
				}
				if(wFullName)
					ExFreePool(wFullName);
				if(logs)
					ExFreePool(logs);
				
			}
			
			
		}

#endif

	return rc;
}


/*
 *-----------------------------------------------------------------------------
 *
 * FvmFile_NtQueryAttributesFile --
 *
 *      This function is the FVM-provided ID_NTQUERYATTRIBUTESFILE system call
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
FvmFile_NtQueryAttributesFile(IN POBJECT_ATTRIBUTES ObjectAttributes,
                              OUT PFILE_BASIC_INFORMATION FileInformation)
{
	NTSTATUS rc;
	POBJECT_ATTRIBUTES objAttrPtr = NULL;
	ULONG vmId = INVALID_VMID;
	PWCHAR fnPtr = NULL;
	ULONG memSize = _MAX_PATH*2, memSizeFvm = _MAX_PATH*2;
	POBJECT_ATTRIBUTES fvmObjPtr = NULL;
       PWCHAR fileLinkName=NULL;
	PWCHAR vDirName=NULL;
          
	InterlockedIncrement(&fvm_Calls_In_Progress);

	objAttrPtr = ObjectAttributes;
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		PWCHAR binPath = NULL;
	/*	WCHAR fileLinkName[_MAX_PATH*2];
		WCHAR vDirName[_MAX_PATH*2];*/
		PWCHAR hostName, fvmName = NULL;
        
              fileLinkName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (fileLinkName == NULL) {
                     DbgPrint("FvmFile_NtOpenFile: ExAllocateFromPagedLookasideList fail\n");  
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
              vDirName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (vDirName == NULL) {
                     DbgPrint("FvmFile_NtOpenFile: ExAllocateFromPagedLookasideList fail\n"); 
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
              
		if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
			goto winSysCall;
		}
		//DbgPrint(".........> %S\n", fileLinkName);
		if (!FvmIsLocalFileAccess(fileLinkName, vmId)) {
		 BOOLEAN ddofsAccess=FALSE;
			
			FvmFile_AllowDeviceAccess(fileLinkName,vmId, &ddofsAccess);
			if (!ddofsAccess)
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

			if (FvmTable_FVMFileListLookup(fnPtr + 4, vmId)) {
				goto winSysCall;
			} else {
				objAttrPtr = NULL;
				rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, fnPtr,
						&objAttrPtr, &memSize);

				if (!NT_SUCCESS(rc)) {
					rc = STATUS_OBJECT_PATH_NOT_FOUND;
					goto ntExit;
				}
				hostName = fnPtr;
				fvmName = fileLinkName;

				goto hostQuery;
			}
		} else {
			fnPtr = NULL;
			hostName = fileLinkName;

			if (!FvmTable_FVMFileListLookup(hostName + 4, vmId)) {
				goto hostQuery;
			} else {
				if (!FvmFile_MapPath(hostName, vmId, vDirName)) {
					goto winSysCall;
				}
				fvmName = vDirName;

				rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
						&fvmObjPtr, &memSizeFvm);

				if (!NT_SUCCESS(rc)) {
					goto winSysCall;
				}

				rc = (winNtQueryAttributesFileProc)(fvmObjPtr,
						FileInformation);
				goto ntExit;
			}
		}

#if DBG_QUERYATTRIBUTESFILE
		binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2,
		    FVM_FILEOPT_POOL_TAG);
		if (binPath == NULL) {
			goto winSysCall;
		}
		FvmUtil_GetBinaryPathName(binPath);
		DbgPrint("ID_NTQUERYATTRIBUTESFILE : Application Name - %S\n", binPath);
		ExFreePool(binPath);
		DbgPrint("               Arguments - %S\n", hostName);
		DbgPrint("               New file name - %S\n", fvmName);
#endif

hostQuery:
        /*
         * The file to be accessed does not exist on the VM's workspace.
         * We need to check if it has been deleted before accessing it
         * from the host environment.
         */

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
       if (fileLinkName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, fileLinkName );
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
FvmFile_NtQueryFullAttributesFile(IN POBJECT_ATTRIBUTES ObjectAttributes,
                                  OUT PFILE_NETWORK_OPEN_INFORMATION
                                  		FileInformation)
{
	NTSTATUS rc;
	POBJECT_ATTRIBUTES objAttrPtr = NULL, fvmObjPtr = NULL;
	ULONG memSize = _MAX_PATH*2, memSizeFvm = _MAX_PATH*2;
	ULONG vmId = INVALID_VMID;
	PWCHAR fnPtr = NULL;
       PWCHAR fileLinkName= NULL;
       PWCHAR vDirName= NULL;

	InterlockedIncrement(&fvm_Calls_In_Progress);

	objAttrPtr = ObjectAttributes;
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		PWCHAR binPath = NULL;
/*		WCHAR fileLinkName[_MAX_PATH*2];
		WCHAR vDirName[_MAX_PATH*2];*/
		PWCHAR hostName, fvmName = NULL;
              fileLinkName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (fileLinkName == NULL) {
                     DbgPrint("FvmFile_NtOpenFile: ExAllocateFromPagedLookasideList fail\n");  
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
              vDirName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (vDirName == NULL) {
                     DbgPrint("FvmFile_NtOpenFile: ExAllocateFromPagedLookasideList fail\n"); 
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
		if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
			goto winSysCall;
		}
		if (!FvmIsLocalFileAccess(fileLinkName, vmId)) {
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

			if (FvmTable_FVMFileListLookup(fnPtr + 4, vmId)) {
				goto winSysCall;
			} else {
				objAttrPtr = NULL;
				rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, fnPtr,
						&objAttrPtr, &memSize);

            	if (!NT_SUCCESS(rc)) {
					rc = STATUS_OBJECT_PATH_NOT_FOUND;
					goto ntExit;
				}
				hostName = fnPtr;
				fvmName = fileLinkName;

				goto hostQuery;
			}
		} else {
			fnPtr = NULL;
			hostName = fileLinkName;

			if (!FvmTable_FVMFileListLookup(hostName + 4, vmId)) {
				goto hostQuery;
			} else {
				if (!FvmFile_MapPath(hostName, vmId, vDirName)) {
					goto winSysCall;
				}
				fvmName = vDirName;

				rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
						&fvmObjPtr, &memSizeFvm);

				if (!NT_SUCCESS(rc)) {
					goto winSysCall;
				}

				rc = (winNtQueryFullAttributesFileProc)(fvmObjPtr,
						FileInformation);

				goto ntExit;
			}
		}

#if DBG_QUERYFULLATTRIBUTESFILE
		binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2,
		    FVM_FILEOPT_POOL_TAG);
		if (binPath == NULL) {
			goto winSysCall;
		}
		FvmUtil_GetBinaryPathName(binPath);
		DbgPrint("NtQueryFullAttributesFile : Application Name - %S\n",
				binPath);
		ExFreePool(binPath);

		DbgPrint("               Arguments - %S\n", hostName);
		DbgPrint("               New file name - %S\n", fvmName);
#endif

hostQuery:
        /*
         * The file to be accessed does not exist on the VM's workspace.
         * We need to check if it has been deleted before accessing it
         * from the host environment.
         */

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
       if (fileLinkName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, fileLinkName );
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
FvmFile_NtDeleteFile(IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	NTSTATUS rc;
	ULONG vmId = INVALID_VMID;
	POBJECT_ATTRIBUTES objAttrPtr = NULL, fvmObjPtr = NULL;
	ULONG memSize = _MAX_PATH*2, memSizeFvm = _MAX_PATH*2;
	PWCHAR fnPtr = NULL;
	BOOLEAN logFlag = FALSE;
	PWCHAR hostName = NULL, fvmName = NULL;
    PWCHAR fileLinkName= NULL;
	PWCHAR vDirName= NULL;

	InterlockedIncrement(&fvm_Calls_In_Progress);

	objAttrPtr = ObjectAttributes;
	vmId = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if (vmId != INVALID_VMID) {
		PWCHAR binPath = NULL;
//		WCHAR fileLinkName[_MAX_PATH*2];
//		WCHAR vDirName[_MAX_PATH*2];
		PFILE_BASIC_INFORMATION fileBasicInfoPtr = NULL;
		ULONG memSize1;

              fileLinkName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (fileLinkName == NULL) {
                     DbgPrint("FvmFile_NtOpenFile: ExAllocateFromPagedLookasideList fail\n");  
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
              vDirName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
              if (vDirName == NULL) {
                     DbgPrint("FvmFile_NtOpenFile: ExAllocateFromPagedLookasideList fail\n"); 
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}
              
		if (!FvmUtil_GetSysCallArgument(ObjectAttributes, fileLinkName)) {
			goto winSysCall;
		}

		DbgPrint(".............> %S\n", fileLinkName);
		if (!FvmIsLocalFileAccess(fileLinkName, vmId)) {
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

			if (FvmTable_FVMFileListLookup(fnPtr + 4, vmId)) {
				logFlag = TRUE;
				goto winSysCall;
			} else {
				objAttrPtr = NULL;
				rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, fnPtr,
						&objAttrPtr, &memSize);

				if (!NT_SUCCESS(rc)) {
					rc = STATUS_ACCESS_DENIED;
					goto ntExit;
				}
				hostName = fnPtr;
				fvmName = fileLinkName;

				goto hostQuery;
			}
		} else {
			fnPtr = NULL;
			hostName = fileLinkName;

			if (!FvmTable_FVMFileListLookup(hostName + 4, vmId)) {
				goto hostQuery;
			} else {
				if (!FvmFile_MapPath(hostName, vmId, vDirName)) {
					rc = STATUS_ACCESS_DENIED;
					goto ntExit;
				}
				fvmName = vDirName;

				rc = FvmUtil_InitializeVMObjAttributes(ObjectAttributes, vDirName,
						&fvmObjPtr, &memSizeFvm);

				if (!NT_SUCCESS(rc)) {
					goto ntExit;
				}

				rc = (winNtDeleteFileProc)(fvmObjPtr);

				if (NT_SUCCESS(rc)) {
					/*
					 * Add the file path (virtual path) into the delete
					 * log. Also remove the path from the VM's private
					 * file tree in memory.
					 */

					FvmTable_DeleteLogAdd(hostName, vmId);
					FvmTable_FVMFileListDelete(hostName + 4, vmId);
				}
				goto ntExit;
			}
		}

#if DBG_DELETEFILE
		binPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2,
		    FVM_FILEOPT_POOL_TAG);
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

hostQuery:
        /*
         * Check if the file has already been deleted (in the DeleteLog)
         * before.
         */

		if (FvmTable_DeleteLogLookup(hostName, vmId)) {
			rc = STATUS_OBJECT_PATH_NOT_FOUND;
			goto ntExit;
		}

		memSize1 = sizeof(FILE_BASIC_INFORMATION);
		rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr,
				0, &memSize1, MEM_COMMIT, PAGE_READWRITE);

		if (!NT_SUCCESS(rc)) {
			rc = STATUS_ACCESS_DENIED;
			goto ntExit;
		}

        /*
         * We use ID_NTQUERYATTRIBUTESFILE to find out if the file exists
         * on the host environment.
         */

		rc = (winNtQueryAttributesFileProc)(objAttrPtr, fileBasicInfoPtr);

        memSize1 = 0;
		FvmVm_FreeVirtualMemory(NtCurrentProcess(), &fileBasicInfoPtr, &memSize1,
				MEM_RELEASE);

		if (NT_SUCCESS(rc)||(rc != STATUS_OBJECT_PATH_NOT_FOUND
				&& rc != STATUS_OBJECT_NAME_NOT_FOUND)) {
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
     * If the file to be deleted exists in the VM's workspace, we can delete
     * it and then update the DeleteLog.
     */

	rc = (winNtDeleteFileProc)(objAttrPtr);

	if (logFlag && NT_SUCCESS(rc) && hostName) {
		FvmTable_DeleteLogAdd(hostName, vmId);
		FvmTable_FVMFileListDelete(hostName + 4, vmId);
	}

ntExit:
	if (vmId != INVALID_VMID){		
		
#ifdef logNtDeleteKey
		WCHAR *logFileName = L"NULL";
		IO_STATUS_BLOCK Iosb;
		KPROCESSOR_MODE mode;
		NTSTATUS lrc;
		WCHAR *nptr;
						
		mode = ExGetPreviousMode(); 	
										
		if (mode != KernelMode) {
			FvmUtil_GetBinaryPathName(vDirName);
								
			if(pvms[vmId]->logHandle && !wcsstr(vDirName, L"fvmshell.exe")){
				ticks tm;
				char *p = (char *)vDirName;
				if (fileLinkName){
					logFileName = fileLinkName;
				}
				tm = getticks();
				RtlStringCbPrintfA(p, PATHSIZE, "%I64u, NtDeleteFile, %u, %S, %u\r\n", 
					tm.QuadPart, (ULONG)PsGetCurrentProcessId(), fileLinkName,  rc);						
				lrc = ZwWriteFile(pvms[vmId]->logHandle, NULL, NULL, NULL, &Iosb, (void*)p, strlen(p)*sizeof(char), NULL, NULL);								
			}
		}											
#endif


		
		

		
	}
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
       if (fileLinkName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, fileLinkName );
	}     
       if (vDirName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vDirName );
	}  

	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}

#endif // ifdef USE_FS_MAP
