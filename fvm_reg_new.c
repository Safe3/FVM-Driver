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

#include <ntddk.h>
#include <stdlib.h>
#include "fvm_util.h"
#include "fvm_table.h"
#include "hooksys.h"
#include "fvm_vm.h"
#include "fvm_syscalls.h"
#include "fvm_reg.h"

#define FVM_REG_POOL_TAG '5GAT'

void FvmReg_CopyKey(	HANDLE KeyHandle, int vmn);

//======================================================================
//  R E G I S T R Y  P A R A M E T E R  S U P P O R T  R O U T I N E S
//======================================================================

/*
 * GetPointer
 *
 * Translates a handle to an object pointer.
 */
static POBJECT
GetPointer(HANDLE Handle) {
	POBJECT pKey = NULL;

	/*
	 * Ignore null handles.
	 */
	if (!Handle) return NULL;

	/*
	 * Make sure that we're not going to access
	 * the kernel handle table from a non-system process
	 */
	if ((LONG)(ULONG_PTR)Handle < 0 &&
	    ExGetPreviousMode() != KernelMode) {
		return NULL;
	}

	/*
	 * Get the pointer the handle refers to.
	 */
	ObReferenceObjectByHandle( Handle,
	    0, NULL, KernelMode, &pKey, NULL);
	return pKey;
}


/*
 * Dereference the object.
 */
static VOID
ReleasePointer(POBJECT Object) {
	if (Object) ObDereferenceObject(Object);
}


/*
 * this function return the full path of the virtual and host registry
 */
static int
GetFullRegName(
	HANDLE KeyHandle,
	PUNICODE_STRING LpszSubKeyVal,
	PWCHAR OrigName,
	PWCHAR VirName,
	PWCHAR TempBuffer,
	int Vmn) {

	POBJECT	pKey = NULL;
	PUNICODE_STRING	fullUniName = (PUNICODE_STRING)TempBuffer;

	PWCHAR	wPtr;
	ULONG	actualLen;
	ULONG	_length = 256;
	PISID	sid;
	NTSTATUS	rc;

	int	initial = 0;

	/*
	 * Is it a valid handle ?
	 */
	if (pKey = GetPointer(KeyHandle)) {
		if (pKey) {
			fullUniName->MaximumLength = MAXPATHLEN * sizeof(WCHAR);

			if (NT_SUCCESS(ObQueryNameString(pKey, fullUniName,
			    MAXPATHLEN, &actualLen))) {
				wcscat(OrigName, fullUniName->Buffer);
			}
			ReleasePointer(pKey);
		}
	}

	try {
		if (LpszSubKeyVal) {

			if (LpszSubKeyVal->Buffer[0] != L'\\')
				wcscat(OrigName, L"\\");
			wcsncat(OrigName, LpszSubKeyVal->Buffer, LpszSubKeyVal->Length/2);

			/*
			 * if a registry name contains vm strid, then it is a path in vm
			 */
			if (wcsstr(OrigName, pvms[Vmn]->idStr)) {

				wcsncpy(VirName, OrigName, wcslen(OrigName)+1);

				wPtr = wcsstr(VirName, pvms[Vmn]->idStr);


				wPtr = wcschr(wPtr, L'\\');
				/*
				 * The original location.
				 */
				wcsncpy(OrigName, wPtr, wcslen(wPtr)+1);

				initial = 1;
			} else {
				_length = 1024;

				wcscpy(TempBuffer, pvms[Vmn]->SidStr);

				swprintf(VirName, L"\\REGISTRY\\USER\\%s\\fvms\\%s%s",
					TempBuffer, pvms[Vmn]->idStr, OrigName);
			}

		}
	}except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in GetRegFullName\n"));
		return initial;
	}
	return initial;
}


/*
 * FVM REGISTRY HOOK ROUTINES..
 */

PWCHAR sees_value_name = L"SEES_INITIAL";

#define SEES_VALUE_NAME L"SEES_INITIAL"
#define SEES_VALUE_NAME_LEN 12
#define SEES_VALUE_NAME_LEN_A 32


NTSTATUS
FvmReg_NtOpenKey
(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK ReqAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
) {
	NTSTATUS	ntStatus;
	HANDLE	procHandle;
	NTSTATUS	rc;
	int	size;
	POBJECT_ATTRIBUTES	pObjectAttributes=NULL;
	PUNICODE_STRING	pObjectName;
	PKEY_VALUE_FULL_INFORMATION	pValueFullInfo;
	PHANDLE	pTempHandle;
	PHANDLE	pTempHandle1;
	PULONG	pTempSize;
	PWCHAR	pVirName;
	PWCHAR	pOriName;
	PWCHAR	pTempBuffer;
	PKEY_BASIC_INFORMATION	pKeyBasicInfo;
	int	vmn;
	ULONG	TitleIndex = 0;
	PUNICODE_STRING	Class = NULL;
	PULONG	Disposition = NULL;
	ULONG	createOptions = REG_OPTION_NON_VOLATILE;
	ULONG	working;
	PWCHAR	pPointer;
	WCHAR	cSave;
	ULONG	virNameLen;
	PULONG	sv;
	PWCHAR	rp;
	int nprt = FALSE;
	
	InterlockedIncrement(&fvm_Calls_In_Progress);
	try {
	
		/*
		 * Get the virtual machine number
		 */
		vmn = FvmVm_GetPVMId((ULONG) PsGetCurrentProcessId());
		
		if (vmn == INVALID_VMID) {
			/*
			 * The corruent process is not under a VM
			 */
			rc = winNtOpenKeyProc( KeyHandle, ReqAccess, ObjectAttributes);
			goto NtExit;
		}
/* #ifdef RPCSS
		if(FvmVm_isRpcssProcess((ULONG)PsGetCurrentProcessId(),vmn)){
			rc = winNtOpenKeyProc( KeyHandle, ReqAccess, ObjectAttributes);
			goto NtExit;
		}
#endif */




		/*
		 * Allocate virtual memory from the process user space
		 */
		size = 16384+1024*1024; /* 4 pages + 1MB */
		procHandle = NtCurrentProcess();

		pObjectAttributes = NULL;
		rc = FvmVm_AllocateVirtualMemory(procHandle, &pObjectAttributes, 0, &size,
			    MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (rc != STATUS_SUCCESS) {
			DbgPrint("--memory allocation problem(%d,NtOpenKey)\n",(ULONG)PsGetCurrentProcessId());
			goto NtExit;
		}
		

		(char *)pObjectName = ((char *)pObjectAttributes ) +
			    sizeof(OBJECT_ATTRIBUTES);
		(char *)pValueFullInfo = ((char *)pObjectName) +
		    sizeof(UNICODE_STRING);
		(char *)pTempHandle = ((char *)pValueFullInfo) + 4096+1024*1024;
		(char *)pTempHandle1 = ((char *)pTempHandle) + sizeof(HANDLE);
		(char *)pTempSize = ((char *)pTempHandle1) + sizeof(HANDLE);
		(char *)pOriName = ((char *)pTempSize) + sizeof(ULONG);
		(char *)pVirName = ((char *)pOriName) + 4096;
		(char *)pTempBuffer = ((char *)pVirName) + 4096;

		/*
		 * Get the orignal and the virtual name of the registry key
		 */
	
		pOriName[0] = L'\0';
		pVirName[0] = L'\0';

		
		GetFullRegName( ObjectAttributes->RootDirectory,
		    ObjectAttributes->ObjectName, pOriName, pVirName,
		    pTempBuffer, vmn);
		//DbgPrint("++++ OpenRegKey: %S\n", pOriName);
		if (ExGetPreviousMode() == KernelMode) {
				nprt = TRUE;
			DbgPrint("Kernel level -- OpenRegKey: %S\n", pOriName);
		
			rc = winNtOpenKeyProc( KeyHandle, ReqAccess, ObjectAttributes);
		
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,   MEM_RELEASE);
			goto NtExit;
			}

		/*
		if (wcsstr(pOriName, L"Classes\\CLSID")){
	
			nprt = TRUE;
			DbgPrint("++++ OpenRegKey: %S\n", pOriName);
		
			rc = winNtOpenKeyProc( KeyHandle, ReqAccess, ObjectAttributes);
		
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,   MEM_RELEASE);
			goto NtExit;
	
			}
			*/
#if 0
	/*
		if (wcsstr(pOriName, L"Software\\Microsoft"))
							goto vl;
							*/

		//if (wcsstr(pOriName, L"Office")== NULL)
			//		goto vl;
		

 		if (wcsstr(pOriName, L"\\REGISTRY\\MACHINE"))
			goto vl;

		if (wcsstr(pOriName, L"machine"))
					goto vl;

		if (wcsstr(pOriName, L"Machine"))
							goto vl;

		if (wcsstr(pOriName, L"Current"))
								goto vl;

		//if (wcsstr(pOriName, L"Office"))
		//	goto vl;

		if (wcsstr(pOriName, L"Execution"))
					goto vl;
		
		if (wcsstr(pOriName, L"Classes"))
					goto vl;
	
		if(wcsstr(pOriName, L"Control"))
					goto vl;
		if(wcsstr(pOriName, L"IME"))
					goto vl;
		if(wcsstr(pOriName, L"Assistant"))
					goto vl;
		
			if(wcsstr(pOriName, L"Common"))
					goto vl;

			if(wcsstr(pOriName, L"CTF"))
					goto vl;
			if(wcsstr(pOriName, L"Products"))
					goto vl;

			if(wcsstr(pOriName, L"Features"))
					goto vl;
		
		nprt = TRUE;
		//DbgPrint("++++ OpenRegKey: %S\n", pOriName);
		

			nprt = TRUE;
		DbgPrint("++++ OpenRegKey: %S\n", pOriName);
		rc = winNtOpenKeyProc( KeyHandle, ReqAccess, ObjectAttributes);
		size = 0;
		FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
			    MEM_RELEASE);
		
		goto NtExit;

			
vl:
#endif
	
		rp = wcschr(pOriName, L'\\');
		if (rp) {
			rp++;
			rp = wcschr(rp, L'\\');
		}
		if (rp) {
		  rp++;
		  rp = wcschr(rp, L'\\');
		}
		if (rp) {
		  rp++;
		  rp = wcschr(rp, L'\\');
		}

		if (rp && _wcsnicmp(rp,
		    L"\\Software\\Microsoft\\SystemCertificates\\root\\ProtectedRoots",
		    58) == 0) {

			pObjectName->MaximumLength = 2048;
			pObjectName->Length = wcslen(pOriName)*2;
			pObjectName->Buffer = pOriName;

			InitializeObjectAttributes(pObjectAttributes, pObjectName,
				    OBJ_CASE_INSENSITIVE, NULL, NULL );

			rc = winNtOpenKeyProc(KeyHandle, ReqAccess,  pObjectAttributes);

			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
				    MEM_RELEASE);
			goto NtExit;
		}
		
		if(FvmVm_CheckClsid((ULONG)PsGetCurrentProcessId(), pOriName)==TRUE){
					pObjectName->MaximumLength = 2048;
					pObjectName->Length = wcslen(pOriName)*2;
					pObjectName->Buffer = pOriName;
		
					InitializeObjectAttributes(pObjectAttributes, pObjectName,
							OBJ_CASE_INSENSITIVE, NULL, NULL );
		
					rc = winNtOpenKeyProc(KeyHandle, ReqAccess,  pObjectAttributes);
		
					size = 0;
					DbgPrint("winNtOpenKeyProc donot virtualize key %S\n",pOriName);
					FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
							MEM_RELEASE);			
					goto NtExit;			
		}

		/*
		 * Try to open the key from the virtual machine first
		 */
		pObjectName->Length = wcslen(pVirName)*2;
		pObjectName->Buffer = pVirName;
		InitializeObjectAttributes(pObjectAttributes, pObjectName,
			    OBJ_CASE_INSENSITIVE, NULL, NULL );

		ntStatus = winNtOpenKeyProc(KeyHandle, KEY_ALL_ACCESS,
			    pObjectAttributes);

		/*
		 * Key is in VM
		 */
	    if (ntStatus == STATUS_SUCCESS) {
			wcscpy((PWCHAR) pTempBuffer, SEES_VALUE_NAME);
			pObjectName->Buffer = pTempBuffer;
			pObjectName->Length = (USHORT) SEES_VALUE_NAME_LEN*2;
			pObjectName->MaximumLength = (USHORT) SEES_VALUE_NAME_LEN*2;

			rc = winNtQueryValueKeyProc(*KeyHandle, pObjectName,
				    KeyValueFullInformation, pValueFullInfo, 4096, pTempSize);

			/*
			 * Copy subkeys
			 */
			if (rc == STATUS_SUCCESS) {
				winNtDeleteValueKeyProc(*KeyHandle, pObjectName);
			} else {
				size = 0;
				FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
				    MEM_RELEASE);
				rc = ntStatus;
				goto NtExit;
	      }
		}

		if (ntStatus != STATUS_SUCCESS) {
			/*
			 * Could not find the key in the VM.
			 * See if it is in the original location.
			 */
			pObjectName->Length = wcslen(pOriName)*2;

			pObjectName->MaximumLength = 2048;
			pObjectName->Buffer = pOriName;
			InitializeObjectAttributes(pObjectAttributes, pObjectName,
			    OBJ_CASE_INSENSITIVE, NULL, NULL);
			ntStatus = winNtOpenKeyProc(KeyHandle, ReqAccess, pObjectAttributes);

			if ((ntStatus != STATUS_SUCCESS)||(_wcsicmp(pOriName,
			    SERVICE_KEY) == 0)) {
				/*
				 * The original location does not have the key. return.
				 */
				size = 0;
				rc = FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
					    MEM_RELEASE);
				rc = ntStatus;
				goto NtExit;
			}

			/*
			 * Found the key in the original location, copy it to our
			 * virtual machine
			 */
			working = 0;
			pObjectName->Length = wcslen(pVirName)*2;
			pObjectName->MaximumLength = 4096;
			pObjectName->Buffer = pVirName;
			InitializeObjectAttributes(pObjectAttributes, pObjectName,
			    OBJ_CASE_INSENSITIVE, NULL, NULL);

			/*
			 * We create all keys on the path
			 */
			pPointer = pVirName+1;

			/*
			 * To prevent dos attack, we only permit a path has no more than 100
			 * subkeys
			 */
			while (working < 3000) {

				working++;
				pPointer = wcschr(pPointer, L'\\');

				if (!pPointer) {
					/*
					 * Last sub key on the path
					 */
					pObjectName->Length = wcslen(pVirName) * 2;
					pObjectName->Buffer = pVirName;
					pObjectName->MaximumLength = 4096;

					if (*KeyHandle)
						winNtCloseProc(*KeyHandle);

					Disposition = (PULONG)pTempBuffer;
					ntStatus = winNtCreateKeyProc(KeyHandle, KEY_ALL_ACCESS,
							    pObjectAttributes, TitleIndex, Class,
							    createOptions, Disposition);

					/*
					 * We have trouble to create the
					 * key on the virtual machine
					 */
					if (ntStatus != STATUS_SUCCESS) {
					    size = 0;
						rc = FvmVm_FreeVirtualMemory(procHandle,
							    &pObjectAttributes, &size, MEM_RELEASE);
						rc = ntStatus;
						goto NtExit;
					}
					/*
					 * This is the last key. Exit the loop.
					 */
					break;
				} else {
					cSave = *pPointer;
					*pPointer = L'\0';
					pObjectName->Length = wcslen(pVirName)*2;
					pObjectName->Buffer = pVirName;
					pObjectName->MaximumLength=4096;

					if (*KeyHandle)
						winNtCloseProc(*KeyHandle);

					Disposition = (PULONG)pTempBuffer;
					ntStatus = winNtCreateKeyProc(KeyHandle, KEY_ALL_ACCESS,
							    pObjectAttributes,  TitleIndex, Class,
							    createOptions,Disposition );

					if (ntStatus == STATUS_SUCCESS &&
					    *Disposition ==REG_CREATED_NEW_KEY) {
						sv = (ULONG *)(pTempBuffer+SEES_VALUE_NAME_LEN_A);
						*sv = 0;
						wcscpy((PWCHAR)pTempBuffer, SEES_VALUE_NAME);
						pObjectName->Buffer = pTempBuffer;
						pObjectName->Length = (USHORT)SEES_VALUE_NAME_LEN*2;
						pObjectName->MaximumLength =
						    (USHORT)SEES_VALUE_NAME_LEN * 2;
						winNtSetValueKeyProc(*KeyHandle, pObjectName,  1,
							REG_DWORD, sv, sizeof(ULONG));
					}
					*pPointer = cSave;
					pPointer++;
				}
			}
		}

	    /*
		 *  Copy the values.
		 */
		pObjectName->Length = wcslen(pOriName) * 2;

		pObjectName->MaximumLength = 2048;
		pObjectName->Buffer = pOriName;
		InitializeObjectAttributes(pObjectAttributes, pObjectName,
				    OBJ_CASE_INSENSITIVE, NULL, NULL);

	    rc = winNtOpenKeyProc(pTempHandle, KEY_QUERY_VALUE, pObjectAttributes);

		if (rc == STATUS_SUCCESS) {
			int index = 0;
			working = 0;
			while (working < 5000) {
				working++;
				rc = winNtEnumerateValueKeyProc(*pTempHandle, index,
					    KeyValueFullInformation, pValueFullInfo,
					    4096 + 1024 * 1024, pTempSize);
				if (rc != STATUS_SUCCESS) {
					break;
				} else {
					/*
					 * Do the copying.
					 */
					
					pObjectName->Buffer = pValueFullInfo->Name;
					pObjectName->Length = (USHORT)pValueFullInfo->NameLength;
					pObjectName->MaximumLength =
					    (USHORT)pValueFullInfo->NameLength;

					rc = winNtSetValueKeyProc(*KeyHandle, pObjectName,
						    pValueFullInfo->TitleIndex, pValueFullInfo->Type,
						    (PVOID)( pValueFullInfo->DataOffset +
						    ((char *)pValueFullInfo)),
						    pValueFullInfo->DataLength);
					 if (wcsstr(pOriName, L"PowerPoint")){
						pObjectName->Buffer[pObjectName->Length/2] = L'\0';						
					 }
				}
				index++;
			}
	    } else {
	            size = 0;
				rc = FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
					    MEM_RELEASE);
				if (*KeyHandle) {
					winNtCloseProc(*KeyHandle);
					*KeyHandle = 0;
				}
				rc = ntStatus;
				goto NtExit;
	    }

		if (*pTempHandle) {
			winNtCloseProc(*pTempHandle);
		}

	    /*
		 * Copy subkeys
		 */
#if 0
		if (_wcsnicmp(pOriName, L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES",wcslen(L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES")) !=0){
			pObjectName->Length = wcslen(pOriName) * 2;
			pObjectName->MaximumLength = 2048;
			pObjectName->Buffer = pOriName;
			InitializeObjectAttributes(pObjectAttributes, pObjectName,
			    OBJ_CASE_INSENSITIVE, NULL, NULL);
	    	rc = winNtOpenKeyProc(pTempHandle, KEY_ENUMERATE_SUB_KEYS,
			    pObjectAttributes);

			pKeyBasicInfo = (PKEY_BASIC_INFORMATION )pValueFullInfo;

			if (rc == STATUS_SUCCESS) {
				int index = 0;
				working = 0;

				virNameLen = wcslen(pVirName);
				while (working < 3000) {
					working++;
					rc = winNtEnumerateKeyProc(*pTempHandle, index,
					    KeyBasicInformation, pKeyBasicInfo, 4096, pTempSize);

					if (rc != STATUS_SUCCESS) {
						break;
					} else {
						pKeyBasicInfo->Name[pKeyBasicInfo->NameLength/2] = L'\0';

						pVirName[virNameLen] = L'\\';
					 	pVirName[virNameLen+1] = L'\0';
					 	wcscat(pVirName, pKeyBasicInfo->Name);
					 	pObjectName->Length = wcslen(pVirName) * 2;
					 	pObjectName->MaximumLength = 4096;
					 	pObjectName->Buffer =  pVirName;
					 	InitializeObjectAttributes(pObjectAttributes, pObjectName,
						    OBJ_CASE_INSENSITIVE, NULL, NULL );
						if (*KeyHandle)
							winNtCloseProc(*KeyHandle);

					 	Disposition = (PULONG)pTempBuffer;
					 	rc = winNtCreateKeyProc(pTempHandle1, KEY_ALL_ACCESS,
						    pObjectAttributes, TitleIndex, Class,
						    createOptions, Disposition);

						if (rc == STATUS_SUCCESS && *Disposition ==
					    	REG_CREATED_NEW_KEY) {
							sv = (ULONG *)(pTempBuffer + SEES_VALUE_NAME_LEN_A);
							*sv = 0;
							wcscpy((PWCHAR)pTempBuffer, SEES_VALUE_NAME);
							pObjectName->Buffer = pTempBuffer;
							pObjectName->Length = (USHORT)SEES_VALUE_NAME_LEN * 2;
							pObjectName->MaximumLength =
						    (USHORT)SEES_VALUE_NAME_LEN * 2;
							winNtSetValueKeyProc(*pTempHandle1, pObjectName, 0,
						    REG_DWORD, sv, sizeof(ULONG));
						}
					}
					index++;
				}
				pVirName[virNameLen] = L'\0';
			} else {
				size = 0;
				FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
			    	MEM_RELEASE);

				if (*KeyHandle) {
					winNtCloseProc(*KeyHandle);
					*KeyHandle = 0;
				}
				rc = ntStatus;
				goto NtExit;
	    	}
		}
#endif

		/*
		 * Everything is set up.  Open the key from the virtual machine.
		 */
		if (*KeyHandle) {
			winNtCloseProc(*KeyHandle);
			*KeyHandle = 0;
		}
		if (*pTempHandle) {
			winNtCloseProc(*pTempHandle);
		}

		pObjectName->Length = wcslen(pVirName) * 2;
		pObjectName->MaximumLength = 4096;
		pObjectName->Buffer = pVirName;
		InitializeObjectAttributes(pObjectAttributes, pObjectName,
			    OBJ_CASE_INSENSITIVE, NULL, NULL);

		rc = winNtOpenKeyProc(KeyHandle, ReqAccess, pObjectAttributes);

		size = 0;
		FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
			    MEM_RELEASE);
		goto NtExit;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FvmReg_NtOpenKey\n"));
		rc = -1;
	}
 NtExit:
	/*
	if (vmn != INVALID_VMID) {
		DbgPrint("OpenRegKey: %x\n", rc);
	}*/
	//if(nprt)
	//	DbgPrint("OpenRegKey: %x %x\n", rc, *KeyHandle);
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}


NTSTATUS
FvmReg_NtCreateKey
(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK ReqAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class,
	IN ULONG CreateOptions,
	OUT PULONG Disposition
) {
	NTSTATUS	ntStatus;
	NTSTATUS	rc, rc2;
	HANDLE	procHandle;
	ULONG	virNameLen;
	PKEY_BASIC_INFORMATION	pKeyBasicInfo;
	int	vmn;
	int	size;
	int	initial;
	ULONG	sees_value;
	int	index;
	ULONG	working;
	PWCHAR	pPointer;
	WCHAR	cSave;
	PULONG	sv;

	/*
	 * All of these pointers point to some virtual memory in the user space.
	 * Micro$oft NT system calls require that all OUT parameters must be in
	 * user space. Since we are working on the behalf of the process, we need to
	 * use a undocumented function ZwAllocationVirtualMemory to allocate some
	 * virtual memory in user space to satisfy this requirement.
	 */

	POBJECT_ATTRIBUTES	pObjectAttributes;
	PUNICODE_STRING	pObjectName;
	PKEY_VALUE_FULL_INFORMATION	pValueFullInfo;
	PHANDLE	pTempHandle1;
	PHANDLE	pTempHandle;
	PULONG	pTempSize;
	PWCHAR	pOriName;
	PWCHAR	pVirName;
	PWCHAR	pTempBuffer;
	WCHAR Name[MAXPROCNAMELEN];

	InterlockedIncrement(&fvm_Calls_In_Progress);
	try {
		vmn = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());
		
		if (vmn == INVALID_VMID) {
			/*
			 * The corruent process is not running under a VM, call the
			 * original system call.
			 */

			rc = winNtCreateKeyProc(KeyHandle, ReqAccess, ObjectAttributes,
				    TitleIndex,Class, CreateOptions,Disposition);
			goto NtExit;
		}

		/*
		 * Allocate virtual memory from the process user space
		 */
		size = 16384; /* 4 pages */
		procHandle = NtCurrentProcess();
		pObjectAttributes = NULL;
		rc = FvmVm_AllocateVirtualMemory(procHandle, &pObjectAttributes, 0, &size,
				    MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (rc != STATUS_SUCCESS) {
			DbgPrint("--memory allocation problem(%d,NtCreateKey)\n",(ULONG)PsGetCurrentProcessId());
			goto NtExit;
		}

		/*
		 * Allocate the memory for each individual member
		 */
		(char *)pObjectName = ((char *)pObjectAttributes ) +
			    sizeof(OBJECT_ATTRIBUTES);
		(char *)pValueFullInfo = ((char *)pObjectName)+
			    sizeof(UNICODE_STRING);
		(char *)pTempHandle = ((char *)pValueFullInfo) + 4096;
		(char *)pTempHandle1 = ((char *)pTempHandle) + sizeof(HANDLE);
		(char *)pTempSize = ((char *)pTempHandle1) + sizeof(HANDLE);
		if(Disposition == NULL){
			(char *)Disposition = ((char *)pTempSize) + sizeof(ULONG);
			(char *)pOriName = ((char *)Disposition) + sizeof(PULONG);
		}
		else 
			(char *)pOriName = ((char *)pTempSize) + sizeof(ULONG);
		(char *)pVirName = ((char *)pOriName) + 4096;
		(char *)pTempBuffer = ((char *)pVirName) + 4096;

		/*
		 * Get the orignal and the virtual name of the registry key
		 */
		pOriName[0] = L'\0';
		pVirName[0] = L'\0';
		initial = GetFullRegName(ObjectAttributes->RootDirectory,
				    ObjectAttributes->ObjectName, pOriName, pVirName,
				    pTempBuffer, vmn);
		
		pObjectName->MaximumLength = 2048;
		//DbgPrint("createKey, %S\n",pOriName);
		if (ExGetPreviousMode() == KernelMode) {
		
			DbgPrint("Kernel level -- CreateRegKey: %S\n", pOriName);
		
			rc = winNtOpenKeyProc( KeyHandle, ReqAccess, ObjectAttributes);
		
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,   MEM_RELEASE);
			goto NtExit;
		}
		
		if(wcscmp(pOriName,  L"\\REGISTRY\\MACHINE")==0){

		rc = winNtCreateKeyProc(KeyHandle, ReqAccess, ObjectAttributes,
				    TitleIndex,Class, CreateOptions,Disposition);
		FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
								MEM_RELEASE);		

		goto NtExit;
			}
			
		if(FvmVm_CheckClsid((ULONG)PsGetCurrentProcessId(), pOriName)==TRUE){
			pObjectName->Length = wcslen(pOriName) * 2;
			pObjectName->Buffer = pOriName;
			
			InitializeObjectAttributes(pObjectAttributes, pObjectName,
						OBJ_CASE_INSENSITIVE, NULL, NULL);
			winNtCreateKeyProc(KeyHandle, ReqAccess,
								pObjectAttributes,	TitleIndex, Class,
							CreateOptions, Disposition);			
					size = 0;
			DbgPrint("winNtCreateKeyProc donot virtualize key %S\n",pOriName);
				FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
						MEM_RELEASE);			
			goto NtExit;			
		}

#if 1 //kghari: hacks to get the office XP/2k3 working!.

		if (wcsstr(pOriName, L"MSSetup_Chaining") != NULL) {
			rc = winNtCreateKeyProc(KeyHandle, ReqAccess, ObjectAttributes,
				    TitleIndex,Class, CreateOptions,Disposition);
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
			    MEM_RELEASE);
			goto NtExit;
		}
		if (wcsstr(pOriName, L"ChainedInstalls") != NULL) {
			rc = winNtCreateKeyProc(KeyHandle, ReqAccess, ObjectAttributes,
				    TitleIndex,Class, CreateOptions,Disposition);
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
			    MEM_RELEASE);
			goto NtExit;
		}
		

		if (wcsstr(pOriName, L"Cryptography") != NULL) {
			rc = winNtCreateKeyProc(KeyHandle, ReqAccess, ObjectAttributes,
				    TitleIndex,Class, CreateOptions,Disposition);
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
			    MEM_RELEASE);
			goto NtExit;
		}


		if (wcsstr(pOriName, L"Tcpip") != NULL) {
			rc = winNtCreateKeyProc(KeyHandle, ReqAccess, ObjectAttributes,
				    TitleIndex,Class, CreateOptions,Disposition);
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
			    MEM_RELEASE);
			goto NtExit;
		}

//		DbgPrint("pOriName = %S Virt Name %S\n", pOriName, pVirName);
#endif


		/*
		 * The input key has a virtual machine prefix
		 */

		pObjectName->Length = wcslen(pOriName) * 2;
		pObjectName->Buffer = pOriName;

		InitializeObjectAttributes(pObjectAttributes, pObjectName,
			    OBJ_CASE_INSENSITIVE, NULL, NULL);
		ntStatus = winNtCreateKeyProc(KeyHandle, ReqAccess,
				    pObjectAttributes,  TitleIndex, Class,
				    CreateOptions, Disposition);

		if (ntStatus != STATUS_SUCCESS) {
			size = 0;
			DbgPrint("Status NOT Success\n");
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
			    MEM_RELEASE);
			rc = ntStatus;
			goto NtExit;
		} else if (*Disposition == REG_CREATED_NEW_KEY) {
				ZwDeleteKey(KeyHandle);
		} else {
			ZwClose(KeyHandle);
		}

		pObjectName->Length = wcslen(pVirName) * 2;
		pObjectName->Buffer = pVirName;


		InitializeObjectAttributes(pObjectAttributes, pObjectName,
				    OBJ_CASE_INSENSITIVE, NULL, NULL);
		ntStatus = winNtCreateKeyProc(KeyHandle, ReqAccess | KEY_SET_VALUE,
				    pObjectAttributes,  TitleIndex, Class, CreateOptions,
				    Disposition);


		/*
		 * If there is a existing key in the virtual machine, we return
		 */
	    if (ntStatus == STATUS_SUCCESS && *Disposition ==
		    REG_OPENED_EXISTING_KEY) {
			wcscpy((PWCHAR) pTempBuffer, SEES_VALUE_NAME);
			pObjectName->Buffer = pTempBuffer;
			pObjectName->Length = (USHORT) SEES_VALUE_NAME_LEN * 2;
			pObjectName->MaximumLength = (USHORT) SEES_VALUE_NAME_LEN * 2;

				rc = winNtQueryValueKeyProc(*KeyHandle,pObjectName,
				    KeyValueFullInformation, pValueFullInfo, 4096, pTempSize);

				if (rc == STATUS_SUCCESS) {
					/*
				 	* Copy flag has been turned off.
				 	*/
					winNtDeleteValueKeyProc(*KeyHandle, pObjectName);
				} else {
					size = 0;
					FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
				    	MEM_RELEASE);
					rc = ntStatus;
					goto NtExit;
				
			}
    	}

	    /*
		 * There is no key in the virtual machine, we create one
		 */
		if (ntStatus != STATUS_SUCCESS) {
			working = 0;
			pObjectName->MaximumLength = 4096;
			pObjectName->Buffer = pVirName;

			InitializeObjectAttributes(pObjectAttributes, pObjectName,
				    OBJ_CASE_INSENSITIVE, NULL, NULL);


			pPointer = pVirName + 1;
			while(working<1000) {
				working++;
				pPointer = wcschr(pPointer, L'\\');

				if (!pPointer) {   // last key on the path
					 pObjectName->Length = wcslen(pVirName) * 2;
					 pObjectName->Buffer = pVirName;
					 pObjectName->MaximumLength = 4096;

					if (*KeyHandle)
						ZwClose(*KeyHandle);

					Disposition  = (PULONG)pTempBuffer;
					ntStatus = winNtCreateKeyProc(KeyHandle, KEY_ALL_ACCESS,
							    pObjectAttributes, TitleIndex, Class,
							    CreateOptions, Disposition);
					if (ntStatus !=  STATUS_SUCCESS) {
						size = 0;
						FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes,
							    &size, MEM_RELEASE);

						rc = ntStatus;
						goto NtExit;
					}
					break;
				} else {
					cSave = *pPointer;
					*pPointer = L'\0';

					pObjectName->Length = wcslen(pVirName) * 2;
					pObjectName->Buffer = pVirName;
					pObjectName->MaximumLength = 4096;

					if (*KeyHandle)
						winNtCloseProc(*KeyHandle);

					Disposition  = (PULONG)pTempBuffer;
					ntStatus = winNtCreateKeyProc(KeyHandle, KEY_ALL_ACCESS,
							    pObjectAttributes,  TitleIndex, Class,
							    CreateOptions,Disposition);

					if (ntStatus == STATUS_SUCCESS &&
					    *Disposition ==REG_CREATED_NEW_KEY) {
						sv = (ULONG *)(pTempBuffer+SEES_VALUE_NAME_LEN_A);
						*sv = 0;
						wcscpy((PWCHAR) pTempBuffer, SEES_VALUE_NAME);
						pObjectName->Buffer = pTempBuffer;
						pObjectName->Length = (USHORT)SEES_VALUE_NAME_LEN * 2;
						pObjectName->MaximumLength =
							    (USHORT)SEES_VALUE_NAME_LEN*2;

						winNtSetValueKeyProc(*KeyHandle, pObjectName, 0,
							    REG_DWORD, sv, sizeof(ULONG));
					}

					*pPointer = cSave;
					pPointer++;
				}
			}
		}

		/*
		 * copy the values
		 */
		pObjectName->Length = (wcslen(pOriName)) * 2;
		pObjectName->MaximumLength = 4096;
		pObjectName->Buffer = pOriName;

		rc =  winNtOpenKeyProc(pTempHandle, KEY_QUERY_VALUE, pObjectAttributes);
		if (rc == STATUS_SUCCESS) {
			index = 0;
			working = 0;

			while(working < 3000) {
				working++;
				rc = winNtEnumerateValueKeyProc(*pTempHandle, index,
					    KeyValueFullInformation,
					    pValueFullInfo, 4096, pTempSize);
				if (rc != STATUS_SUCCESS) {
					break;
				} else {
					/*
					 *  Do the copying.
					 */
					pObjectName->Buffer = pValueFullInfo->Name;
					pObjectName->Length = (USHORT)pValueFullInfo->NameLength;
					pObjectName->MaximumLength =
						    (USHORT)pValueFullInfo->NameLength;

					rc =  winNtSetValueKeyProc(*KeyHandle, pObjectName,
						    pValueFullInfo->TitleIndex,
						    pValueFullInfo->Type,
						    (PVOID)( pValueFullInfo->DataOffset +
						    ((char *)pValueFullInfo)),
						    pValueFullInfo->DataLength);
					 if (wcsstr(pOriName, L"PowerPoint")){
						pObjectName->Buffer[pObjectName->Length/2] = L'\0';						
					 }
				}
				index++;
			}
	    } else {
            size = 0;
			rc = FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
				    MEM_RELEASE);
			rc = ntStatus;
			goto NtExit;
		}

		if (*pTempHandle) {
			winNtCloseProc(*pTempHandle);
		}

#if 0
		pObjectName->Length = wcslen(pOriName) * 2;
		pObjectName->MaximumLength = 2048;
		pObjectName->Buffer = pOriName;
		InitializeObjectAttributes(pObjectAttributes, pObjectName,
			    OBJ_CASE_INSENSITIVE, NULL, NULL);
	    rc =  winNtOpenKeyProc(pTempHandle, KEY_ENUMERATE_SUB_KEYS, pObjectAttributes);
		pKeyBasicInfo = (PKEY_BASIC_INFORMATION)pValueFullInfo;

		if (rc == STATUS_SUCCESS) {
			int index = 0;
			working = 0;
			virNameLen = wcslen(pVirName);

			while (working < 3000) { //2000 is for preventing dos
				working++;
				rc = winNtEnumerateKeyProc(*pTempHandle, index,
					    KeyBasicInformation, pKeyBasicInfo,  4096, pTempSize);
				if (rc != STATUS_SUCCESS) {
					break;
				} else {
					pKeyBasicInfo->Name[pKeyBasicInfo->NameLength/2] = L'\0';
					pVirName[virNameLen] = L'\\';
					pVirName[virNameLen+1] = L'\0';
					wcscat(pVirName,  pKeyBasicInfo->Name);
					pObjectName->Length = wcslen(pVirName) * 2;
					pObjectName->MaximumLength = 4096;
					pObjectName->Buffer =  pVirName;
					InitializeObjectAttributes(pObjectAttributes, pObjectName,
						    OBJ_CASE_INSENSITIVE, NULL, NULL);
					if (*KeyHandle)
						winNtCloseProc(*KeyHandle);
					Disposition = (PULONG)pTempBuffer;
					rc = winNtCreateKeyProc(pTempHandle1, KEY_ALL_ACCESS,
						    pObjectAttributes, TitleIndex, Class,
						    CreateOptions,Disposition );

					if (rc == STATUS_SUCCESS && *Disposition ==
					    REG_CREATED_NEW_KEY) {
						sv = (ULONG *)(pTempBuffer+SEES_VALUE_NAME_LEN_A);
						*sv = 0;
						wcscpy((PWCHAR) pTempBuffer, SEES_VALUE_NAME);
						pObjectName->Buffer = pTempBuffer;
						pObjectName->Length = (USHORT)SEES_VALUE_NAME_LEN*2;
						pObjectName->MaximumLength =
						    (USHORT)SEES_VALUE_NAME_LEN*2;

						winNtSetValueKeyProc(*pTempHandle1, pObjectName,  0,
						    REG_DWORD, sv, sizeof(ULONG));

					}
				}
				index++;
			}
			pVirName[virNameLen] = L'\0';

		} else {
			size = 0;
			rc = FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
				    MEM_RELEASE);
			if (*KeyHandle) {
				winNtCloseProc(*KeyHandle);
				*KeyHandle = 0;
			}
			rc = ntStatus;
			goto NtExit;
		}
#endif
	 	/*
		 * Now open the key from the virtual machine
		 */
		if (*KeyHandle) {
			winNtCloseProc(*KeyHandle);
			*KeyHandle = 0;
		}
		if (*pTempHandle) {
			winNtCloseProc(*pTempHandle);
		}

		pObjectName->Length = wcslen(pVirName)*2;
		pObjectName->MaximumLength = 4096;
		pObjectName->Buffer = pVirName;
		InitializeObjectAttributes(pObjectAttributes, pObjectName,
			    OBJ_CASE_INSENSITIVE, NULL, NULL);


		ntStatus = winNtCreateKeyProc(KeyHandle, ReqAccess, pObjectAttributes,
				    TitleIndex, Class, CreateOptions, Disposition);

		size = 0;
		FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
		    MEM_RELEASE);
		rc = ntStatus;
		goto NtExit;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FvmReg_NtCreateKey\n"));
		rc = -1;
	}

 NtExit:
	/*if (vmn != INVALID_VMID) {
		DbgPrint("CreateRegKey: %x\n", rc);
	}*/
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}


static void
GetRegKeyName(HANDLE Key, PWCHAR Name) {
	CHAR	buff[2064];
	PUNICODE_STRING	fullUniName = (PUNICODE_STRING)buff;
	POBJECT	pKey = NULL;
	ULONG	actualLen;
	Name[0] = L'\0';

	try {
		wcscpy(Name, L"error");
		if (pKey = GetPointer(Key)) {

			if (pKey) {
				fullUniName->MaximumLength = MAXPATHLEN * sizeof(WCHAR);

				if (NT_SUCCESS(ObQueryNameString(pKey, fullUniName,
				    MAXPATHLEN, &actualLen))) {
					wcscpy(Name, fullUniName->Buffer);
			} else {
				DbgPrint("failed to ObQueryNameString\n");
			}
			ReleasePointer( pKey );
		}
	}
  } except(EXCEPTION_EXECUTE_HANDLER) {
		Name[0] = L'\0';
		DbgPrint(("Exception occured in GetRegKeyName\n"));
	}
}


NTSTATUS
FvmReg_NtQueryKey0(
	IN HANDLE  KeyHandle,
	IN KEY_INFORMATION_CLASS  KeyInformationClass,
	OUT PVOID  KeyInformation,
	IN ULONG  Length,
	OUT PULONG  ResultLength
) {

	//NTSTATUS	ntStatus;
	int	vmn;
	PWCHAR	wPtr;
	PWCHAR	buff;
	HANDLE	procHandle;
	NTSTATUS	rc;
	int	size;
	int	tmpSize;
	PULONG	rlen;
	WCHAR	wc;
	WCHAR	name[1024];
	int	slen;
	PVOID	keyInfo;
	PULONG	rsize;
	ULONG	newlength;

	InterlockedIncrement (&fvm_Calls_In_Progress);

	try {
		vmn = FvmUtil_VmNumber(); // get the virtual machine number

		if (vmn == INVALID_VMID) {
			rc = winNtQueryKeyProc(KeyHandle, KeyInformationClass,
					    KeyInformation, Length, ResultLength);		
			goto NtExit;
		}


		if (KeyInformationClass == KeyFullInformation || KeyInformationClass == KeyCachedInformation) {
			POBJECT_ATTRIBUTES	pObjectAttributes=NULL;
			PUNICODE_STRING pObjectName;
			PHANDLE pOriHandle;
			PWCHAR pOriName;
			PWCHAR kp;
			PKEY_BASIC_INFORMATION pOrgKeyInfo;
			PKEY_FULL_INFORMATION pFullInfo;
				
			PULONG		pRetLen;
			NTSTATUS ntStatus;
			ULONG index, repeat;
			PHANDLE pNewHandle;
			PKEY_CACHED_INFORMATION pCachedInfo;// =(PKEY_CACHED_INFORMATION) KeyInformation;
			PKEY_FULL_INFORMATION pOrigFullInfo;
			
			rc = winNtQueryKeyProc(KeyHandle, KeyInformationClass,
					    KeyInformation, Length, ResultLength);
	#if 1	
			GetRegKeyName(KeyHandle, name);			
				
			/* the registry key is in the host*/
			if (!wcsstr(name, pvms[vmn]->idStr))
				goto NtExit;
			
			procHandle = NtCurrentProcess();
				
			
			size = sizeof(OBJECT_ATTRIBUTES)+sizeof(UNICODE_STRING)+sizeof(HANDLE)+1024+ (sizeof(KEY_FULL_INFORMATION)+1024)
				   +sizeof(ULONG)+sizeof(HANDLE);
			
			ntStatus = FvmVm_AllocateVirtualMemory(procHandle, &pObjectAttributes, 0, &size,
							MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			
			//	DbgPrint("There is no more entry.....\n");
			if (ntStatus != STATUS_SUCCESS) {
				DbgPrint("-->memory allocation problem(%d,NtEnumerateKey0)\n",(ULONG)PsGetCurrentProcessId());
				
				goto NtExit;
			}
							
			(char *)pObjectName = ((char *)pObjectAttributes ) +  sizeof(OBJECT_ATTRIBUTES);
			(char *)pOriHandle = ((char *)pObjectName)+sizeof(UNICODE_STRING);
			(char *)pOriName =	 ((char *)pOriHandle )+sizeof(HANDLE);
			(char *)pOrgKeyInfo = ((char *)pOriName)+1024;
			(char *)pFullInfo  = (char *)pOrgKeyInfo;
			(char *)pRetLen =     ((char *)pOrgKeyInfo)+ (sizeof(KEY_FULL_INFORMATION)+1024);
			(char *)pNewHandle = ((char *)pRetLen)+sizeof(ULONG);

			
			kp =wcsstr(name, L"fvms");
			
			if(kp){
				kp = kp+37; 		
			}	
			if (_wcsnicmp(kp, L"\\Registry", 9)!=0){
				ntStatus = STATUS_NO_MORE_ENTRIES;			
					
				size = 0;
				FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size, MEM_RELEASE);
				goto NtExit;
			}

			
			wcscpy(pOriName, kp);
			pObjectName->Length = wcslen(pOriName)*2;
								
			pObjectName->MaximumLength = 1024;
			pObjectName->Buffer = pOriName;
			InitializeObjectAttributes(pObjectAttributes, pObjectName,
										OBJ_CASE_INSENSITIVE, NULL, NULL);
			ntStatus = winNtOpenKeyProc(pOriHandle, KEY_ENUMERATE_SUB_KEYS|KEY_QUERY_VALUE, pObjectAttributes);
											
			if (ntStatus != STATUS_SUCCESS) {
				size = 0;
				FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size, MEM_RELEASE);
				goto NtExit;
			}

			index = 0;
			repeat = 0;
			while(1){
				ntStatus= winNtEnumerateKeyProc(*pOriHandle, index, KeyBasicInformation, pOrgKeyInfo, 1024,pRetLen);
	
		
				if (ntStatus != STATUS_SUCCESS) {						
					break;
				}

				
				index++;
				
				
				pObjectName->Length = (USHORT) pOrgKeyInfo->NameLength;
				pObjectName->MaximumLength = 1024;
				pObjectName->Buffer = pOrgKeyInfo->Name;
				InitializeObjectAttributes(pObjectAttributes, pObjectName,
									OBJ_CASE_INSENSITIVE, KeyHandle, NULL);
		        ntStatus = winNtOpenKeyProc(pNewHandle, KEY_ENUMERATE_SUB_KEYS, pObjectAttributes);

	
				if (ntStatus == STATUS_SUCCESS){		
					repeat++;
					winNtCloseProc(*pNewHandle);
				}
		
			}


			ntStatus = winNtQueryKeyProc(*pOriHandle, KeyFullInformation,
					    pFullInfo, 1024, pRetLen);
			
			
			if (ntStatus == STATUS_SUCCESS){
				if (KeyInformationClass == KeyFullInformation){						
					pOrigFullInfo = (PKEY_FULL_INFORMATION )KeyInformation;
					if (pFullInfo->MaxNameLen > pOrigFullInfo->MaxNameLen)
						pOrigFullInfo->MaxNameLen = pFullInfo->MaxNameLen;
					if(pFullInfo->MaxClassLen > pOrigFullInfo->MaxClassLen)
						pOrigFullInfo->MaxClassLen = pFullInfo->MaxClassLen;
					if(pFullInfo->MaxValueNameLen > pOrigFullInfo->MaxValueNameLen)
						pOrigFullInfo->MaxValueNameLen = pFullInfo->MaxValueNameLen;
					if(pFullInfo->MaxValueDataLen > pOrigFullInfo->MaxValueDataLen)
						pOrigFullInfo->MaxValueDataLen =pFullInfo->MaxValueDataLen;
						
					pOrigFullInfo->SubKeys = pOrigFullInfo->SubKeys+pFullInfo->SubKeys-repeat;
				}
				else{
					pCachedInfo =(PKEY_CACHED_INFORMATION) KeyInformation;
					if (pFullInfo->MaxNameLen > pCachedInfo->MaxNameLen)
						pCachedInfo->MaxNameLen = pFullInfo->MaxNameLen;
					
					if(pFullInfo->MaxValueNameLen > pCachedInfo->MaxValueNameLen)
						pCachedInfo->MaxValueNameLen = pFullInfo->MaxValueNameLen;
					if(pFullInfo->MaxValueDataLen > pCachedInfo->MaxValueDataLen)
						pCachedInfo->MaxValueDataLen =pFullInfo->MaxValueDataLen;
						
					pCachedInfo->SubKeys = pCachedInfo->SubKeys+pFullInfo->SubKeys-repeat;

				}
			}
			else{
				if (KeyInformationClass == KeyFullInformation){
					pOrigFullInfo = (PKEY_FULL_INFORMATION )KeyInformation;
					pOrigFullInfo->SubKeys = pOrigFullInfo->SubKeys+index-repeat;

				}
				else{
					pCachedInfo =(PKEY_CACHED_INFORMATION) KeyInformation;
					
					pCachedInfo->SubKeys = pCachedInfo->SubKeys+index-repeat;
				}

			}
			winNtCloseProc(*pOriHandle);	
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size, MEM_RELEASE);
#endif
			goto NtExit;
		}



		/*
		 * We need a bigger sized structure than the one that is passed.
		 */
		tmpSize = Length*2;
		if (tmpSize < 1024)
			tmpSize = 1024;
		else if (tmpSize < 2048)
			tmpSize = 2048;
		else if (tmpSize < 4096)
			tmpSize = 4096;
		else
			tmpSize = 8192;


		size = tmpSize * 2 + 4;

		procHandle = NtCurrentProcess();
		buff = NULL;
		rc = FvmVm_AllocateVirtualMemory(procHandle, &buff, 0, &size,
			    MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (rc != STATUS_SUCCESS) {
			DbgPrint("-->memory allocation problem(%d,NtQueryKey0)\n",(ULONG)PsGetCurrentProcessId());
			goto NtExit;
		}

		keyInfo = (PVOID)(((char *)buff) + tmpSize);
		rsize = (PULONG)(((char*)buff) + tmpSize * 2);

		rc	= winNtQueryKeyProc( KeyHandle, KeyInformationClass,
				    keyInfo, tmpSize, rsize);

		if (rc != STATUS_SUCCESS) {
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &buff, &size, MEM_RELEASE);
		
			goto NtExit;
		}

		if (KeyInformationClass == KeyBasicInformation) {
			PKEY_BASIC_INFORMATION keyBasic   = (PKEY_BASIC_INFORMATION)keyInfo;
			PKEY_BASIC_INFORMATION keyBasic1 =
			    (PKEY_BASIC_INFORMATION)KeyInformation;
			wc = keyBasic->Name[keyBasic->NameLength/2];
			keyBasic->Name[keyBasic->NameLength/2]=L'\0';
			wPtr = wcsstr(keyBasic->Name, pvms[vmn]->idStr);

			/*
			 * Get rid of our prefix.
			 */
			if (wPtr) {
				wPtr = wcschr(wPtr, L'\\');
				wcscpy(buff, wPtr);

				/* Check to see if the input buffer passed to the syscall is enough for storing the result from query */
				newlength = wcslen(buff)*2;
				if((*rsize - (keyBasic->NameLength - newlength)) > Length) {
					/* The input buffer is too short */
					rc = STATUS_BUFFER_TOO_SMALL;
					*ResultLength = *rsize - (keyBasic->NameLength - newlength);
					goto NtExit;
				}
				
				wcscpy(keyBasic1->Name, buff);

				keyBasic1->NameLength = wcslen(keyBasic1->Name) * 2;
				keyBasic1->Name[keyBasic1->NameLength/2] = wc;
			} else {
				/* Check to see if the input buffer passed to the syscall is enough for storing the result from query */
				newlength = wcslen(keyBasic->Name)*2;
				if((*rsize - (keyBasic->NameLength - newlength)) > Length) {
					/* The input buffer is too short */
					rc = STATUS_BUFFER_TOO_SMALL;
					*ResultLength = *rsize - (keyBasic->NameLength - newlength);
					goto NtExit;
				}

				wcscpy(keyBasic1->Name, keyBasic->Name);
				keyBasic1->NameLength = wcslen(keyBasic1->Name)*2;
				keyBasic1->Name[keyBasic1->NameLength/2] = wc;
			}

			keyBasic1->LastWriteTime = keyBasic->LastWriteTime;
			keyBasic1->TitleIndex = keyBasic->TitleIndex;
			*ResultLength = *rsize - (keyBasic->NameLength - keyBasic1->NameLength);
		} else if (KeyInformationClass ==
		    KeyNodeInformation) {
			PKEY_NODE_INFORMATION keyNode =(PKEY_NODE_INFORMATION)keyInfo;
			PKEY_NODE_INFORMATION keyNodeOut =(PKEY_NODE_INFORMATION)
			    KeyInformation;

			wc = keyNode->Name[keyNode->NameLength/2];
			keyNode->Name[keyNode->NameLength/2] = L'\0';

			wPtr = wcsstr(keyNode->Name, pvms[vmn]->idStr);
			if (wPtr) {
				wPtr = wcschr(wPtr, L'\\');
				wcscpy(buff, wPtr);

				/* Check to see if the input buffer passed to the syscall is enough for storing the result from query */
				newlength = wcslen(buff)*2;
				if((*rsize - (keyNode->NameLength - newlength)) > Length) {
				   /* The input buffer is too short */
				   rc = STATUS_BUFFER_TOO_SMALL;
				   *ResultLength = *rsize - (keyNode->NameLength - newlength);
				   goto NtExit;
				}
				
				wcscpy(keyNodeOut->Name, wPtr);
				keyNodeOut->NameLength = wcslen(keyNodeOut->Name)*2;
				keyNodeOut->ClassOffset = keyNode->ClassOffset-(keyNode->NameLength - keyNodeOut->NameLength);
			} else {
				/* Check to see if the input buffer passed to the syscall is enough for storing the result from query */
				newlength = wcslen(keyNode->Name)*2;
				if((*rsize - (keyNode->NameLength - newlength)) > Length) {
					/* The input buffer is too short */
					rc = STATUS_BUFFER_TOO_SMALL;
					*ResultLength = *rsize - (keyNode->NameLength - newlength);
					goto NtExit;
				}
			
				wcscpy(keyNodeOut->Name, keyNode->Name);
				keyNodeOut->ClassOffset = keyNode->ClassOffset;
				keyNodeOut->NameLength = wcslen(keyNodeOut->Name)*2;
			}

			keyNodeOut->Name[keyNode->NameLength/2] = wc;
			keyNodeOut->LastWriteTime = keyNode->LastWriteTime;
			keyNodeOut->TitleIndex = keyNode->TitleIndex;
			keyNodeOut->ClassLength = keyNode->ClassLength;
			memcpy(((char *)KeyInformation)+keyNodeOut->ClassOffset,
			    ((char *)keyInfo)+keyNode->ClassOffset, keyNodeOut->ClassLength);
			*ResultLength = *rsize - (keyNode->NameLength -
				    keyNodeOut->NameLength);

		} else if (KeyInformationClass == KeyNameInformation) {

			PKEY_NAME_INFORMATION keyName = (PKEY_NAME_INFORMATION) keyInfo;
			PKEY_NAME_INFORMATION keyNameOut = (PKEY_NAME_INFORMATION) KeyInformation;

			slen = keyName->NameLength;
			wc = keyName->Name[keyName->NameLength/2];
			keyName->Name[keyName->NameLength/2] = L'\0';
			wPtr = wcsstr(keyName->Name, pvms[vmn]->idStr);

			if (wPtr) {
				int tlen;
				wPtr = wcschr(wPtr, L'\\');
				wcscpy(buff, wPtr);

				/* Check to see if the input buffer passed to the syscall is enough for storing the result from query */
				newlength = wcslen(buff)*2;
				if((*rsize - (keyName->NameLength - newlength)) > Length) {
				   /* The input buffer is too short */
				   rc = STATUS_BUFFER_TOO_SMALL;
				   *ResultLength = *rsize - (keyName->NameLength - newlength);
				   goto NtExit;
				}

				wcscpy(keyNameOut->Name, buff);
				keyNameOut->NameLength = wcslen(keyNameOut->Name) * 2;
			} else {
				/* Check to see if the input buffer passed to the syscall is enough for storing the result from query */
				newlength = wcslen(keyName->Name)*2;
				if((*rsize - (keyName->NameLength - newlength)) > Length) {
					/* The input buffer is too short */
					rc = STATUS_BUFFER_TOO_SMALL;
					*ResultLength = *rsize - (keyName->NameLength - newlength);
					goto NtExit;
				}

				wcscpy(keyNameOut->Name, keyName->Name);
				keyNameOut->NameLength = wcslen(keyNameOut->Name)*2;
			}
			*ResultLength = *rsize - (keyName->NameLength -
			    keyNameOut->NameLength);
			keyNameOut->Name[keyNameOut->NameLength/2] = wc;

		} 
#if 1
		else if(KeyInformationClass == KeyCachedInformation) {

			/*    On Windows XP, NtQueryKey does return KEY_CACHED_INFORMATION
			  *    Information Class also. We do
			  */

			PKEY_CACHED_INFORMATION keyCached =(PKEY_CACHED_INFORMATION)keyInfo;
			PKEY_CACHED_INFORMATION keyCachedOut =(PKEY_CACHED_INFORMATION) KeyInformation;

			/* Check to see if the input buffer passed to the syscall is enough for storing the result from query */
			if(*rsize > Length) {
			   /* The input buffer is too short */
			   rc = STATUS_BUFFER_TOO_SMALL;
			   *ResultLength = *rsize;
			   goto NtExit;
			}

			*ResultLength = *rsize;

			keyCachedOut->LastWriteTime = keyCached->LastWriteTime;
			keyCachedOut->TitleIndex = keyCached->TitleIndex;
			keyCachedOut->SubKeys = keyCached->SubKeys;
			keyCachedOut->MaxNameLen = keyCached->MaxNameLen;
			keyCachedOut->Values = keyCached->Values;
			keyCachedOut->MaxValueNameLen = keyCached->MaxValueNameLen;
			keyCachedOut->MaxValueDataLen = keyCached->MaxValueDataLen;
			keyCachedOut->NameLength = keyCached->NameLength;
		}
#endif
		size = 0;
		FvmVm_FreeVirtualMemory(procHandle, &buff, &size, MEM_RELEASE);
		//rc = ntStatus;
		goto NtExit;
	}   except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FvmReg_NtQueryKey0\n"));
		rc = -1;
	}
NtExit:

#if 0
			if (vmn!= INVALID_VMID) {
				WCHAR keyName[300];
				PWCHAR kp;
				WCHAR bp[256];
				FvmUtil_GetBinaryPathName(bp);
				if(1){	
					GetRegKeyName(KeyHandle, keyName);
				
					kp =wcsstr(keyName, L"fvms");
					if(kp){
						kp = kp+37;// wcsstr(keyName, L"\\Registry");
						if(!kp)
							kp = keyName;
							
					}	
					else
						kp = keyName;
					
					if (rc == STATUS_SUCCESS) {
						switch(KeyInformationClass){
						case KeyBasicInformation:{
							PKEY_BASIC_INFORMATION n1 =
								(PKEY_BASIC_INFORMATION) KeyInformation;
							n1->Name[n1->NameLength/2] = L'\0';
							//DbgPrint("QueryKey: KeyBasicInformation:%S --> %S\n", kp, n1->Name);
							break;
							}
						case KeyNodeInformation:{
							PKEY_NODE_INFORMATION n2 =
								(PKEY_NODE_INFORMATION)KeyInformation;
									n2->Name[n2->NameLength/2] = L'\0';
							//DbgPrint("QueryKey: KeyNodeInformation:%S --> %S\n", kp, n2->Name);
							break;
							}
						case KeyFullInformation:{
							PKEY_FULL_INFORMATION n4 = (PKEY_FULL_INFORMATION )KeyInformation;
							DbgPrint("QueryKey: KeyFullInformation: %d %S\n", n4->SubKeys, kp);
							//DbgPrint("QueryKey: KeyFullInformation: %S\n", kp);
							break;
							}
						case KeyNameInformation:{
						
							PKEY_NAME_INFORMATION n3 =
												(PKEY_NAME_INFORMATION)KeyInformation;
									n3->Name[n3->NameLength/2] = L'\0';
							//DbgPrint("QueryKey: KeyNameInformation:%S --> %S\n",kp, n3->Name);
							break;
							}
						
						case KeyCachedInformation:{
							PKEY_CACHED_INFORMATION n4 =(PKEY_CACHED_INFORMATION) KeyInformation;
							DbgPrint("QueryKey: KeyCachedInformation: %d, %S\n", n4->SubKeys, kp );
							break;
							}
						default:
							DbgPrint("QueryKey: unknown class\n");
						
						}
					}
					else{
		
						DbgPrint("QueryKey:fail..... %x %S\n", rc, kp);
					}
						
				}
			}
#endif 

	
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

void
FvmReg_CopyKey
(
	HANDLE KeyHandle,
	int vmn
) {
	NTSTATUS	ntStatus;
	HANDLE	procHandle;
	NTSTATUS	rc;
	int	size;
	POBJECT_ATTRIBUTES	pObjectAttributes=NULL;
	PUNICODE_STRING	pObjectName;
	PKEY_VALUE_FULL_INFORMATION	pValueFullInfo;
	PHANDLE	pTempHandle;
	PHANDLE	pTempHandle1;
	PULONG	pTempSize;
	PWCHAR	pVirName;
	PWCHAR	pOriName;
	PWCHAR	pTempBuffer;
	PKEY_BASIC_INFORMATION	pKeyBasicInfo;
	ULONG	TitleIndex = 0;
	PUNICODE_STRING	Class = NULL;
	PULONG	Disposition = NULL;
	ULONG	createOptions = REG_OPTION_NON_VOLATILE;
	ULONG	working;
	PWCHAR	pPointer;
	WCHAR	cSave;
	ULONG	virNameLen;
	PULONG	sv;
	PWCHAR	rp;
	PWCHAR wFullName = NULL;

	try {

		

		wFullName = ExAllocatePoolWithTag(PagedPool, MAXPATHLEN, '2GAT');
		if (wFullName){	
			if (FvmUtil_PathFromHandle(KeyHandle, NULL, wFullName) == FALSE) {
				DbgPrint("CopyKey: false");
				return;
			}			
		}
		else {
			DbgPrint("CopyKey: false 1");
			return;
		}	


		//DbgPrint("Copy: %S\n", wFullName);
		
		/*
		 * Allocate virtual memory from the process user space
	 	*/
		size = 16384+1024*1024; /* 4 pages + 1MB */
		procHandle = NtCurrentProcess();

		pObjectAttributes = NULL;
		rc = FvmVm_AllocateVirtualMemory(procHandle, &pObjectAttributes, 0, &size,
		    MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (rc != STATUS_SUCCESS) {
			DbgPrint("--memory allocation problem(%d,NtOpenKey)\n",(ULONG)PsGetCurrentProcessId());
			goto NtExit;
		}

		(char *)pObjectName = ((char *)pObjectAttributes ) +
			    sizeof(OBJECT_ATTRIBUTES);
		(char *)pValueFullInfo = ((char *)pObjectName) +
	    	sizeof(UNICODE_STRING);
		(char *)pTempHandle = ((char *)pValueFullInfo) + 4096+1024*1024;
		(char *)pTempHandle1 = ((char *)pTempHandle) + sizeof(HANDLE);
		(char *)pTempSize = ((char *)pTempHandle1) + sizeof(HANDLE);
		(char *)pOriName = ((char *)pTempSize) + sizeof(ULONG);
		(char *)pVirName = ((char *)pOriName) + 4096;
		(char *)pTempBuffer = ((char *)pVirName) + 4096;

		/*
		 * Get the orignal and the virtual name of the registry key
		 */
		pOriName[0] = L'\0';
		pVirName[0] = L'\0';

		

		swprintf(pVirName, L"\\REGISTRY\\USER\\%s\\fvms\\%s", pvms[vmn]->SidStr, pvms[vmn]->idStr);
		size = wcslen(pVirName);
		if (_wcsnicmp(wFullName, pVirName, size) != 0){
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,MEM_RELEASE);
			ExFreePool(wFullName);

			return;

		}
			
		wcscpy(pVirName, wFullName);
		ExFreePool(wFullName);
		wcscpy(pOriName, &pVirName[size]);
	

		wcscpy((PWCHAR) pTempBuffer, SEES_VALUE_NAME);
		pObjectName->Buffer = pTempBuffer;
		pObjectName->Length = (USHORT) SEES_VALUE_NAME_LEN*2;
		pObjectName->MaximumLength = (USHORT) SEES_VALUE_NAME_LEN*2;

		
		/*
		 *  Check if we need to copy subkeys
	 	*/
		rc = winNtQueryValueKeyProc(KeyHandle, pObjectName,
				    KeyValueFullInformation, pValueFullInfo, 4096, pTempSize);

		if (rc == STATUS_SUCCESS) {
			winNtDeleteValueKeyProc(KeyHandle, pObjectName);
		} else {
			/*
			 * The original location does not have the key. retur
			 */

			//DbgPrint("Do not need to copy key: %S\n", pOriName);
			size = 0;
			rc = FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
				    MEM_RELEASE);
			return;
		}

		/* Open the original key */
		
		

		pObjectName->Length = wcslen(pOriName) * 2;
		pObjectName->MaximumLength = 2048;
		pObjectName->Buffer = pOriName;
		InitializeObjectAttributes(pObjectAttributes, pObjectName,
			    OBJ_CASE_INSENSITIVE, NULL, NULL);
	    rc = winNtOpenKeyProc(pTempHandle, KEY_ENUMERATE_SUB_KEYS,
			    pObjectAttributes);

		pKeyBasicInfo = (PKEY_BASIC_INFORMATION )pValueFullInfo;

		
	    /*
		 * Copy subkeys
		 */
		if (rc == STATUS_SUCCESS) {
			int index = 0;
			working = 0;

			DbgPrint("...copying key: %S\n",pOriName);
			virNameLen = wcslen(pVirName);
			while (working < 3000) {
				working++;
				rc = winNtEnumerateKeyProc(*pTempHandle, index,
					    KeyBasicInformation, pKeyBasicInfo, 4096, pTempSize);

				if (rc != STATUS_SUCCESS) {
					break;
				} else {
					pKeyBasicInfo->Name[pKeyBasicInfo->NameLength/2] = L'\0';

					 pVirName[virNameLen] = L'\\';
					 pVirName[virNameLen+1] = L'\0';
					 wcscat(pVirName, pKeyBasicInfo->Name);
					 pObjectName->Length = wcslen(pVirName) * 2;
					 pObjectName->MaximumLength = 4096;
					 pObjectName->Buffer =  pVirName;
					 InitializeObjectAttributes(pObjectAttributes, pObjectName,
						    OBJ_CASE_INSENSITIVE, NULL, NULL );
					if (KeyHandle)
						winNtCloseProc(KeyHandle);

					 Disposition = (PULONG)pTempBuffer;
					 rc = winNtCreateKeyProc(pTempHandle1, KEY_ALL_ACCESS,
						    pObjectAttributes, TitleIndex, Class,
						    createOptions, Disposition);

					if (rc == STATUS_SUCCESS && *Disposition ==
					    REG_CREATED_NEW_KEY) {
						sv = (ULONG *)(pTempBuffer + SEES_VALUE_NAME_LEN_A);
						*sv = 0;
						wcscpy((PWCHAR)pTempBuffer, SEES_VALUE_NAME);
						pObjectName->Buffer = pTempBuffer;
						pObjectName->Length = (USHORT)SEES_VALUE_NAME_LEN * 2;
						pObjectName->MaximumLength =
						    (USHORT)SEES_VALUE_NAME_LEN * 2;
						winNtSetValueKeyProc(*pTempHandle1, pObjectName, 0,
						    REG_DWORD, sv, sizeof(ULONG));
					}
				}
				index++;
			}
			pVirName[virNameLen] = L'\0';
		} else{

			DbgPrint("Could not open: %S\n",pOriName);
		}

	
		size = 0;
		FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size,
			    MEM_RELEASE);
		goto NtExit;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FvmReg_NtOpenKey\n"));
		rc = -1;
	}
 NtExit:


	return;
}



/****************************************************************************
****************************************************************************/


NTSTATUS
FvmReg_NtQueryKey(
	IN HANDLE  KeyHandle,
	IN KEY_INFORMATION_CLASS  KeyInformationClass,
	OUT PVOID  KeyInformation,
	IN ULONG  Length,
	OUT PULONG  ResultLength
) {
	NTSTATUS ntStatus;
	
	ntStatus = FvmReg_NtQueryKey0(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
	return ntStatus;
}


/*
 * Once we've deleted a key, we can remove its reference in the hash
 * table.
 */
NTSTATUS
FvmReg_NtDeleteKey(
	IN HANDLE Handle
) {
	NTSTATUS	ntStatus;
	int	vmn = -1;
	WCHAR	name[1024];

	/*
	 * Get the VM number
	 */
	vmn = FvmUtil_VmNumber();
	InterlockedIncrement (&fvm_Calls_In_Progress);

	if (ExGetPreviousMode() == KernelMode) {
		ntStatus = winNtDeleteKeyProc(Handle);
		goto Original_Call;
	}

	try {
		RtlZeroMemory(name, 1024 * sizeof(WCHAR));
		GetRegKeyName(Handle, name);

		ntStatus = winNtDeleteKeyProc(Handle);
		if (vmn != -1 && vmn != INVALID_VMID) {
			FvmTable_DeleteLogAdd(name, vmn);
		}
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FvmReg_NtDeleteKey\n"));
		ntStatus = -1;
	}
Original_Call:

	InterlockedDecrement (&fvm_Calls_In_Progress);
	return ntStatus;
}


//----------------------------------------------------------------------
//
// HookRegEnumerateKey
//
// This is a documented Zw-class function.
//
//----------------------------------------------------------------------
NTSTATUS
NTAPI
FvmReg_NtEnumerateKey0(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
) {
	NTSTATUS	ntStatus;
	int	vmn;
	PWCHAR	wptr;
	PWCHAR	info;
	PWCHAR	buff;
	HANDLE	procHandle;
	int	size;
	int	tmpSize;
	WCHAR	wc;
	PVOID	keyInfo;
	int	*rSize;

	InterlockedIncrement(&fvm_Calls_In_Progress);

	try {

		/*
		 * Get the VM number
		 */
		vmn = FvmUtil_VmNumber();
		if (vmn == INVALID_VMID) {
			ntStatus= winNtEnumerateKeyProc(KeyHandle, Index,
					    KeyInformationClass, KeyInformation, Length,
					    ResultLength);
			goto NtExit;
		}

		FvmReg_CopyKey(KeyHandle, vmn);
		
		if (KeyInformationClass == KeyFullInformation) {
			ntStatus = winNtEnumerateKeyProc(KeyHandle, Index,
					    KeyInformationClass, KeyInformation, Length,
					    ResultLength);
			goto NtExit;
		}

		/*
		  * We need bigger sized structure than the one passed by the program
		  */
		tmpSize = Length*2;
		if (tmpSize < 1024)
			tmpSize = 1024;
		else if (tmpSize < 2048)
			tmpSize = 2048;
		else if (tmpSize < 4096)
			tmpSize = 4096;
		else
			tmpSize = 8192;

		size = tmpSize*2 + 4;
		procHandle = NtCurrentProcess();
		buff = NULL;
		ntStatus = FvmVm_AllocateVirtualMemory(procHandle, &buff, 0, &size,
				    MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (ntStatus != STATUS_SUCCESS) {
			DbgPrint("-->memory allocation problem(%d,NtEnumerateKey0)\n",(ULONG)PsGetCurrentProcessId());
			goto NtExit;
		}

		keyInfo = (PVOID)(((char *)buff)+tmpSize);
		rSize = (int *)(((char*)buff)+tmpSize*2);
		ntStatus = winNtEnumerateKeyProc( KeyHandle, Index, KeyInformationClass, keyInfo, tmpSize, rSize );

		if (ntStatus != STATUS_SUCCESS) {
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &buff, &size, MEM_RELEASE);
			goto NtExit;
         }

         if (KeyInformationClass == KeyBasicInformation) {
			PKEY_BASIC_INFORMATION keyBasic =
				    (PKEY_BASIC_INFORMATION) keyInfo;
			PKEY_BASIC_INFORMATION keyBasic1 =
				    (PKEY_BASIC_INFORMATION) KeyInformation;

               wc = keyBasic->Name[keyBasic->NameLength/2];
               keyBasic->Name[keyBasic->NameLength/2]=L'\0';
               wptr = wcsstr(keyBasic->Name, pvms[vmn]->idStr);


				/*
				 * Get rid of our prefix.
				 */
			if (wptr) {
				wptr = wcschr(wptr, L'\\');
				wcscpy(buff, wptr);
				wcscpy(keyBasic1->Name, buff);

				keyBasic1->NameLength = wcslen(keyBasic1->Name)*2;
				keyBasic1->Name[keyBasic1->NameLength/2] = wc;
			} else {
				wcscpy(keyBasic1->Name, keyBasic->Name);
				keyBasic1->NameLength = wcslen(keyBasic1->Name)*2;
				keyBasic1->Name[keyBasic1->NameLength/2] = wc;
			}

			keyBasic1->LastWriteTime = keyBasic->LastWriteTime;
			keyBasic1->TitleIndex = keyBasic->TitleIndex;
			*ResultLength = *rSize - (keyBasic->NameLength -
						    keyBasic1->NameLength);
		} else if (KeyInformationClass ==
		    KeyNodeInformation) {
			PKEY_NODE_INFORMATION keyNode = (PKEY_NODE_INFORMATION)keyInfo;
			PKEY_NODE_INFORMATION keyNodeOut =
				    (PKEY_NODE_INFORMATION)KeyInformation;

			wc = keyNode->Name[keyNode->NameLength/2];
			keyNode->Name[keyNode->NameLength/2]=L'\0';

			wptr = wcsstr(keyNode->Name, pvms[vmn]->idStr);
			if (wptr) {
				wptr = wcschr(wptr, L'\\');
				wcscpy(buff, wptr);
				wcscpy(keyNodeOut->Name, wptr);
				keyNodeOut->NameLength = wcslen(keyNodeOut->Name) * 2;
				keyNodeOut->ClassOffset = keyNode->ClassOffset -
					    (keyNode->NameLength - keyNodeOut->NameLength);
			} else {
				wcscpy(keyNodeOut->Name, keyNode->Name);
				keyNodeOut->ClassOffset=keyNode->ClassOffset;
				keyNodeOut->NameLength = wcslen(keyNodeOut->Name)*2;
			}
			keyNodeOut->Name[keyNode->NameLength/2]=wc;
			keyNodeOut->LastWriteTime = keyNode->LastWriteTime;
			keyNodeOut->TitleIndex = keyNode->TitleIndex;
			keyNodeOut->ClassLength = keyNode->ClassLength;
			memcpy(((char *)KeyInformation)+keyNodeOut->ClassOffset,
			    ((char *)keyInfo)+keyNode->ClassOffset,
			    keyNodeOut->ClassLength);
			*ResultLength = *rSize - (keyNode->NameLength -
				keyNodeOut->NameLength);
         } else if (KeyInformationClass == KeyNameInformation) {
            PKEY_NAME_INFORMATION keyName = (PKEY_NAME_INFORMATION)keyInfo;
			PKEY_NAME_INFORMATION keyNameOut =
    				(PKEY_NAME_INFORMATION)KeyInformation;

			wc = keyName->Name[keyName->NameLength/2];
			keyName->Name[keyName->NameLength/2] = L'\0';
			wptr = wcsstr(keyName->Name, pvms[vmn]->idStr);
			if (wptr) {
				wptr = wcschr(wptr, L'\\');
				wcscpy(buff, wptr);
				wcscpy(keyNameOut->Name, buff);
				keyNameOut->NameLength = wcslen(keyNameOut->Name)*2;
			} else {
				wcscpy(keyNameOut->Name, keyName->Name);
				keyNameOut->NameLength = wcslen(keyNameOut->Name)*2;
			}
			*ResultLength = *rSize - (keyName->NameLength -
				    keyNameOut->NameLength);
			keyNameOut->Name[keyNameOut->NameLength/2] = wc;
         }

		size = 0;
		FvmVm_FreeVirtualMemory(procHandle, &buff, &size, MEM_RELEASE);
		goto NtExit;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FvmReg_NtEnumerateKey0\n"));
		ntStatus= -1;
	}

NtExit:
#if 1
			if (vmn!= INVALID_VMID) {
				WCHAR keyName[300];
				PWCHAR kp;
				WCHAR bp[256];
				FvmUtil_GetBinaryPathName(bp);
				if(1){	
					GetRegKeyName(KeyHandle, keyName);
				
					kp =wcsstr(keyName, L"fvms");
					if(kp){
						kp = wcsstr(keyName, L"\\Registry");
						if(!kp)
							kp = keyName;
							
					}	
					else
						kp = keyName;
					/*if(wcscmp(kp, L"\\Registry\\Machine\\Software\\Classes\\CLSID") ==0||
						wcscmp(kp, L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID") ==0
		
					){*/
					if (ntStatus == STATUS_SUCCESS) {
						switch(KeyInformationClass){
						case KeyBasicInformation:{
							PKEY_BASIC_INFORMATION n1 =
								(PKEY_BASIC_INFORMATION) KeyInformation;
							n1->Name[n1->NameLength/2] = L'\0';
							DbgPrint("EnumerateKey: KeyBasicInformation: %d %S --> %S\n",Index, kp, n1->Name);
							break;
							}
						case KeyNodeInformation:{
							PKEY_NODE_INFORMATION n2 =
								(PKEY_NODE_INFORMATION)KeyInformation;
									n2->Name[n2->NameLength/2] = L'\0';
							DbgPrint("EnumerateKey: KeyNodeInformation: %d	%S --> %S\n", Index, kp, n2->Name);
							break;
							}
						case KeyFullInformation:
							DbgPrint("EnumerateKey: KeyFullInformation: %d %S\n",Index, kp);
							break;
						case KeyNameInformation:{
						
							PKEY_NAME_INFORMATION n3 =
												(PKEY_NAME_INFORMATION)KeyInformation;
									n3->Name[n3->NameLength/2] = L'\0';
							DbgPrint("EnumerateKey: KeyNameInformation:%d  %S --> %S\n",Index, kp, n3->Name);
							break;
							}
						default:
							DbgPrint("EnumerateKey: unknown class\n");
						
						}
					}
					else{
		
						DbgPrint("EnumerateKey: fail..... %x %S\n", ntStatus, kp);
					}
						//}
				}
			}
#endif 

	InterlockedDecrement (&fvm_Calls_In_Progress);
	return ntStatus;
}

FVM_PHandleTableEntry cachedHandleEntry=NULL;

NTSTATUS FvmReg_EnumerateHostKey(
	FVM_PHandleTableEntry handleEntry,
	IN HANDLE KeyHandle,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation,
	IN ULONG Length,
	OUT PULONG ResultLength,
	ULONG vmId,
	HANDLE	procHandle
	)
{
	NTSTATUS ntStatus, rc;

	POBJECT_ATTRIBUTES	pObjectAttributes=NULL;
	PUNICODE_STRING pObjectName;
	PHANDLE pNewHandle;
	PWCHAR pKeyName;
	PWCHAR kp;
	int size;
	PWCHAR pSubKeyName;
	ULONG keyLength;

	if(handleEntry->hnative == 0){
		FvmTable_HandleTableRemove(KeyHandle, vmId);
		cachedHandleEntry = NULL;
		return STATUS_NO_MORE_ENTRIES;
	}
	
	procHandle = NtCurrentProcess();
	size = sizeof(OBJECT_ATTRIBUTES)+sizeof(UNICODE_STRING)+sizeof(HANDLE)+1024;
			ntStatus = FvmVm_AllocateVirtualMemory(procHandle, &pObjectAttributes, 0, &size,
							MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			
	if (ntStatus != STATUS_SUCCESS) {
		DbgPrint("-->memory allocation problem(%d,FvmReg_EnumerateHostKey)\n",(ULONG)PsGetCurrentProcessId());
		FvmTable_HandleTableRemove(KeyHandle, vmId);
		cachedHandleEntry = NULL;
		return ntStatus;
	}
	(char *)pObjectName = ((char *)pObjectAttributes ) +  sizeof(OBJECT_ATTRIBUTES);
	(char *)pNewHandle = ((char *)pObjectName)+sizeof(UNICODE_STRING);
	(char *)pKeyName =	 ((char *)pNewHandle )+sizeof(HANDLE);

	while(1){
			
		ntStatus= winNtEnumerateKeyProc(handleEntry->hnative, handleEntry->hostIndex,
								KeyInformationClass, KeyInformation, Length,
								ResultLength);
	
		
		if (ntStatus != STATUS_SUCCESS) {	
			winNtCloseProc(handleEntry->hnative);
			FvmTable_HandleTableRemove(KeyHandle, vmId);
			cachedHandleEntry = NULL;
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size, MEM_RELEASE);
			return ntStatus;
		}


		switch(KeyInformationClass){
			case KeyBasicInformation:{
				PKEY_BASIC_INFORMATION n1 =
					(PKEY_BASIC_INFORMATION) KeyInformation;
						pSubKeyName = n1->Name;
						keyLength = n1->NameLength;
						break;
						}
			case KeyNodeInformation:{
				PKEY_NODE_INFORMATION n2 =
					(PKEY_NODE_INFORMATION)KeyInformation;
				keyLength = n2->NameLength;
				pSubKeyName = n2->Name;
				break;
			}
			case KeyFullInformation:
				pSubKeyName = NULL;
				break;
			case KeyNameInformation:{	
				PKEY_NAME_INFORMATION n3 =
				(PKEY_NAME_INFORMATION)KeyInformation;
				keyLength = n3->NameLength;
				pSubKeyName =n3->Name;
				break;
			}
			default:
				pSubKeyName = NULL;					
		}
		if (pSubKeyName == NULL){
			handleEntry->hostIndex++;
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size, MEM_RELEASE);
			return ntStatus;
		}
		memcpy(pKeyName, pSubKeyName, keyLength);
		pObjectName->Length = (USHORT)keyLength;
		pObjectName->MaximumLength = 1024;
		pObjectName->Buffer = pKeyName;
		InitializeObjectAttributes(pObjectAttributes, pObjectName,
									OBJ_CASE_INSENSITIVE, KeyHandle, NULL);
		rc = winNtOpenKeyProc(pNewHandle, KEY_ENUMERATE_SUB_KEYS, pObjectAttributes);

		handleEntry->hostIndex++;
		if (rc != STATUS_SUCCESS){		
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size, MEM_RELEASE);
			return ntStatus;
			
		}
		else{
			winNtCloseProc(*pNewHandle);
		}

		//DbgPrint("repeat: %S\n", pSubKeyName);
	}		
}



NTSTATUS
FvmReg_NtEnumerateKeyEx (
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
) {
	
	//NTSTATUS rc;
	ULONG vmId = INVALID_VMID;
	WCHAR regName[400];
	HANDLE hostDir;
	FVM_PHandleTableEntry handleEntry = NULL;

	NTSTATUS	ntStatus;
		//int vmn;
		PWCHAR	wptr;
		PWCHAR	info;
		PWCHAR	buff;
		HANDLE	procHandle;
		int size;
		int tmpSize;
		WCHAR	wc;
		PVOID	keyInfo;
		int *rSize;
		HANDLE pid;

	
	InterlockedIncrement(&fvm_Calls_In_Progress);

	vmId= FvmUtil_VmNumber();
	if (vmId == INVALID_VMID){

		ntStatus= winNtEnumerateKeyProc(KeyHandle, Index,
								KeyInformationClass, KeyInformation, Length,
								ResultLength);

		goto NtExit;
	}
	procHandle = NtCurrentProcess();

	
	GetRegKeyName(KeyHandle, regName);

	
	/* the registry key is in the host, we just forward the request*/
	if (!wcsstr(regName, pvms[vmId]->idStr)){
		ntStatus = winNtEnumerateKeyProc(KeyHandle, Index,
										KeyInformationClass, KeyInformation, Length,
										ResultLength);
		
		goto NtExit;
	}
	pid = PsGetCurrentProcessId();

	handleEntry = NULL;
	hostDir = NULL;
	handleEntry = FvmTable_HandleTableLookup(KeyHandle, vmId, &hostDir);
	if (handleEntry == NULL){
		POBJECT_ATTRIBUTES	pObjectAttributes=NULL;
					PUNICODE_STRING pObjectName;
					PHANDLE pOriHandle;
					PWCHAR pOriName;
					PWCHAR kp;
	 	ULONG fvmIndex;
		ULONG hostIndex;
		int   enumDirection;

		size = sizeof(OBJECT_ATTRIBUTES)+sizeof(UNICODE_STRING)+sizeof(HANDLE)+1024;
					ntStatus = FvmVm_AllocateVirtualMemory(procHandle, &pObjectAttributes, 0, &size,
							MEM_COMMIT, PAGE_EXECUTE_READWRITE);

				//	DbgPrint("There is no more entry.....\n");
					if (ntStatus != STATUS_SUCCESS) {
						DbgPrint("-->memory allocation problem(%d,NtEnumerateKey0)\n",(ULONG)PsGetCurrentProcessId());
						size = 0;
						FvmVm_FreeVirtualMemory(procHandle, &buff, &size, MEM_RELEASE);
						goto NtExit;
					}
					
		(char *)pObjectName = ((char *)pObjectAttributes ) +  sizeof(OBJECT_ATTRIBUTES);
		(char *)pOriHandle = ((char *)pObjectName)+sizeof(UNICODE_STRING);
		(char *)pOriName =	 ((char *)pOriHandle )+sizeof(HANDLE);

		
		kp =wcsstr(regName, L"fvms");
		if(kp){
			kp = kp+37;			
		}	
		if (_wcsnicmp(kp, L"\\Registry", 9)!=0){
			ntStatus = STATUS_NO_MORE_ENTRIES;			
		
			size = 0;
			FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size, MEM_RELEASE);
			goto NtExit;
		}
		//DbgPrint("regName............... %S--- %S\n", kp, regName);
		wcscpy(pOriName, kp);
		pObjectName->Length = wcslen(pOriName)*2;
						
		pObjectName->MaximumLength = 1024;
		pObjectName->Buffer = pOriName;
		InitializeObjectAttributes(pObjectAttributes, pObjectName,
								OBJ_CASE_INSENSITIVE, NULL, NULL);
		ntStatus = winNtOpenKeyProc(pOriHandle, KEY_ENUMERATE_SUB_KEYS, pObjectAttributes);
									
		if (ntStatus != STATUS_SUCCESS) {
			hostDir = 0;
		}
		else{
			hostDir = *pOriHandle;		
		}

		fvmIndex = 0;
		hostIndex  = 0;
		enumDirection = 0; //11 fvm forward
		
		
		
		/*
		 * Add the mapping between the two handles into the handle
		* table.
		*/		
		handleEntry = FvmTable_HandleTableAddEx(KeyHandle, hostDir, vmId, fvmIndex, hostIndex, enumDirection);
		size = 0;
		FvmVm_FreeVirtualMemory(procHandle, &pObjectAttributes, &size, MEM_RELEASE);

	}

	if (handleEntry == NULL){
		ntStatus = STATUS_NO_MORE_ENTRIES;	
		goto NtExit;
	}

	cachedHandleEntry = handleEntry;
		/*
		 * Given a directory handle, if we can find a matched entry in the
		 * handle table, and the hostDir field is not empty, we then know that
		 * we have finished the directory query on the VM's workspace, and
		 * we should use the hostDir handle to continue query the directory
		 * on the host environment.
		 */

	if (handleEntry->enumDirection) {
		ntStatus = FvmReg_EnumerateHostKey(handleEntry, KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength, vmId,	procHandle);
		if (ntStatus != STATUS_SUCCESS && handleEntry == cachedHandleEntry) {
			cachedHandleEntry = NULL;
		}
		goto NtExit;
	}
	else{

#if 0
				/*
				  * We need bigger sized structure than the one passed by the program
				  */
				tmpSize = Length*2;
				if (tmpSize < 1024)
					tmpSize = 1024;
				else if (tmpSize < 2048)
					tmpSize = 2048;
				else if (tmpSize < 4096)
					tmpSize = 4096;
				else
					tmpSize = 8192;
		
				size = tmpSize*2 + 4;
			
				buff = NULL;
				ntStatus = FvmVm_AllocateVirtualMemory(procHandle, &buff, 0, &size,
							MEM_COMMIT, PAGE_EXECUTE_READWRITE);

				
				if (ntStatus != STATUS_SUCCESS) {
					DbgPrint("-->memory allocation problem(%d,NtEnumerateKey0)\n",(ULONG)PsGetCurrentProcessId());
					goto NtExit;
				}
		
				keyInfo = (PVOID)(((char *)buff)+tmpSize);
				rSize = (int *)(((char*)buff)+tmpSize*2);
				ntStatus = winNtEnumerateKeyProc( KeyHandle, handleEntry->fvmIndex++, KeyInformationClass, keyInfo, tmpSize, rSize );
#else

				ntStatus= winNtEnumerateKeyProc(KeyHandle, handleEntry->fvmIndex++,	KeyInformationClass, KeyInformation, Length, ResultLength);
#endif
				if (ntStatus == STATUS_NO_MORE_ENTRIES){			
					handleEntry->enumDirection = 1;
					ntStatus = FvmReg_EnumerateHostKey(handleEntry, KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength, vmId,	procHandle);
#if 0					
					size = 0;
					FvmVm_FreeVirtualMemory(procHandle, &buff, &size, MEM_RELEASE);
#endif					
					
					goto NtExit;
					
				}
				else if (ntStatus != STATUS_SUCCESS) {
					FvmTable_HandleTableRemove(KeyHandle, vmId);
					cachedHandleEntry = NULL;
#if 0					
					size = 0;
					FvmVm_FreeVirtualMemory(procHandle, &buff, &size, MEM_RELEASE);
#endif
					goto NtExit;
				 }
#if 0				
				if (KeyInformationClass == KeyFullInformation) {
						memcpy(KeyInformation, keyInfo, *rSize);
				}
				else if (KeyInformationClass == KeyBasicInformation) {
					PKEY_BASIC_INFORMATION keyBasic =
							(PKEY_BASIC_INFORMATION) keyInfo;
					PKEY_BASIC_INFORMATION keyBasic1 =
							(PKEY_BASIC_INFORMATION) KeyInformation;
		
					   wc = keyBasic->Name[keyBasic->NameLength/2];
					   keyBasic->Name[keyBasic->NameLength/2]=L'\0';
					   wptr = wcsstr(keyBasic->Name, pvms[vmId]->idStr);
						DbgPrint(".............> %S\n", keyBasic->Name);
		
						/*
						 * Get rid of our prefix.
						 */
					if (wptr) {
						wptr = wcschr(wptr, L'\\');
						wcscpy(buff, wptr);
						wcscpy(keyBasic1->Name, buff);
		
						keyBasic1->NameLength = wcslen(keyBasic1->Name)*2;
						keyBasic1->Name[keyBasic1->NameLength/2] = wc;
					} else {
						wcscpy(keyBasic1->Name, keyBasic->Name);
						keyBasic1->NameLength = wcslen(keyBasic1->Name)*2;
						keyBasic1->Name[keyBasic1->NameLength/2] = wc;
					}
		
					keyBasic1->LastWriteTime = keyBasic->LastWriteTime;
					keyBasic1->TitleIndex = keyBasic->TitleIndex;
					*ResultLength = *rSize - (keyBasic->NameLength -
									keyBasic1->NameLength);
				} else if (KeyInformationClass ==
					KeyNodeInformation) {
					PKEY_NODE_INFORMATION keyNode = (PKEY_NODE_INFORMATION)keyInfo;
					PKEY_NODE_INFORMATION keyNodeOut =
							(PKEY_NODE_INFORMATION)KeyInformation;
		
					wc = keyNode->Name[keyNode->NameLength/2];
					keyNode->Name[keyNode->NameLength/2]=L'\0';
					DbgPrint(".............> %S\n", keyNode->Name);
					wptr = wcsstr(keyNode->Name, pvms[vmId]->idStr);
					if (wptr) {
						wptr = wcschr(wptr, L'\\');
						wcscpy(buff, wptr);
						wcscpy(keyNodeOut->Name, wptr);
						keyNodeOut->NameLength = wcslen(keyNodeOut->Name) * 2;
						keyNodeOut->ClassOffset = keyNode->ClassOffset -
								(keyNode->NameLength - keyNodeOut->NameLength);
					} else {
						wcscpy(keyNodeOut->Name, keyNode->Name);
						keyNodeOut->ClassOffset=keyNode->ClassOffset;
						keyNodeOut->NameLength = wcslen(keyNodeOut->Name)*2;
					}
					keyNodeOut->Name[keyNode->NameLength/2]=wc;
					keyNodeOut->LastWriteTime = keyNode->LastWriteTime;
					keyNodeOut->TitleIndex = keyNode->TitleIndex;
					keyNodeOut->ClassLength = keyNode->ClassLength;
					memcpy(((char *)KeyInformation)+keyNodeOut->ClassOffset,
						((char *)keyInfo)+keyNode->ClassOffset,
						keyNodeOut->ClassLength);
					*ResultLength = *rSize - (keyNode->NameLength -
						keyNodeOut->NameLength);
				 } else if (KeyInformationClass == KeyNameInformation) {
					PKEY_NAME_INFORMATION keyName = (PKEY_NAME_INFORMATION)keyInfo;
					PKEY_NAME_INFORMATION keyNameOut =
							(PKEY_NAME_INFORMATION)KeyInformation;
		
					wc = keyName->Name[keyName->NameLength/2];
					keyName->Name[keyName->NameLength/2] = L'\0';

					DbgPrint(".............> %S\n", keyName->Name);
					wptr = wcsstr(keyName->Name, pvms[vmId]->idStr);
					if (wptr) {
						wptr = wcschr(wptr, L'\\');
						wcscpy(buff, wptr);
						wcscpy(keyNameOut->Name, buff);
						keyNameOut->NameLength = wcslen(keyNameOut->Name)*2;
					} else {
						wcscpy(keyNameOut->Name, keyName->Name);
						keyNameOut->NameLength = wcslen(keyNameOut->Name)*2;
					}
					*ResultLength = *rSize - (keyName->NameLength -
							keyNameOut->NameLength);
					keyNameOut->Name[keyNameOut->NameLength/2] = wc;
				 }

	
				size = 0;
				FvmVm_FreeVirtualMemory(procHandle, &buff, &size, MEM_RELEASE);
#endif
			
				goto NtExit;



	}
	
NtExit:
#if 0
		if (vmId!= INVALID_VMID) {
			WCHAR keyName[300];
			PWCHAR kp;
			WCHAR bp[256];
			FvmUtil_GetBinaryPathName(bp);
			if(1){	
				GetRegKeyName(KeyHandle, keyName);
			
				kp =wcsstr(keyName, L"fvms");
				if(kp){
					kp = wcsstr(keyName, L"\\Registry");
					if(!kp)
						kp = keyName;
						
				}	
				else
					kp = keyName;
				
				if (ntStatus == STATUS_SUCCESS) {
					switch(KeyInformationClass){
					case KeyBasicInformation:{
						PKEY_BASIC_INFORMATION n1 =
							(PKEY_BASIC_INFORMATION) KeyInformation;
						n1->Name[n1->NameLength/2] = L'\0';
						DbgPrint("EnumerateKey: KeyBasicInformation: %d %S --> %S\n",Index, kp, n1->Name);
						break;
						}
					case KeyNodeInformation:{
						PKEY_NODE_INFORMATION n2 =
							(PKEY_NODE_INFORMATION)KeyInformation;
								n2->Name[n2->NameLength/2] = L'\0';
						DbgPrint("EnumerateKey: KeyNodeInformation: %d  %S --> %S\n", Index, kp, n2->Name);
						break;
						}
					case KeyFullInformation:
						DbgPrint("EnumerateKey: KeyFullInformation: %d %S\n",Index, kp);
						break;
					case KeyNameInformation:{
					
						PKEY_NAME_INFORMATION n3 =
											(PKEY_NAME_INFORMATION)KeyInformation;
								n3->Name[n3->NameLength/2] = L'\0';
						DbgPrint("EnumerateKey: KeyNameInformation:%d  %S --> %S\n",Index, kp, n3->Name);
						break;
						}
					default:
						DbgPrint("EnumerateKey: unknown class\n");
					
					}
				}
				else{
	
					DbgPrint("EnumerateKey: %d fail..... %x %S\n", Index, ntStatus, kp);
				}
					//}
			}
		}
#endif 

	InterlockedDecrement (&fvm_Calls_In_Progress);

	return ntStatus;
}




NTSTATUS
FvmReg_NtEnumerateKey (
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
) {
	NTSTATUS ntStatus;
//	int vmn;

	InterlockedIncrement(&fvm_Calls_In_Progress);
		//vmn = FvmUtil_VmNumber();
	try {
		ntStatus = FvmReg_NtEnumerateKeyEx(KeyHandle, Index,
				    KeyInformationClass, KeyInformation, Length, ResultLength);
		

	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FvmReg_NtEnumerateKey\n"));
		ntStatus= -1;
	}
	InterlockedDecrement (&fvm_Calls_In_Progress);

	/*
	if (vmn != INVALID_VMID) {
			DbgPrint("NtEnumerateKey hand: %x status: %x\n", KeyHandle, ntStatus);
		}
		*/

	return ntStatus;
}


//----------------------------------------------------------------------
//
// HookRegSetValueKey
//
//----------------------------------------------------------------------
NTSTATUS
FvmReg_NtSetValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex,
	IN ULONG Type,
	IN PVOID Data,
	IN ULONG DataSize
) {
	NTSTATUS	ntStatus = -1;
	int	vmn;

	try {
		vmn = FvmUtil_VmNumber();

		ntStatus = winNtSetValueKeyProc(KeyHandle, ValueName, TitleIndex,
				    Type, Data, DataSize);

		return ntStatus;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FvmReg_NtSetValueKey\n"));
	}

	return ntStatus;
}


/*
 * This is a documented Zw-class function.
 */
NTSTATUS
FvmReg_NtQueryValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation,
	IN ULONG Length,
	OUT PULONG  ResultLength
) {
	NTSTATUS	ntStatus;
	int	vmn;

	WCHAR name_rqk[_MAX_PATH];
	WCHAR RegPath[_MAX_PATH]={L'\0'};
		
	vmn = FvmUtil_VmNumber();

	ntStatus = winNtQueryValueKeyProc(KeyHandle, ValueName,
    			KeyValueInformationClass, KeyValueInformation, Length,
    			ResultLength);

	if (vmn != INVALID_VMID) {
		DbgPrint("NtQueryValueKey hand: %x status: %x %S\n", KeyHandle, ntStatus, ValueName);
	}

	return ntStatus;
}


/*
 * This is a documented Zw-class function.
 */
NTSTATUS
FvmReg_NtEnumerateValueKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation,
	IN ULONG Length,
	OUT PULONG  pResultLength
) {
	NTSTATUS                ntStatus;
	int                     vmn;
	PWCHAR                 wptr;
	WCHAR                  twc;
	int                    dLen;

	vmn = FvmUtil_VmNumber();

	ntStatus = winNtEnumerateValueKeyProc(KeyHandle, Index,
    			KeyValueInformationClass, KeyValueInformation, Length,
    			pResultLength );

	if (vmn != INVALID_VMID) {
		DbgPrint("NtEnumerateValueKey hand: %x status: %x\n", KeyHandle, ntStatus);
	}
	return ntStatus;
}
