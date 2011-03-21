/* **********************************************************
 * Copyright 2007 Rether Networks, Inc.  All rights reserved.
 * *********************************************************
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
 *  FVM object virtualization
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include "fvm_util.h"
#include "fvm_table.h"
#include "hooksys.h"
#include "fvm_vm.h"
#include "fvm_syscalls.h"
#include "fvm_obj.h"

#define FVM_OBJ_POOL_TAG '4GAT'

HANDLE   FVM_ObjectDirectoryHandle[MAX_VM];
HANDLE   FVM_PortDirectoryHandle[MAX_VM];


// Convert the original object path into a virtualized object path
BOOLEAN MapObjectPath(IN PWCHAR sourcename, IN ULONG  vmid,
    OUT PWCHAR destname)
{
		PWCHAR dirptr;
		PWCHAR objprefix = CONF_OBJ_PATH;
		PWCHAR global_ns = L"Global\\";
		PWCHAR local_ns = L"Local\\";
		int nlen;
		BOOLEAN global = FALSE;

		//DbgPrint("sourcename: %S", sourcename);
		if(wcsstr(sourcename, L"dofs-instance-semaphore")){
			//DbgPrint("sourcename:	dofs-instance-semaphore");
			return FALSE;
		}

		if(wcsstr(sourcename, L"DBWinMutex")) //outputdebugstring
			return FALSE;
		
		nlen = wcslen(objprefix);
		if (wcsncmp(sourcename, objprefix, nlen) != 0) return FALSE;
	
		dirptr = sourcename + nlen;
	
		// Global named objects created inside the VM are mapped to local ones
		nlen = wcslen(global_ns);
		if (wcsncmp(dirptr, global_ns, nlen) == 0) {
			if (wcsstr(dirptr, L"_MSIExecute")||wcsstr(dirptr, L"SvcctrlStartEvent_A3752DX"))
				return FALSE;
			dirptr = dirptr + nlen; 
			global = TRUE;
			return FALSE;
		}
	
		nlen = wcslen(local_ns);
		if (wcsncmp(dirptr, local_ns, nlen) == 0)
			dirptr = dirptr + nlen;
	
		if(*dirptr == L'\0')
			return FALSE;
	
		_snwprintf(destname, _MAX_PATH, L"%sFVM-%u\\%s", objprefix, vmid, dirptr);
		return TRUE;
}


// Convert the original port object path into a virtualized object path
BOOLEAN MapPortObjectPath(IN PWCHAR sourcename, IN ULONG  vmid,
    OUT PWCHAR destname)
{
	PWCHAR dirptr;
	PWCHAR portprefix = CONF_PORT_PATH;
	PWCHAR global_ns = L"Global\\";
	PWCHAR local_ns = L"Local\\";
//#ifndef RPCSS
	PWCHAR ole_ns = L"OLE";
	PWCHAR rpc_ns = L"epmapper";	
// #endif
	int nlen;

	nlen = wcslen(portprefix);
	if (wcsncmp(sourcename, portprefix, nlen) != 0) return FALSE;

	dirptr = sourcename + nlen;

// #ifndef RPCSS
	//for access COM or RPC server from vm
	if((wcsncmp(dirptr,ole_ns,3)==0)||(wcsncmp(dirptr,rpc_ns,8)==0)){
//DbgPrint("%d,MapPortObjectPath:%S\n", PsGetCurrentProcessId(),sourcename);		
		return FALSE;		
	}
//#endif

	nlen = wcslen(global_ns);
	if (wcsncmp(dirptr, global_ns, nlen) == 0) {
		//    DbgPrint("Object should be in global name space:%S\n", sourcename);
		  return FALSE;
	}

	nlen = wcslen(local_ns);
	if (wcsncmp(dirptr, local_ns, nlen) == 0)
		dirptr = dirptr + nlen;

	_snwprintf(destname, _MAX_PATH, L"%sFVM-%u\\%s", portprefix, vmid, dirptr);
	return TRUE;
}


// Convert the original object path into a virtualized object path
BOOLEAN MapSectionObjectPath(IN PWCHAR sourcename, IN ULONG  vmid,
    OUT PWCHAR destname)
{
	PWCHAR dirptr;
	PWCHAR objprefix = CONF_OBJ_PATH;
	PWCHAR global_ns = L"Global\\";
	PWCHAR local_ns = L"Local\\";
	int nlen;
	BOOLEAN global = FALSE;

	nlen = wcslen(objprefix);
	if (wcsncmp(sourcename, objprefix, nlen) != 0) return FALSE;

	dirptr = sourcename + nlen;

	
	if (wcsstr(sourcename, L"\\BaseNamedObjects\\DBWIN_BUFFER")){ //for OutputDebugString 		\BaseNamedObjects\DBWIN_BUFFER
		return FALSE;
	}

	if(wcsstr(sourcename,L"03AA71A5-5A26-46ED-B650-8545381EB957")){ //AutoCAD 2009 License Server
		return FALSE;
	}

	if(wcsstr(sourcename,L"2A9FCEB5-A43F-4EB8-950B-879706CAF379"))//solidwork licence server
			return FALSE;

	
	if(wcsstr(sourcename,L"__R_00000000000f_SMem__")){
		return FALSE;
	}
		
		
	if(wcsstr(sourcename,L"__R_000000000007_SMem__")){
		return FALSE;
	}
	
	if(wcsstr(sourcename,L"mmGlobalPnpInfo")){
		return FALSE;
	}
	
	if(wcsstr(sourcename,L"ComPlusCOMRegTable")){
		return FALSE;
	}
	
	if(wcsstr(sourcename,L"RotHintTable")){
		return FALSE;
	}


	
    //the global section object is also virtualized. 
    //The format of path of virtualized global section object is "\BaseNamedObjects\Global\FVM-0\sectionObjectName"
	nlen = wcslen(global_ns);
	if (wcsncmp(dirptr, global_ns, nlen) == 0) {
		if (wcsstr(dirptr, L"ClipboardOwnerFVMFilemap"))
			return FALSE;
		dirptr = dirptr + nlen;	
		global = TRUE;
	}

	nlen = wcslen(local_ns);
	if (wcsncmp(dirptr, local_ns, nlen) == 0)
		dirptr = dirptr + nlen;

	if(*dirptr == L'\0')
		return FALSE;

	if(global)
		_snwprintf(destname, _MAX_PATH, L"%s%sFVM-%u\\%s", objprefix, global_ns,vmid, dirptr);
	else
		_snwprintf(destname, _MAX_PATH, L"%sFVM-%u\\%s", objprefix, vmid, dirptr);
	
	return TRUE;
}


NTSTATUS FvmObj_NtCreateMutant(OUT PHANDLE hMutex,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes,
    IN BOOLEAN bOwnMutant)
{
	NTSTATUS rc;
	//PWCHAR BinPath = NULL;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG memsize = _MAX_PATH*2;
	ULONG vmid = 0, pid = -1;
       PWCHAR objectName=NULL;
	PWCHAR vobjname=NULL;
    
	InterlockedIncrement(&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID) goto Original_Call;

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtCreateMutant: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
       
	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtCreateMutant: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
	if (!MapObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
		//CHAR errstr[64];
		//DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));
		DbgPrint("FvmObj_NtCreateMutant ErrMem:%x\n", rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtCreateMutantProc)(winNtCreateMutantProc)) (hMutex, desiredAccess, poa,
	         bOwnMutant);

	//DbgPrint("CreateMutant: %x %S--%S\n", rc, objectName, vobjname);
	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtCreateMutantProc)(winNtCreateMutantProc)) (hMutex, desiredAccess,
	         objectAttributes, bOwnMutant);
	
NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	}   
	InterlockedDecrement(&fvm_Calls_In_Progress);
	return rc;
}


NTSTATUS FvmObj_NtOpenMutant(OUT PHANDLE hMutex, IN ACCESS_MASK desiredAccess,
    IN POBJECT_ATTRIBUTES objectAttributes)
{
	NTSTATUS rc;
	//PWCHAR BinPath = NULL;
	ULONG memsize = _MAX_PATH*2;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG vmid = 0, pid = -1;
       PWCHAR objectName=NULL;
	PWCHAR vobjname=NULL;
    
	InterlockedIncrement(&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID)  goto Original_Call;

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtOpenMutant: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
       
	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtOpenMutant: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
       
	if (!MapObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
		/*CHAR errstr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtOpenMutant ErrMem:%x\n", rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtOpenMutantProc)(winNtOpenMutantProc)) (hMutex, desiredAccess, poa);

	//DbgPrint("OpenMutant: %x %S--%S\n", rc, ObjectName, vobjname);
	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtOpenMutantProc)(winNtOpenMutantProc)) (hMutex, desiredAccess,
		     objectAttributes);
NtExit:
	if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	}   	
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}


NTSTATUS FvmObj_NtCreateSemaphore(OUT PHANDLE hSemaphore,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes,
    IN ULONG initialCount, IN ULONG maximumCount)
{
	NTSTATUS rc;
	//   PWCHAR BinPath = NULL;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG memsize = _MAX_PATH*2;
	ULONG vmid = 0, pid = -1;
       PWCHAR objectName=NULL;
	PWCHAR vobjname=NULL;
    
	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID) goto Original_Call;
    
       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtCreateSemaphore: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
       
	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	
	if(!objectName[0]) goto Original_Call;


	if (wcsstr(objectName, L"\\BaseNamedObjects\\OleDfRoot") != NULL){ //for Visio copy to word in office 2003
			//DbgPrint("----FvmObj_NtCreateSemaphore: %S", objectName);
			  goto Original_Call;
	}

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtCreateSemaphore: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
   
	if (!MapObjectPath(objectName, vmid, vobjname)) goto Original_Call; 

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
		/*CHAR errstr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtCreateSemaphore ErrMem:%x\n", rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtCreateSemaphoreProc)(winNtCreateSemaphoreProc)) (hSemaphore,
		     desiredAccess, poa, initialCount, maximumCount);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtCreateSemaphoreProc)(winNtCreateSemaphoreProc)) (hSemaphore,
		     desiredAccess, objectAttributes, initialCount, maximumCount);
NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	}   
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtOpenSemaphore(OUT PHANDLE hSemaphore,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes)
{
   NTSTATUS rc;
   //PWCHAR BinPath = NULL;
   POBJECT_ATTRIBUTES poa = NULL;
   ULONG memsize = _MAX_PATH*2;
   ULONG vmid = 0, pid = -1;
   PWCHAR objectName=NULL;
   PWCHAR vobjname=NULL;
    
   InterlockedIncrement (&fvm_Calls_In_Progress);
   if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
   }

   pid = (ULONG)PsGetCurrentProcessId();
   vmid = FvmVm_GetPVMId(pid);

   if (vmid == INVALID_VMID)  goto Original_Call;

   objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
   if (objectName == NULL) {
              DbgPrint("FvmObj_NtOpenSemaphore: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
   }

   if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
   }

   if(!objectName[0]) goto Original_Call;

   vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
   if (vobjname == NULL) {
              DbgPrint("FvmObj_NtOpenSemaphore: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
   }
   
   if (!MapObjectPath(objectName, vmid, vobjname)) goto Original_Call; 

   DbgPrint("opensemaphore: %S\n", objectName);


   rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
   if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtOpenSemaphore ErrMem:%x\n",rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
   }

   rc = ((NtOpenSemaphoreProc)(winNtOpenSemaphoreProc)) (hSemaphore, desiredAccess,
		    poa);

	memsize = 0;
   FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
   goto NtExit;

Original_Call:
   rc = ((NtOpenSemaphoreProc)(winNtOpenSemaphoreProc)) (hSemaphore, desiredAccess,
		    objectAttributes);

NtExit:
   if (objectName) {
         ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
   }     
   if (vobjname) {
         ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
   }   
   InterlockedDecrement (&fvm_Calls_In_Progress);
   return rc;
}

NTSTATUS FvmObj_NtCreateEvent(OUT PHANDLE hEvent, IN ACCESS_MASK desiredAccess,
    IN POBJECT_ATTRIBUTES objectAttributes, IN EVENT_TYPE eventType,
    IN BOOLEAN bInitialState)
{
	NTSTATUS rc;
	//   PWCHAR BinPath = NULL;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG memsize = _MAX_PATH*2;
	ULONG vmid = 0, pid = -1;
       PWCHAR objectName=NULL;
       PWCHAR vobjname=NULL;


	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID) goto Original_Call;

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtCreateEvent: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
       }
       
	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;
       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtCreateEvent: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
	if (!MapObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtCreateEvent ErrMem:%x\n", rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtCreateEventProc)(winNtCreateEventProc)) (hEvent, desiredAccess, poa,
		     eventType, bInitialState);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtCreateEventProc)(winNtCreateEventProc)) (hEvent, desiredAccess,
		     objectAttributes, eventType, bInitialState);

NtExit:
       if (objectName) {
         ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
       }     
       if (vobjname) {
         ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
       }  
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtOpenEvent(OUT PHANDLE hEvent, IN ACCESS_MASK desiredAccess,
    IN POBJECT_ATTRIBUTES objectAttributes)
{
	NTSTATUS rc;
	//PWCHAR BinPath = NULL;
	ULONG memsize = _MAX_PATH*2;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG vmid = 0, pid = -1;
       PWCHAR objectName=NULL;
       PWCHAR vobjname=NULL;

	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID)  goto Original_Call;
    
       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtCreateEvent: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
       }
       
	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;
	else {
		WCHAR eventName[16];
		swprintf(eventName, L"fvm%u", pid);
		if (wcsstr(objectName, eventName)) {
			goto Original_Call;
		}
	}
       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtCreateEvent: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
       
	if (!MapObjectPath(objectName, vmid, vobjname))  goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtCreateEvent ErrMem:%x\n", rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtOpenEventProc)(winNtOpenEventProc)) (hEvent, desiredAccess, poa);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtOpenEventProc)(winNtOpenEventProc)) (hEvent, desiredAccess,
		     objectAttributes);

NtExit:
       if (objectName) {
         ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
       }     
       if (vobjname) {
         ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
       }  
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtCreateSection (OUT PHANDLE phSection,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes,
    IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG sectionPageProtection,
    IN ULONG allocationAttributes, IN HANDLE hFile OPTIONAL)
{
	NTSTATUS rc;
	//PWCHAR BinPath = NULL;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG memsize = _MAX_PATH*2;
	ULONG vmid = 0, pid = -1;
	PWCHAR objectName=NULL;
	PWCHAR vobjname=NULL;

	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID) goto Original_Call;

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtCreateSection: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}
	
	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtCreateSection: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
	if (!MapSectionObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
//		CHAR errstr[64];
//		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));
		DbgPrint("FvmObj_NtCreateSection ErrMem:%x\n",rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
	
	rc = ((NtCreateSectionProc)(winNtCreateSectionProc)) (phSection, desiredAccess,
		     poa, MaximumSize, sectionPageProtection, allocationAttributes,
		     hFile);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtCreateSectionProc)(winNtCreateSectionProc)) (phSection, desiredAccess,
		     objectAttributes, MaximumSize, sectionPageProtection,
		     allocationAttributes, hFile);

NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	}   
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtOpenSection(OUT PHANDLE phSection,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes)
{
	NTSTATUS rc;
	//PWCHAR BinPath = NULL;
	ULONG memsize = _MAX_PATH*2;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG vmid = 0, pid = -1;
       PWCHAR objectName=NULL;
	PWCHAR vobjname=NULL;


	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID)  goto Original_Call;

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtOpenSection: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}


	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtOpenSection: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}


	if (!MapSectionObjectPath(objectName, vmid, vobjname))  goto Original_Call;
	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtOpenSection ErrMem:%x\n",rc);		
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtOpenSectionProc)(winNtOpenSectionProc)) (phSection, desiredAccess, poa);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtOpenSectionProc)(winNtOpenSectionProc)) (phSection, desiredAccess,
		     objectAttributes);

NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	}  
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtCreateTimer(OUT PHANDLE phTimer,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes,
    IN TIMER_TYPE timerType)
{
	NTSTATUS rc;
	//PWCHAR BinPath = NULL;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG memsize = _MAX_PATH*2;
	ULONG vmid = 0, pid = -1;
       PWCHAR objectName=NULL;
	PWCHAR vobjname=NULL;


	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID) goto Original_Call;

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtCreateTimer: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtCreateTimer: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (!MapObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtCreateTimer ErrMem:%x\n",rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtCreateTimerProc)(winNtCreateTimerProc)) (phTimer, desiredAccess, poa,
		     timerType);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtCreateTimerProc)(winNtCreateTimerProc)) (phTimer, desiredAccess,
		     objectAttributes, timerType);

NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	} 
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtOpenTimer(OUT PHANDLE phTimer, IN ACCESS_MASK desiredAccess,
    IN POBJECT_ATTRIBUTES objectAttributes)
{
   NTSTATUS rc;
   //PWCHAR BinPath = NULL;
   POBJECT_ATTRIBUTES poa = NULL;
   ULONG memsize = _MAX_PATH*2;
   ULONG vmid = 0, pid = -1;
   PWCHAR objectName=NULL;
   PWCHAR vobjname=NULL;

   InterlockedIncrement (&fvm_Calls_In_Progress);
   if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
   }

   pid = (ULONG)PsGetCurrentProcessId();
   vmid = FvmVm_GetPVMId(pid);

   if (vmid == INVALID_VMID)  goto Original_Call;
   
       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtOpenTimer: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
       
   if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
   }

   if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtOpenTimer: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}   

   if (!MapObjectPath(objectName, vmid, vobjname))  goto Original_Call;

   rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
   if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtOpenTimer ErrMem:%x\n",rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
   }

   rc = ((NtOpenTimerProc)(winNtOpenTimerProc)) (phTimer, desiredAccess, poa);

	memsize = 0;
   FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
   goto NtExit;

Original_Call:
   rc = ((NtOpenTimerProc)(winNtOpenTimerProc)) (phTimer, desiredAccess,
   	        objectAttributes);

NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	} 
   InterlockedDecrement (&fvm_Calls_In_Progress);
   return rc;
}

NTSTATUS FvmObj_NtCreateIoCompletion(OUT PHANDLE phIoCompletionPort,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes,
    IN ULONG nConcurrentThreads)
{
	NTSTATUS rc;
	//PWCHAR BinPath = NULL;
//	WCHAR objectName[_MAX_PATH*2];
	POBJECT_ATTRIBUTES poa = NULL;
//	WCHAR vobjname[_MAX_PATH*2];
	ULONG memsize = _MAX_PATH*2;
	ULONG vmid = 0, pid = -1;
   PWCHAR objectName=NULL;
   PWCHAR vobjname=NULL;


	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
	  goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID) goto Original_Call;

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtCreateIoCompletion: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtCreateIoCompletion: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	} 

	if (!MapObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtCreateIoCompletion ErrMem:%x\n",rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtCreateIOCompletionProc)(winNtCreateIOCompletionProc)) (phIoCompletionPort,
		     desiredAccess, poa, nConcurrentThreads);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtCreateIOCompletionProc)(winNtCreateIOCompletionProc)) (phIoCompletionPort,
		     desiredAccess, objectAttributes, nConcurrentThreads);

NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	} 
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtOpenIoCompletion(OUT PHANDLE phIoCompletionPort,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes)
{
	NTSTATUS rc;
	//PWCHAR BinPath = NULL;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG memsize = _MAX_PATH*2;
	ULONG vmid = 0, pid = -1;
       PWCHAR objectName=NULL;
       PWCHAR vobjname=NULL;


	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID)  goto Original_Call;

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtOpenIoCompletion: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtOpenIoCompletion: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	} 

	if (!MapObjectPath(objectName, vmid, vobjname))  goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("FvmObj_NtOpenIoCompletion ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtOpenIoCompletion ErrMem:%x\n",rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtOpenIOCompletionProc)(winNtOpenIOCompletionProc)) (phIoCompletionPort,
		    desiredAccess, poa);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtOpenIOCompletionProc)(winNtOpenIOCompletionProc)) (phIoCompletionPort,
		     desiredAccess, objectAttributes);

NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	} 
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtCreateEventPair(OUT PHANDLE hEventPair,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes)
{
	NTSTATUS rc;
	//PWCHAR BinPath = NULL;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG memsize = _MAX_PATH*2;
	ULONG vmid = 0, pid = -1;
       PWCHAR objectName=NULL;
       PWCHAR vobjname=NULL;
       
	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID)  goto Original_Call;

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtCreateEventPair: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtCreateEventPair: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	} 

	if (!MapObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("FvmObj_NtCreateEventPair ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtCreateEventPair ErrMem:%x\n", rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

		rc = ((NtCreateEventPairProc)(winNtCreateEventPairProc)) (hEventPair,
		     desiredAccess, poa);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtCreateEventPairProc)(winNtCreateEventPairProc)) (hEventPair,
		     desiredAccess, objectAttributes);

NtExit:
        if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	} 
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}


NTSTATUS FvmObj_NtOpenProcess(
	OUT PHANDLE pHandle,
	IN ACCESS_MASK Access_Mask,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientID) {

	NTSTATUS rc = STATUS_SUCCESS;
	ULONG vmid = 0, pid = -1, CVmId = 0;

	//DbgPrint("Inside OpenProcess\n");

	   
   InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
	  goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);
	CVmId = FvmVm_GetPVMId((ULONG)ClientID->UniqueProcess);
	//DbgPrint("PID: %ld Client VMID ID %ld  myvmid = %ld\n", pid, CVmId, vmid);
	if (vmid != INVALID_VMID) {
		char * logs;
		IO_STATUS_BLOCK Iosb;
		logs = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
		if (logs == NULL) {
			DbgPrint("NtOpenProcess: ExAllocateFromPagedLookasideList fail\n");  
		}
		else{
			ticks tm = getticks();
			RtlStringCbPrintfA(logs, PATHSIZE, "%I64u, NtOpenProcess, %u, %u, %u\r\n",
				tm.QuadPart, (ULONG)PsGetCurrentProcessId(), (ULONG)ClientID->UniqueProcess, (ULONG)Access_Mask);
			//DbgPrint("#### %ld \n", vmid);
			ZwWriteFile(pvms[vmid]->logHandle, NULL, NULL, NULL, &Iosb, (void*)logs, strlen(logs)*sizeof(char), 
				NULL, NULL);
		}
		if(logs)
			ExFreePool(logs);
	}
	
#if 1
	if ((vmid != CVmId) && (vmid != INVALID_VMID)) {
		rc = STATUS_ACCESS_DENIED;
		//DbgPrint("OpenProcess..orig fn not called!\n");
		goto NtExit;
	}
#endif

Original_Call:
	rc = ((NTOpenProcess)(WinNtOpenProcess)) (
		  pHandle, Access_Mask, ObjectAttributes,
		  ClientID);
NtExit:
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}


NTSTATUS FvmObj_NtOpenEventPair(OUT PHANDLE hEventPair,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes)
{
	NTSTATUS rc;
	//PWCHAR BinPath = NULL;
	ULONG memsize = _MAX_PATH*2;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG vmid = 0, pid = -1;
       PWCHAR objectName=NULL;
       PWCHAR vobjname=NULL;

	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID)  goto Original_Call;

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtOpenEventPair: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtOpenEventPair: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	} 

	if (!MapObjectPath(objectName, vmid, vobjname))  goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("FvmObj_NtOpenEventPair ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtOpenEventPair ErrMem:%x\n",rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtOpenEventPairProc)(winNtOpenEventPairProc)) (hEventPair, desiredAccess,
		     poa);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
	goto NtExit;

Original_Call:
	rc = ((NtOpenEventPairProc)(winNtOpenEventPairProc)) (hEventPair, desiredAccess,
		     objectAttributes);

NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	} 
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtCreatePort(OUT PHANDLE portHandle,
    IN POBJECT_ATTRIBUTES objectAttributes, IN ULONG maxDataSize,
    IN ULONG maxMessageSize, IN ULONG reserved)
{
	NTSTATUS rc;
	PWCHAR BinPath = NULL, nameptr = NULL;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG memsize = _MAX_PATH*2;
	LONG vmid = 0, pid = -1;
       PWCHAR vobjname= NULL;
       PWCHAR objectName=NULL;

	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID)  goto Original_Call;
	
	//DbgPrint("Calling original function ntcreateport\n");

//	BinPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_OBJ_POOL_TAG);
       BinPath = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
	if (BinPath == NULL) goto Original_Call;

	FvmUtil_GetBinaryPathName(BinPath);
	if ((wcsstr(BinPath, L"msiexec") != NULL) ||
	  (wcsstr(BinPath, L"MsiExec") != NULL)) {
		if ((vmid == msi_owner) || (msi_owner == -1)) {
			ExFreePool(BinPath);
			goto Original_Call;
		}
	}
	//ExFreePool(BinPath);
	if (BinPath) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, BinPath );
	}
	
       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtCreatePort: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtCreatePort: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (!MapPortObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("FvmObj_NtCreatePort ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtCreatePort ErrMem:%x\n",rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtCreatePortProc)(winNtCreatePortProc)) (portHandle, poa, maxDataSize,
		     maxMessageSize, reserved);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);

	goto NtExit;

Original_Call:
	rc = ((NtCreatePortProc)(winNtCreatePortProc)) (portHandle, objectAttributes,
		     maxDataSize, maxMessageSize, reserved);

NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	}    
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtCreateWaitablePort(OUT PHANDLE portHandle,
    IN POBJECT_ATTRIBUTES objectAttributes, IN ULONG maxDataSize,
    IN ULONG maxMessageSize, IN ULONG reserved)
{
	NTSTATUS rc;
	PWCHAR BinPath = NULL;
	POBJECT_ATTRIBUTES poa = NULL;
	ULONG memsize = _MAX_PATH*2;
	LONG vmid = 0, pid = -1;
    	PWCHAR vobjname=NULL;
	PWCHAR objectName=NULL;
    
	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);


	if (vmid == INVALID_VMID)  goto Original_Call;
	//BinPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_OBJ_POOL_TAG);
	BinPath = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
	if (BinPath == NULL) goto Original_Call;

	FvmUtil_GetBinaryPathName(BinPath);

	if ((wcsstr(BinPath, L"msiexec") != NULL) ||
		(wcsstr(BinPath, L"MsiExec") != NULL)) {
		if ((vmid == msi_owner) || (msi_owner == -1)) {
			ExFreePool(BinPath);
			goto Original_Call;
		}
	}
	
	//DbgPrint("NtCreateWaitablePort : Application Name - %S\n", BinPath);
	if (BinPath) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, BinPath );
	}
	//ExFreePool(BinPath);
       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtCreateWaitablePort: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
	if (!FvmUtil_GetSysCallArgument(objectAttributes, objectName)) {
		goto Original_Call;
	}

	if(!objectName[0]) goto Original_Call;

       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtCreateWaitablePort: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (!MapPortObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	rc = FvmUtil_InitializeVMObjAttributes(objectAttributes, vobjname, &poa, &memsize);
	if (!NT_SUCCESS(rc)) {
/*		CHAR errstr[64];
		DbgPrint("FvmObj_NtCreateWaitablePort ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtCreateWaitablePort ErrMem:%x\n",rc);
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	rc = ((NtCreateWaitablePortProc)(winNtCreateWaitablePortProc)) (portHandle, poa,
		     maxDataSize, maxMessageSize, reserved);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &poa, &memsize, MEM_RELEASE);
#if 0
	if (NT_SUCCESS(rc))
#endif
	goto NtExit;

Original_Call:
	rc = ((NtCreateWaitablePortProc)(winNtCreateWaitablePortProc)) (portHandle,
		     objectAttributes, maxDataSize, maxMessageSize, reserved);

NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	}    
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtConnectPort(OUT PHANDLE portHandle,
    IN PUNICODE_STRING portName, IN PSECURITY_QUALITY_OF_SERVICE securityQos,
    IN OUT PPORT_SECTION_WRITE WriteSection OPTIONAL,
    IN OUT PPORT_SECTION_READ ReadSection OPTIONAL,
    OUT PULONG maxMessageSize OPTIONAL, IN OUT PVOID ConnectData OPTIONAL,
    IN OUT PULONG ConnectDataLength OPTIONAL)
{
	NTSTATUS rc;
	PWCHAR binPath = NULL, BinPath = NULL;
	PUNICODE_STRING pName = NULL;
	PWCHAR vdiruser = NULL;
	ULONG memsize = _MAX_PATH*2;
	LONG vmid = 0, pid = -1;
	ULONG len;
	PWCHAR vobjname=NULL;
    	PWCHAR objectName=NULL;
        
       InterlockedIncrement (&fvm_Calls_In_Progress);
       if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}
       pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID)  goto Original_Call;
	
//	BinPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_OBJ_POOL_TAG);
       BinPath = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
	if (BinPath == NULL) goto Original_Call;

	FvmUtil_GetBinaryPathName(BinPath);

	if ((wcsstr(BinPath, L"msiexec") != NULL) ||
		(wcsstr(BinPath, L"MsiExec") != NULL)) {
		if ((vmid == msi_owner) || (msi_owner == -1)) {
			ExFreePool(BinPath);
			goto Original_Call;
		}
	}

	//DbgPrint("NtConnectPort : Application Name - %S\n", BinPath);
//	ExFreePool(BinPath);
       if (BinPath) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, BinPath );
	}

       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtConnectPort: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtConnectPort: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (portName && portName->Buffer) {
		len = (portName->Length) >> 1;
		wcsncpy(objectName, portName->Buffer, len);
		objectName[len] = 0;
	} else {
		goto Original_Call;
	}

	if (!MapPortObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	memsize = sizeof(UNICODE_STRING) + /*wcslen(vobjname)*/_MAX_PATH*2 + 2;
	rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(), &pName, 0, &memsize,
		     MEM_COMMIT, PAGE_READWRITE);

	if (NT_SUCCESS(rc)) {
		(char *)vdiruser = ((char *)pName) + sizeof(UNICODE_STRING);
		wcsncpy(vdiruser, vobjname,wcslen(vobjname)); //_MAX_PATH);
		vdiruser[wcslen(vobjname)] = L'\0';
		RtlInitUnicodeString(pName, vdiruser);
	} else {
/*		CHAR errstr[64];
		DbgPrint("FvmObj_NtConnectPort ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtConnectPort ErrMem:%x\n", rc);
		goto Original_Call;
	}

	rc = ((NtConnectPortProc)(winNtConnectPortProc)) (portHandle, pName, securityQos,
		     WriteSection, ReadSection, maxMessageSize, ConnectData,
		     ConnectDataLength);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &pName, &memsize, MEM_RELEASE);

	if (NT_SUCCESS(rc))
	goto NtExit;

Original_Call:
	rc = ((NtConnectPortProc)(winNtConnectPortProc)) (portHandle, portName,
		     securityQos, WriteSection, ReadSection, maxMessageSize,
		     ConnectData, ConnectDataLength);

NtExit:
	
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	}    
       InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}


NTSTATUS FvmObj_NtSecureConnectPort(OUT PHANDLE portHandle,
    IN PUNICODE_STRING portName, IN PSECURITY_QUALITY_OF_SERVICE securityQos,
    IN OUT PPORT_SECTION_WRITE WriteSection OPTIONAL,
    IN PSID ServerSid OPTIONAL, IN OUT PPORT_SECTION_READ ReadSection OPTIONAL,
    OUT PULONG maxMessageSize OPTIONAL, IN OUT PVOID ConnectData OPTIONAL,
    IN OUT PULONG ConnectDataLength OPTIONAL)
{
	NTSTATUS rc;
	PWCHAR BinPath = NULL;
	PUNICODE_STRING pName = NULL;
	PWCHAR vdiruser = NULL;
	ULONG memsize = _MAX_PATH*2;
	LONG vmid = 0, pid = -1;
	ULONG len;
	PWCHAR objectName=NULL;
	PWCHAR vobjname=NULL;

	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if (vmid == INVALID_VMID)  goto Original_Call;

//	BinPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2, FVM_OBJ_POOL_TAG);
       BinPath = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
	if (BinPath == NULL) goto Original_Call;

	FvmUtil_GetBinaryPathName(BinPath);

	if ((wcsstr(BinPath, L"msiexec") != NULL) ||
		(wcsstr(BinPath, L"MsiExec") != NULL)) {
		if ((vmid == msi_owner) || (msi_owner == -1)) {
			ExFreePool(BinPath);
			goto Original_Call;
		}
	}


	//DbgPrint("NtSecureConnectPort : Application Name - %S\n", BinPath);
	 if (BinPath) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, BinPath );
	}
	//ExFreePool(BinPath);
       objectName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (objectName == NULL) {
              DbgPrint("FvmObj_NtConnectPort: ExAllocateFromPagedLookasideList fail\n");  
		rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}
       vobjname = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
       if (vobjname == NULL) {
              DbgPrint("FvmObj_NtConnectPort: ExAllocateFromPagedLookasideList fail\n"); 
	       rc = STATUS_ACCESS_DENIED;
		goto NtExit;
	}

	if (portName && portName->Buffer) {
		len = (portName->Length) >> 1;
		wcsncpy(objectName, portName->Buffer, len);
		objectName[len] = 0;
	} else {
		goto Original_Call;
	}

	if (!MapPortObjectPath(objectName, vmid, vobjname)) goto Original_Call;

	memsize = sizeof(UNICODE_STRING) + wcslen(vobjname)*2 + 2;
	rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(), &pName, 0, &memsize,
		     MEM_COMMIT, PAGE_READWRITE);

	if (NT_SUCCESS(rc)) {
		(char *)vdiruser = ((char *)pName) + sizeof(UNICODE_STRING);
		wcsncpy(vdiruser, vobjname, wcslen(vobjname)+1);//_MAX_PATH);
		RtlInitUnicodeString(pName, vdiruser);
	}
	else {
/*		CHAR errstr[64];
		DbgPrint("FvmObj_NtSecureConnectPort ErrMem:%s\n", FvmUtil_ErrorString(rc, errstr));*/
		DbgPrint("FvmObj_NtSecureConnectPort ErrMem:%x\n",rc);
		goto Original_Call;
	}

	rc = ((NtSecureConnectPortProc)(winNtSecureConnectPortProc)) (portHandle, pName,
		     securityQos, WriteSection, ServerSid, ReadSection, maxMessageSize,
		     ConnectData, ConnectDataLength);

	memsize = 0;
	FvmVm_FreeVirtualMemory(NtCurrentProcess(), &pName, &memsize, MEM_RELEASE);
	goto NtExit;


Original_Call:
	rc = ((NtSecureConnectPortProc)(winNtSecureConnectPortProc)) (portHandle, portName,
		     securityQos, WriteSection, ServerSid, ReadSection, maxMessageSize,
		     ConnectData, ConnectDataLength);

NtExit:
       if (objectName) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objectName );
	}     
       if (vobjname) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, vobjname );
	}    
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtCreateDirectoryObject(OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes)
{
	NTSTATUS rc;
	ULONG vmid = 0, pid = -1;

	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if(vmid == INVALID_VMID) goto Original_Call;

Original_Call:
	//rc = ((NtCreateDirectoryObjectProc)(OldNtCreateDirectoryObject)) (
	//	     DirectoryHandle, desiredAccess, objectAttributes);

	rc = winNtOpenDirectoryObjectProc (
		     DirectoryHandle, desiredAccess, objectAttributes);

	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtOpenDirectoryObject(OUT PHANDLE directoryHandle,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes)
{
	NTSTATUS rc;
	ULONG vmid = 0, pid = -1;

	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if(vmid == INVALID_VMID) goto Original_Call;

	Original_Call:
	rc = winNtOpenDirectoryObjectProc (directoryHandle,
		     desiredAccess, objectAttributes);

	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtCreateSymbolicLinkObject(OUT PHANDLE hSymbolicLink,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes,
    IN PUNICODE_STRING targetName)
{
	NTSTATUS rc;
	ULONG vmid = 0, pid = -1;

	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if(vmid == INVALID_VMID) goto Original_Call;

	Original_Call:
	rc = winNtCreateSymbolicLinkObjectProc(
		     hSymbolicLink, desiredAccess, objectAttributes, targetName);

	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtOpenSymbolicLinkObject(OUT PHANDLE hSymbolicLink,
    IN ACCESS_MASK desiredAccess, IN POBJECT_ATTRIBUTES objectAttributes)
{
	NTSTATUS rc;
	ULONG vmid = 0, pid = -1;

	InterlockedIncrement (&fvm_Calls_In_Progress);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}

	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);

	if(vmid == INVALID_VMID) goto Original_Call;

	Original_Call:
	rc = winNtOpenSymbolicLinkObjectProc (
		     hSymbolicLink, desiredAccess, objectAttributes);

	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_NtClose(HANDLE handle)
{
	NTSTATUS rc;
	ULONG vmid = 0, pid = -1;
	

	

	InterlockedIncrement (&fvm_Calls_In_Progress);
		pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);
	if (ExGetPreviousMode() == KernelMode) {
		goto Original_Call;
	}



	if (vmid != INVALID_VMID) {
		//FvmTable_HandleTableRemove(handle, vmid);
		FvmTable_HandleTableRemoveEx(handle, vmid,1);
	}

	Original_Call:
	
	if (handle){
		PWCHAR wFullName = NULL;
		PWCHAR name = NULL;
		
		KPROCESSOR_MODE mode;
		mode = ExGetPreviousMode();
		//if (ExGetPreviousMode() == KernelMode) {
		if (vmid != INVALID_VMID && mode != KernelMode) {
		
			wFullName = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
			if (wFullName == NULL) {
	   			DbgPrint("NtClose: ExAllocateFromPagedLookasideList fail\n");  
			}
			else{
				wFullName[0] = L'\0';
				if (FvmUtil_PathFromHandle(handle, NULL, wFullName)) {
					if ( wFullName[0] != L'\0'){
						if (wFullName[1]==L'R' && wFullName[2] == L'E' && wFullName[3] == L'G')
							name = NULL;// wcsstr(wFullName, L"Registry");
						else
							name = wFullName;
					}
				}							
			}

			rc=((NtCloseProc)(winNtCloseProc))(handle);
			if(name){
				FvmUtil_GetOriginalFileName(name, PATHSIZE, vmid);

#ifdef NTCLOSE
				DbgPrint("        NtClose(%d, %x %S, %x)\n",(ULONG)PsGetCurrentProcessId(), handle, name, rc);
#endif
			}
			if(wFullName)
				ExFreePool(wFullName);
		}
		else
			rc=((NtCloseProc)(winNtCloseProc))(handle);

		
	}
	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS FvmObj_CreateObjDirectory(ULONG vmid)
{
//	WCHAR objDirPath[_MAX_PATH*2];
	PWCHAR objDirPath=NULL;
	UNICODE_STRING pathname;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS rc = STATUS_SUCCESS;

	if (FVM_ObjectDirectoryHandle[vmid]) return rc;

      objDirPath = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
      if (objDirPath == NULL) {
           DbgPrint("FvmObj_CreateObjDirectory: ExAllocateFromPagedLookasideList fail\n");
	    rc = STATUS_ACCESS_DENIED;
	    goto ntExit;
      } 

	swprintf(objDirPath, L"\\BaseNamedObjects\\FVM-%u", vmid);

	RtlInitUnicodeString(&pathname, objDirPath);
	InitializeObjectAttributes(&oa, &pathname,
	    OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);

	rc = ZwCreateDirectoryObject(&FVM_ObjectDirectoryHandle[vmid],
		     DIRECTORY_ALL_ACCESS, &oa);
ntExit:    
       if (objDirPath) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, objDirPath );
	}
	return rc;
}

NTSTATUS FvmObj_CreatePortDirectory(ULONG vmid)
{
//	WCHAR portDirPath[_MAX_PATH*2];
       PWCHAR portDirPath=NULL;
	UNICODE_STRING pathname;
	OBJECT_ATTRIBUTES oa;
	NTSTATUS rc = STATUS_SUCCESS;

	if (FVM_PortDirectoryHandle[vmid]) return rc;

      portDirPath = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
      if (portDirPath == NULL) {
           DbgPrint("FvmObj_CreatePortDirectory: ExAllocateFromPagedLookasideList fail\n");
	    rc = STATUS_ACCESS_DENIED;
	    goto ntExit;
      } 

	swprintf(portDirPath, L"\\RPC Control\\FVM-%u", vmid);

	RtlInitUnicodeString(&pathname, portDirPath);
	InitializeObjectAttributes(&oa, &pathname,
	    OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);

	rc = ZwCreateDirectoryObject(&FVM_PortDirectoryHandle[vmid],
		     DIRECTORY_ALL_ACCESS, &oa);
ntExit:    
       if (portDirPath) {
              ExFreeToPagedLookasideList( &FileFullPathLookaside, portDirPath );
	}    
	return rc;
}


NTSTATUS FvmObj_QueryDirectoryObjectProc(
    IN HANDLE DirectoryHandle,
    IN OUT POBJECT_DIRECTORY_INFORMATION QueryBuffer,
    IN ULONG QueryBufferLength,
    IN BOOLEAN ReadOneOrMoreBuffer,
    IN BOOLEAN QueryType,
    OUT PULONG Context OPTIONAL,
    OUT PULONG ReturnedLength OPTIONAL
    )
{

	NTSTATUS rc;
	ULONG vmid = 0, pid = -1;
	
	InterlockedIncrement (&fvm_Calls_In_Progress);
	//if (ExGetPreviousMode() == KernelMode) {
	//	goto Original_Call;
	//}
	
	pid = (ULONG)PsGetCurrentProcessId();
	vmid = FvmVm_GetPVMId(pid);
	
	if(vmid == INVALID_VMID) goto Original_Call;

	DbgPrint("QueryDirectoryObject******************************************\n");
	
	Original_Call:
		

		rc = winNtQueryDirectoryObjectProc(DirectoryHandle, QueryBuffer, QueryBufferLength, ReadOneOrMoreBuffer, QueryType, Context, ReturnedLength);
		
		InterlockedDecrement (&fvm_Calls_In_Progress);
		return rc;


	



}


