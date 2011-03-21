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
#include <ntstrsafe.h>
#include "hooksys.h"
#include "fvm_obj.h"
#include "fvm_file.h"
#include "fvm_util.h"
#include "fvm_table.h"
#include "fvm_vm.h"
#include "fvm_syscalls.h"

#define FVM_VM_POOL_TAG '8GAT'

/*
 * This header file contains the functions that defines the Virtual Machine
 * manager API's
 */

static struct FVM_new_process_t *getNewProcess(ULONG Pid);

struct FVM_new_process_t *FVM_new_processes = NULL;

ERESOURCE FVM_newProcessResource, FVM_processVMRes,FVM_ProcBufferResource;
ULONG BufferSize=1064960 + 4096*16;

/*
 * Add a new process to the FVM process queue structure.
 * The Pid parameter would be added to the FVM_new_processes structure.
 */
void
FvmVm_addNewProcess(ULONG Pid) {
	struct FVM_new_process_t *nt;

	nt = (struct FVM_new_process_t *) ExAllocatePoolWithTag(PagedPool,
		    sizeof(struct FVM_new_process_t), FVM_VM_POOL_TAG);
	if (nt == NULL) {
		DbgPrint("Unable to allocate memory in the driver\n");
		return;
	}

	nt->pid = Pid;
	nt->dllLoad = NULL;
	nt->imageName = NULL;
	nt->next = NULL;
	nt->prev = NULL;

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_newProcessResource, TRUE);

	if (FVM_new_processes == NULL) {
		FVM_new_processes = nt;
	} else {
		nt->next = FVM_new_processes;
		FVM_new_processes->prev = nt;
		FVM_new_processes = nt;
	}

	ExReleaseResourceLite(&FVM_newProcessResource);
	KeLeaveCriticalRegion();
}

/*
 * Remove the Pid from the FVM_new_processes structure.
 * This function essentially disassociates a Pid from FVM.
 */
void
FvmVm_removeNewProcess(ULONG Pid) {
	struct FVM_new_process_t *p = NULL;

	p = FVM_new_processes;
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_newProcessResource, TRUE);

	while (p) {
		if (p->pid == Pid) {
			if (p->next == NULL && p->prev == NULL) {
				FVM_new_processes = NULL;
				DbgPrint("---------------------------------------\n");
			}
			if (p->prev)
				p->prev->next = p->next;
			else
				FVM_new_processes = p->next;

			if (p->next)
				p->next->prev = p->prev;

			if (p->imageName)
				ExFreePool(p->imageName);		
			if (p->dllLoad)
				ExFreePool(p->dllLoad);
			ExFreePool(p);
			break;
	    }
		p = p->next;
	}
	ExReleaseResourceLite(&FVM_newProcessResource);
	KeLeaveCriticalRegion();
}

/*
 * Get the Pid from the FVM_new_processes structure.
 */
struct FVM_new_process_t *
getNewProcess(ULONG Pid) {

	struct FVM_new_process_t *p = NULL;

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&FVM_newProcessResource, TRUE);

	p = FVM_new_processes;
	while (p != NULL) {

		if (p->pid == Pid)
			break;
		p = p->next;
	}

	ExReleaseResourceLite(&FVM_newProcessResource);
	KeLeaveCriticalRegion();
	return p;
}

/*
 * Update process status to resume the execution.
 */
BOOLEAN
FvmVm_UpdateProcessStatus(ULONG Pid) {
	struct FVM_new_process_t *np = NULL;

	np = getNewProcess(Pid);
	if (np == NULL)
		return FALSE;
	KeSetEvent(np->dllLoad, IO_NO_INCREMENT, FALSE);
	return TRUE;
}

struct FVM_new_process_t *
FvmVm_CheckProcessStatus(ULONG Pid, PWCHAR imageName) {
	struct FVM_new_process_t *np;

	np = getNewProcess(Pid);
	if (np == NULL)
		return NULL;

	if (!np->dllLoad) {
		np->imageName = ExAllocatePoolWithTag(PagedPool,
			wcslen(imageName) * 2 + 2, FVM_VM_POOL_TAG);
		wcscpy(np->imageName, imageName);

		np->dllLoad = (PKEVENT)ExAllocatePoolWithTag(NonPagedPool, sizeof(KEVENT), FVM_VM_POOL_TAG);
		if (np->dllLoad) {
			KeInitializeEvent(np->dllLoad, NotificationEvent, FALSE);
			return np;
		}
	}
	return NULL;
}

/*
 * Get the ImageName from the FVM_new_process_t structure form the Pid.
 */
PWCHAR
FvmVm_FindProcessCreateImage(ULONG Pid) {

	struct FVM_new_process_t *np = NULL;

	np = getNewProcess(Pid);
	if (np == NULL)
		return NULL;
	return np->imageName;

}

/*
 * This returns PVM ID from the global table. If not present,
 * it returns INVALID_VMID
 */
ULONG
FvmVm_GetPVMId(ULONG Pid) {
	PFVM_PVM_TBL_ENTRY pte;
	ULONG hv;

	hv = hash_pid(Pid);

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&FVM_processVMRes, TRUE);

	for(pte = FVM_pvm_pid_tbl[hv]; pte; pte = pte->next) {
		if (pte->pid == Pid) {
		    ExReleaseResourceLite(&FVM_processVMRes);
		    KeLeaveCriticalRegion();
		    return pte->pvm_id;
		}
	}
	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();
	return INVALID_VMID;
}


#ifdef RPCSS
/*
 * This function adds a process to a domain.
 */
void
FvmVm_AddPid(ULONG Pid, ULONG Pvm_id, int comServerType)
{
	ULONG hv;
	PFVM_PVM_TBL_ENTRY pte;
	ULONG vmid;

	UNICODE_STRING NDISDevice;
	NTSTATUS ret;

    KEVENT              event;
    PIRP                irp;
    IO_STATUS_BLOCK     ioStatus;
	LARGE_INTEGER	startingOffset;
	PIO_STACK_LOCATION	nextStack;
	PVOID context;

	if (FvmVm_GetPVMId(Pid) != INVALID_VMID)
	return;

	hv = hash_pid(Pid);
	pte = (PFVM_PVM_TBL_ENTRY)ExAllocatePoolWithTag(PagedPool,
		sizeof(FVM_PVM_TBL_ENTRY), FVM_VM_POOL_TAG);
	if (!pte) {
		DbgPrint("Unable to allocate memory in the driver\n");
		return;
	}
	pte->pid = Pid;
	pte->pvm_id = Pvm_id;
	pte->dllLoad = NULL;
	pte->imageName = NULL;
	pte->PBuffer = NULL;
	pte->PLitBuffer = NULL;
	pte->BufMap = 0;
	pte->BufferAllocated = FALSE;
	pte->newClsid = (PWCHAR)ExAllocatePoolWithTag(PagedPool,
						900*sizeof(WCHAR), FVM_VM_POOL_TAG);
	pte->oldClsid= pte->newClsid+50;
	pte->newProgId = pte->oldClsid+50;
	pte->oldProgId = pte->newProgId+300;
	pte->newAppId= pte->oldProgId+300;
	pte->newAppName = pte->newAppId+50;
	pte->newTypeLibId= pte->newAppName+100;
	
	pte->newClsid[0]=L'\0';
	pte->oldClsid[0]=L'\0';
	pte->newProgId[0]=L'\0';
	pte->oldProgId[0]=L'\0';
	pte->newAppId[0]=L'\0';
	pte->newAppName[0]=L'\0';
	pte->newTypeLibId[0]=L'\0'; 

	if(comServerType>=0){
		pte->comServerPid=Pid;
		if(comServerType>0)  //service or surrogate COM Server
			pte->rpcssPid=Pid;
	}else{
		pte->comServerPid=0;
		pte->rpcssPid=0;
	}
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);

	pte->next = FVM_pvm_pid_tbl[hv];
	pvms[Pvm_id]->n_procs++;
	FVM_pvm_pid_tbl[hv] = pte;

	DbgPrint("Adding pid %d to FVM %d, FVM now has %d processes\n", Pid,
	    Pvm_id, pvms[Pvm_id]->n_procs);
	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();


	if (pvms[Pvm_id]->handle||1) { //lapchunglam
		char buf[35], pid[11], FVMID[11], ipaddress[11];

	
		// Add the pid and the FVM ID to the buffer to passed to the NDIS driver
		RtlZeroMemory(buf, sizeof(buf));
		sprintf(pid, "%lu", Pid);
		sprintf(FVMID, "%lu", Pvm_id);
		_snprintf(ipaddress, 11, "%s", pvms[Pvm_id]->key);
		buf[0] = 'A';

		memcpy(buf+1, pid, strlen(pid));
		memcpy(buf + 1 + sizeof(pid), FVMID, strlen(FVMID));
		memcpy(buf + 1 + sizeof(pid)+ sizeof(FVMID), ipaddress, strlen(ipaddress));
		buf[34] = '\0';
		DP_TdiWrite(buf, sizeof(buf));
	}

}

BOOLEAN 
FvmVm_isComServer(ULONG Pid, ULONG Pvm_id)
{
	ULONG hv;
	ULONG vmid;
	BOOLEAN ret=FALSE;
	
	if (FvmVm_GetPVMId(Pid) == INVALID_VMID)
		return FALSE;

	hv = hash_pid(Pid);

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);
	if(FVM_pvm_pid_tbl[hv]->comServerPid== Pid)
		ret = TRUE;
	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();

	return ret;

}


/*
 * This function check if the process is the RPCSS process in a domain.
 */
BOOLEAN 
FvmVm_isRpcssProcess(ULONG Pid, ULONG Pvm_id)
{
	ULONG hv;
	ULONG vmid;
	BOOLEAN ret=FALSE;
	
	if (FvmVm_GetPVMId(Pid) == INVALID_VMID)
		return FALSE;

	hv = hash_pid(Pid);

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);
	if(FVM_pvm_pid_tbl[hv]->rpcssPid == Pid)
		ret = TRUE;
	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();

	return ret;

}

#else
/*
 * This function adds a process to a domain.
 */
void
FvmVm_AddPid(ULONG Pid, ULONG Pvm_id)
{
	ULONG hv;
	PFVM_PVM_TBL_ENTRY pte;
	ULONG vmid;

	if (FvmVm_GetPVMId(Pid) != INVALID_VMID)
	return;

	hv = hash_pid(Pid);
	pte = (PFVM_PVM_TBL_ENTRY)ExAllocatePoolWithTag(PagedPool,
		sizeof(FVM_PVM_TBL_ENTRY), FVM_VM_POOL_TAG);
	if (!pte) {
		DbgPrint("Unable to allocate memory in the driver\n");
		return;
	}
	pte->pid = Pid;
	pte->pvm_id = Pvm_id;
	pte->dllLoad = NULL;
	pte->imageName = NULL;
	pte->PBuffer = NULL;
	pte->PLitBuffer = NULL;
	pte->BufMap = 0;
	pte->BufferAllocated = FALSE;

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);

	pte->next = FVM_pvm_pid_tbl[hv];
	pvms[Pvm_id]->n_procs++;
	FVM_pvm_pid_tbl[hv] = pte;

	DbgPrint("Adding pid %d to FVM %d, FVM now has %d processes\n", Pid,
	    Pvm_id, pvms[Pvm_id]->n_procs);
	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();
}
#endif  //RPCSS
/*
 * This function removes a process from a domain.
 */
void
FvmVm_RemovePid(ULONG Pid) {
	ULONG hv;
	PFVM_PVM_TBL_ENTRY pte, pte1;
	PWCHAR BinPath = NULL;
	LONG vmid;

    KEVENT              event;
    PIRP                irp;
    IO_STATUS_BLOCK     ioStatus;
	LARGE_INTEGER	startingOffset;
	PIO_STACK_LOCATION	nextStack;
	PVOID context;
	NTSTATUS ret;
	UNICODE_STRING NDISDevice;

	hv = hash_pid(Pid);
	pte1 = NULL;
	
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);

//	if ((vmid = FvmVm_GetPVMId(Pid)) != INVALID_VMID)
	//	return;
	vmid =  FvmVm_GetPVMId(Pid);

	  BinPath = ExAllocatePoolWithTag(PagedPool, _MAX_PATH * 2,
	      FVM_VM_POOL_TAG);

	  if (BinPath == NULL) {
		  ExReleaseResourceLite(&FVM_processVMRes);
		  KeLeaveCriticalRegion();
		  return;
	  }

	  FvmUtil_GetBinaryPathName(BinPath);
	  if ((wcsstr(BinPath, L"msiexec.exe") != NULL)) {
		 DbgPrint("Process name = %Smsi_owner = %ld my num_process = %ld\n",
			BinPath, msi_owner, num_process);
		  if (msi_owner == vmid)
			num_process--;
	
	
		  if ((num_process == 0) && (msi_owner != -1)) {
			//DbgPrint("num_process = %d serv pid%d \n", num_process, service_pid);
			if ((service_pid != 0) && (is_added)) {
				DbgPrint("Removing service pid = %ld from fvm\n",
					service_pid);
				FvmVm_RemovePid(service_pid);
				is_added = 0;
			}
			msi_owner = -1;
			num_process = 0;
			}
	  }
	
	ExFreePool(BinPath);

	for(pte = FVM_pvm_pid_tbl[hv]; pte && (pte->pid != Pid); pte = pte->next)
		pte1=pte;
	if (pte == NULL) {
		//DbgPrint("Strange! Pid %d is not in the table\n", Pid);
		ExReleaseResourceLite(&FVM_processVMRes);
		KeLeaveCriticalRegion();
		return;
	}
	if(pte->BufferAllocated == TRUE)
		FvmDestroyVirtualMemory(pte);	
	if(pte->newClsid)
		ExFreePool(pte->newClsid);
	
	if (pte1 == NULL)
		FVM_pvm_pid_tbl[hv] = pte->next;
	else
		pte1->next = pte->next;
	pvms[pte->pvm_id]->n_procs--;
	DbgPrint("Removing pid %d from FVM %d, FVM now has %d processes\n",
	    pte->pid, pte->pvm_id, pvms[pte->pvm_id]->n_procs);
	ExFreePool(pte);

	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();


	// Remove the pid and the FVM ID from the NDIS driver
 	if (pvms[vmid]->handle ||1){ //lapchunglam
		char buf[24], pid[11], FVMID[11];

	

		// Remove the pid and the FVM ID from the buffer to passed to the NDIS driver
		RtlZeroMemory(buf, sizeof(buf));
		sprintf(pid, "%lu", Pid);
		sprintf(FVMID, "%lu", vmid);

		buf[0] = 'D';
		memcpy(buf+1, pid, strlen(pid));
		memcpy(buf + 1 + sizeof(pid), FVMID, strlen(FVMID));	
		buf[23] = '\0';
		DP_TdiWrite(buf, sizeof(buf));
	}



}



HANDLE FvmVm_OpenSysLog(int vmNumber)
{
	
	UNICODE_STRING UnicodeFilespec;
	NTSTATUS status;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE fileHandle;
	IO_STATUS_BLOCK Iosb;
	WCHAR buf[256];

	RtlZeroMemory(buf, sizeof(WCHAR)*256);

	DbgPrint("Open System call log %d\n", vmNumber);

	

	status = RtlStringCbPrintfW(buf, sizeof(buf), L"\\??\\%s\\%s.log", 
		pvms[vmNumber]->fileRoot, pvms[vmNumber]->idStr);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Error copying sys log path func:OpenSysLog code: %x\n", status);
		return 0;
	}
	
	DbgPrint("FVM %d system call log file name is: %S\n", vmNumber, buf);
	RtlInitUnicodeString(&UnicodeFilespec, buf);

	InitializeObjectAttributes(&objectAttributes, &UnicodeFilespec,
	     OBJ_KERNEL_HANDLE, NULL, NULL );

	status =ZwCreateFile
	    (&fileHandle,              		  // returned file handle
	    FILE_GENERIC_READ|FILE_GENERIC_WRITE| SYNCHRONIZE, // desired access
	     &objectAttributes,                // ptr to object attributes
	    &Iosb,                            // ptr to I/O status block
	    0,                                // allocation size
	    FILE_ATTRIBUTE_NORMAL,            // file attributes
	   	FILE_SHARE_READ,                                // share access
	    FILE_OVERWRITE_IF,                // create disposition
	    FILE_SYNCHRONOUS_IO_NONALERT,     // create options
	    NULL,                             // ptr to extended attributes
	    0);                               // length of ea buffer


	
	if (status == STATUS_SUCCESS){
		DbgPrint("..................1 %x\n", fileHandle);
		return fileHandle;
	}
	else{
		DbgPrint("........2 %x\n", status);
		return 0;
		}
}

/*
 * Create new PVM and initialize with pvm_id
 * This function returns non-zero success and 0 failure.
 */
UINT
FvmVm_CreatePVM(ULONG *Ptr_pvm_id, PWCHAR Pvm_name, PWCHAR IdStr, PWCHAR Root,
		ULONG VmIp, ULONG VmContext, PWCHAR ddofsIp, PWCHAR ddofsDns, PWCHAR ddofsNetbios, PWCHAR driverLetter, PWCHAR encryptHandle, PWCHAR encryptKey)
	{
	ULONG i;
	int j = 0;

	if (FvmVm_FindPVM(Ptr_pvm_id, IdStr) == 0) {
		DbgPrint("Same name virtual machine already exist!\n");
		return CREATE_VM_RUNNING;
	}

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);

	for(i=0; i<MAX_NUM_PVMS; i++) {
		if (pvms[i] == NULL)
			break;
	}

	if (i == MAX_NUM_PVMS) {
		DbgPrint("Number of Virtual Machines already reached maximum(%d), "
		    "Cannot create anymore!\n", MAX_NUM_PVMS);

		ExReleaseResourceLite(&FVM_processVMRes);
		KeLeaveCriticalRegion();
		return CREATE_VM_MAXVMER;
	}

	pvms[i] = (PFVM_PSEUDO_VIRTUAL_MACHINE)ExAllocatePoolWithTag(PagedPool,
		    sizeof(FVM_PSEUDO_VIRTUAL_MACHINE), FVM_VM_POOL_TAG);

	if (pvms[i] == NULL) {
		DbgPrint("Failed to Allocate memory for the new PVM\n");
		ExReleaseResourceLite(&FVM_processVMRes);
		KeLeaveCriticalRegion();
		return CREATE_VM_MEMERRO;
	}
	if (Ptr_pvm_id)
		*Ptr_pvm_id = i;

	n_pvms++;
	pvms[i]->id = i;
	pvms[i]->n_procs = 0;
	pvms[i]->status = 1;
	wcscpy(pvms[i]->name, Pvm_name);
	wcscpy(pvms[i]->idStr, IdStr);

	
	if(ddofsIp)
		wcscpy(pvms[i]->DDOFSIP, ddofsIp);
	else
		pvms[i]->DDOFSIP[0] = L'\0';

	if(ddofsDns)
		wcscpy(pvms[i]->DDOFSDNS, ddofsDns);
	else
		pvms[i]->DDOFSDNS[0] = L'\0';

	if (ddofsNetbios)
		wcscpy(pvms[i]->DDOFSNETBIOS, ddofsNetbios);
	else
		pvms[i]->DDOFSNETBIOS[0] = L'\0';

	if (driverLetter)
		wcscpy(pvms[i]->DDOFSDRIVE, driverLetter);
	else
		pvms[i]->DDOFSDRIVE[0] = L'\0';
	

	if (Root[0] == L'\\' && Root[1] == L'\\') {		
		_snwprintf(pvms[i]->fileRoot, _MAX_PATH*2, L"\\??\\UNC\\%s", &Root[2]);
		DbgPrint("root: %S\n", pvms[i]->fileRoot);
	}
	else
	wcscpy(pvms[i]->fileRoot, Root);


	if (encryptHandle && encryptKey){
		char hdl[15];
		sprintf(hdl, "%S", encryptHandle);
		pvms[i]->handle = atoi(hdl);
		_snprintf(pvms[i]->key, 11, "%S", encryptKey);
	}
	else
		pvms[i]->handle = 0;

	pvms[i]->pvm_vmIp = VmIp;
	pvms[i]->pvm_vmContext = VmContext;
	for(j=0;j<10;j++){
		pvms[i]->comServerPaths[j][0]=L'\0';
		pvms[i]->comServerTypes[j]=0;
	}

	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();

	FvmFile_CreateFVMRootDir(*Ptr_pvm_id);

	FvmObj_CreateObjDirectory(*Ptr_pvm_id);

	FvmObj_CreatePortDirectory(*Ptr_pvm_id);

	FvmTable_ReadVMDeletedLogFile(*Ptr_pvm_id);

	pvms[i]->logHandle = FvmVm_OpenSysLog(i);
    //FvmTable_FVMFileListInit(*Ptr_pvm_id);

	DbgPrint("Created a new virtual machine named %S\n", pvms[i]->name);
	return CREATE_VM_SUCCESS;
}

/*
 * This function would be invoked when all the processes in the PVM die.
 * Returns Non-zero:Success
 * 0: Failure
 */
UINT
FvmVm_DestroyPVM(ULONG Pvm_id)
{
	if (FVM_ObjectDirectoryHandle[Pvm_id]) {
		ZwClose(FVM_ObjectDirectoryHandle[Pvm_id]);
		FVM_ObjectDirectoryHandle[Pvm_id] = NULL;
	}

	if (FVM_PortDirectoryHandle[Pvm_id]) {
		ZwClose(FVM_PortDirectoryHandle[Pvm_id]);
		FVM_PortDirectoryHandle[Pvm_id] = NULL;
	}

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);

	if (pvms[Pvm_id] != NULL && pvms[Pvm_id]->n_procs > 0) {
		DbgPrint("FVM %d contains %d processes, Returning without "
			"destroying\n", Pvm_id, pvms[Pvm_id]->n_procs);
		ExReleaseResourceLite(&FVM_processVMRes);
		KeLeaveCriticalRegion();
		return 0;
	}

	if (pvms[Pvm_id]->logHandle){
		ZwClose(pvms[Pvm_id]->logHandle);
		DbgPrint("....logfile is closed\n");
	}
	
	ExFreePool(pvms[Pvm_id]);
	pvms[Pvm_id] = NULL;
	DbgPrint("Destroying PVM %d\n", Pvm_id);

	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();
	return 1;
}

/*
 * The idStr is unique for all FVM's.
 * Find PVM Id from the global FVM_PSEUDO_VIRTUAL_MACHINE structure.
 */
UINT
FvmVm_FindPVM(ULONG *Ptr_pvm_id, PWCHAR IdStr)
{
	int i;

	if (IdStr == NULL)
		return 1;
	if (Ptr_pvm_id == NULL)
		return 1;

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&FVM_processVMRes, TRUE);

	for( i = 0; i < MAX_NUM_PVMS; i++) {
		if (pvms[i] != NULL) {
			if (wcscmp(pvms[i]->idStr, IdStr) == 0) {
				*Ptr_pvm_id = pvms[i]->id;
				ExReleaseResourceLite(&FVM_processVMRes);
				KeLeaveCriticalRegion();
				return 0;
			}
		}
	}
	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();
	return 1;
}
/*
 * This function allocates virtual memory. 
 * It gets memory from preallocated buffer.
 */
NTSTATUS FvmVm_AllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PULONG AllocationSize,
	IN ULONG AllocationType,
	IN ULONG Protect
)
{
	int i=0;
	NTSTATUS rc;
    PFVM_PVM_TBL_ENTRY CurrentProc; 
	   
    CurrentProc = FVM_pvm_pid_tbl[hash_pid((ULONG)PsGetCurrentProcessId())];
    if(CurrentProc==NULL){
    	rc = ZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
    				AllocationSize, AllocationType, Protect);
    	if(!NT_SUCCESS(rc))
    		DbgPrint("ZwAllocateVirtualMemory failed pid=%ld\n",(ULONG)PsGetCurrentProcessId());
    	  //else
    	    //DbgPrint("ZwAllocateVirtualMemory success pid=%ld,without buffer\n",(ULONG)PsGetCurrentProcessId());
    		return rc;
        }
  
        if(CurrentProc->BufferAllocated==FALSE){
	    	rc=FvmInitiateVirtualMemory(CurrentProc);
	    	if(!NT_SUCCESS(rc)){
			DbgPrint("ZwAllocateVirtualMemory initiate buffer failed pid=%ld\n",(ULONG)PsGetCurrentProcessId());
			return rc;
	    }
	}
	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&FVM_ProcBufferResource, TRUE);	  
    if((int)*AllocationSize > 4096){
    	if((CurrentProc->BufMap & 0x80000000)==0){
	  		*BaseAddress=CurrentProc->PBuffer;
			CurrentProc->BufMap = CurrentProc->BufMap | 0x80000000;
			//DbgPrint("FvmVm_AllocateVirtualMemory (%ld) allocate a big memory\n",(ULONG)PsGetCurrentProcessId());
			ExReleaseResourceLite(&FVM_ProcBufferResource);
   	    	KeLeaveCriticalRegion();	
			return STATUS_SUCCESS;
        }
    }else{
        for(i=0;i<16;i++){
			if((CurrentProc->BufMap &(0x00000001<<i))==0){
				*BaseAddress = (PVOID)((char*)CurrentProc->PLitBuffer + (15-i)*4096);
				CurrentProc->BufMap = CurrentProc->BufMap|(0x00000001<<i);
	            //DbgPrint("FvmVm_AllocateVirtualMemory (%ld) allocate a lit memory i=%d,addr=%ld\n",(ULONG)PsGetCurrentProcessId(),i,*BaseAddress);
			    ExReleaseResourceLite(&FVM_ProcBufferResource);
	   	        KeLeaveCriticalRegion();	
			    return STATUS_SUCCESS;			
			}
        }
    }
	ExReleaseResourceLite(&FVM_ProcBufferResource);
	KeLeaveCriticalRegion();	  
	  
	rc = ZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
			AllocationSize, AllocationType, Protect);
	//DbgPrint("FvmVm_AllocateVirtualMemory (%ld) buffer overflow\n",(ULONG)PsGetCurrentProcessId());

    return rc;
}



/*
 * This function free virtual memory. 
 * It puts memory to the preallocated buffer.
 */

NTSTATUS
FvmVm_FreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PULONG FreeSize,
	IN ULONG FreeType
)
{
	NTSTATUS rc=STATUS_SUCCESS;
	int i=0;
    PFVM_PVM_TBL_ENTRY CurrentProc;
	BOOLEAN Freed = FALSE;

    CurrentProc = FVM_pvm_pid_tbl[hash_pid((ULONG)PsGetCurrentProcessId())];
    if((CurrentProc==NULL)||(CurrentProc->BufferAllocated==FALSE)){
		rc = ZwFreeVirtualMemory(ProcessHandle,BaseAddress,FreeSize,FreeType);
		//DbgPrint("FvmVm_FreeVirtualMemory (%ld),without buffer\n",(ULONG)PsGetCurrentProcessId());
		return rc;
    }
	if(*BaseAddress==NULL)
		return rc;

	KeEnterCriticalRegion();
	ExAcquireResourceSharedLite(&FVM_ProcBufferResource, TRUE);
	if(*BaseAddress == CurrentProc->PBuffer){
		*BaseAddress=NULL;
		CurrentProc->BufMap = CurrentProc->BufMap & 0x7fffffff;
		//DbgPrint("FvmVm_FreeVirtualMemory (%ld) free big memory\n",(ULONG)PsGetCurrentProcessId());		  
		Freed = TRUE;
		rc = STATUS_SUCCESS;
	}else if((*BaseAddress>=CurrentProc->PLitBuffer)&&(*BaseAddress<((PVOID)((char*)CurrentProc->PBuffer+BufferSize)))){
		CurrentProc->BufMap = CurrentProc->BufMap&(~(0x00000001<<(((char*)*BaseAddress-(char*)CurrentProc->PLitBuffer)/4096)));
		//DbgPrint("FvmVm_FreeVirtualMemory (%ld) free lit memory addr=%ld\n",(ULONG)PsGetCurrentProcessId(),*BaseAddress);		  
		*BaseAddress = NULL;		  
  		Freed = TRUE;
		rc = STATUS_SUCCESS;
	}
	ExReleaseResourceLite(&FVM_ProcBufferResource);
	KeLeaveCriticalRegion();
    if(!Freed){	
		rc = ZwFreeVirtualMemory(ProcessHandle,BaseAddress,FreeSize,FreeType);
		//DbgPrint("FvmVm_FreeVirtualMemory (%ld) buffer overflow\n",(ULONG)PsGetCurrentProcessId());  
    }
	return rc;
}

/*
 * This function preallocates and formats a block of big buffer for a process. 
 * 
 */
NTSTATUS
FvmInitiateVirtualMemory(PFVM_PVM_TBL_ENTRY CurrentProc)
{
	NTSTATUS rc;

	if(CurrentProc->BufferAllocated == TRUE)
		return STATUS_SUCCESS;
	
	rc = ZwAllocateVirtualMemory(NtCurrentProcess(),&CurrentProc->PBuffer,0,&BufferSize,MEM_COMMIT,PAGE_READWRITE);
	if(!NT_SUCCESS(rc)){
		DbgPrint("FvmInitiateVirtualMemory failed,process id=%ld\n",(ULONG)PsGetCurrentProcessId());
		return rc;
    }
    CurrentProc->BufferAllocated = TRUE;
    //DbgPrint("FvmInitiateVirtualMemory success,process id=%ld,addr=%ld,size=%ld\n",(ULONG)PsGetCurrentProcessId(),CurrentProc->PBuffer,BufferSize);
    CurrentProc->PLitBuffer = (PVOID)((char*)CurrentProc->PBuffer + 1064960);
    CurrentProc->BufMap = 0;
	
    return STATUS_SUCCESS;
}

/*
 * This function free the preallocated buffer. 
 *
 */

NTSTATUS
FvmDestroyVirtualMemory(PFVM_PVM_TBL_ENTRY CurrentProc)
{
	NTSTATUS rc;
	ULONG size = 0;
	if(CurrentProc->BufferAllocated == FALSE)
		return STATUS_SUCCESS;
	CurrentProc->BufferAllocated = FALSE;
	CurrentProc->PLitBuffer = NULL;
	CurrentProc->BufMap = 0;	
	rc = ZwFreeVirtualMemory(NtCurrentProcess(),&(CurrentProc->PBuffer),&size,MEM_RELEASE);
    if(!NT_SUCCESS(rc)){
		CHAR errStr[64];
	    DbgPrint("FvmDestroyVirtualMemory failed, process id=%ld, Err:%s\n",(ULONG)PsGetCurrentProcessId(),FvmUtil_ErrorString(rc, errStr));
    }//else
	  //DbgPrint("FvmDestroyVirtualMemory success, process id=%ld, addr=%ld\n",(ULONG)PsGetCurrentProcessId(),CurrentProc->PBuffer);
	CurrentProc->PBuffer = NULL;
	return STATUS_SUCCESS;
}



/*
 * This function save new clsid to a process.
 */
void
FvmVm_SaveClsid(ULONG Pid,WCHAR* oldClsid,WCHAR* newClsid,WCHAR* oldProgId,WCHAR* newProgId) {
	ULONG hv;
	PFVM_PVM_TBL_ENTRY pte;

    if((!newClsid)||(!newProgId)||(!oldClsid)||(!oldProgId))
		return;
	hv = hash_pid(Pid);
	if (FvmVm_GetPVMId(Pid) == INVALID_VMID)
		return;
	
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);

	for(pte = FVM_pvm_pid_tbl[hv]; pte && (pte->pid != Pid); pte = pte->next);

	if (pte == NULL) {
		ExReleaseResourceLite(&FVM_processVMRes);
		KeLeaveCriticalRegion();
		return;
	}
	//swprintf(pte->newClsid,L"%S",newClsid);
	//swprintf(pte->oldClsid,L"%S",oldClsid);
	wcscpy(pte->newClsid,newClsid);
	wcscpy(pte->oldClsid,oldClsid);
	wcscpy(pte->newProgId,newProgId);
	wcscpy(pte->oldProgId,oldProgId);

	//wcscpy(pte->newTypeLibId,newTypeLibId);

	DbgPrint("save oldClsid=%S, newClsid=%S, oldProgId=%S, newProgId=%S, for process %d\n",
	    oldClsid,newClsid, oldProgId,newProgId, pte->pid);

	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();
	return;
}

/*
 * This function save new App ID and name to process.
 */
void
FvmVm_SaveAppId(ULONG Pid,WCHAR* newAppId,WCHAR* newAppName) {
	ULONG hv;
	PFVM_PVM_TBL_ENTRY pte;

    if((!newAppId)||(!newAppName))
		return;
	hv = hash_pid(Pid);
	if (FvmVm_GetPVMId(Pid) == INVALID_VMID)
		return;
	
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);

	for(pte = FVM_pvm_pid_tbl[hv]; pte && (pte->pid != Pid); pte = pte->next);

	if (pte == NULL) {
		ExReleaseResourceLite(&FVM_processVMRes);
		KeLeaveCriticalRegion();
		return;
	}
	swprintf(pte->newAppId,L"%S",newAppId);
	swprintf(pte->newAppName,L"%S",newAppName);	
	//wcscpy(pte->newAppName,newAppName);

	DbgPrint("save appId %s and newAppName %s for process %d\n",
	    newAppId, newAppName,pte->pid);

	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();
	return;
}

/*
 * This function saves a new COM server path to vm.
 */
void
FvmVm_SaveComServerPath(ULONG Pid,WCHAR* newComServerPath,int type) {
	ULONG hv;
	PFVM_PVM_TBL_ENTRY pte;
	ULONG vmid;
	int j=0;
	WCHAR * fileName;
	
    if(!newComServerPath)
		return;
	vmid = FvmVm_GetPVMId(Pid);
	if (vmid == INVALID_VMID)
		return;

	fileName= wcsrchr(newComServerPath,L'\\');
	
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);

	for(j=0;j<10;j++){
		if(pvms[vmid]->comServerPaths[j][0]==L'\0'){
			swprintf(pvms[vmid]->comServerPaths[j],L"%s",fileName);
			pvms[vmid]->comServerTypes[j]=type;
			break;
		}
	}
	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();

	if(j==10)
		DbgPrint("newComServerPath of vm %d is overflow when adding %s\n",vmid,fileName);
	else
		DbgPrint("save newComServerName %S in vm %d, type=%d\n",fileName,vmid,type);
	
	return;
}


/*
 * This function saves a new COM server path to vm.
 */
ULONG
FvmVm_GetPVMIdByComServerPath(WCHAR* newComServerPath, int* comServerType) {
	ULONG hv;
	PFVM_PVM_TBL_ENTRY pte;
	ULONG vmid;
	int j=0,i=0;
	WCHAR comPath[256];
	
    if(!newComServerPath)
		return -1;
	if(wcsstr(newComServerPath,L"\\??\\"))
		wcscpy(comPath,(wcsstr(newComServerPath,L"\\??\\")+4));
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);
	
	for(i=0; i<MAX_NUM_PVMS; i++) {
		if (pvms[i] == NULL)
			break;
		for(j=0;j<10;j++){
			if(pvms[i]->comServerPaths[j][0]==L'\0'){
				continue;
			}
			DbgPrint("%d, FvmVm_GetPVMIdByComServerPath ,vm=%d j=%d, path=%S\n",PsGetCurrentProcessId(),i,j,pvms[i]->comServerPaths[j]);
			if(wcsstr(comPath,pvms[i]->comServerPaths[j])){
				pvms[i]->comServerPaths[j][0]=L'\0';
				*comServerType= pvms[i]->comServerTypes[j];
				ExReleaseResourceLite(&FVM_processVMRes);
				KeLeaveCriticalRegion();
				return i;
			}
		}
	}
	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();


	//DbgPrint("%d, FvmVm_GetPVMIdByComServerPath fail,binpath=%S\n",PsGetCurrentProcessId(),comPath);
	
	return -1;
}


/*
 * This function checks CreateClsid flag of a process.
 */
BOOLEAN
FvmVm_CheckClsid(ULONG Pid, WCHAR* regPath) {
	ULONG hv;
	PFVM_PVM_TBL_ENTRY pte;
	BOOLEAN flag = FALSE;
	char regPathStr[500], clsidchr[50], flagStr[20];
	ULONG vmid = 0;	
		
//	WCHAR str[50];
	//WCHAR *chr;
	
	if(!regPath)
		return FALSE;
	
	sprintf(regPathStr,"%S",regPath);

	vmid= FvmVm_GetPVMId(Pid);
	if (vmid == INVALID_VMID)
		return FALSE;
	sprintf(flagStr,"FVM%d-",vmid);
	if(strstr(regPathStr,flagStr)&&(strstr(regPathStr,"SOFTWARE\\Classes"))){
		//DbgPrint("checkClsid return true, regPathStr=%s, flagStr=%s.\n",regPathStr,flagStr);
		return TRUE;
	}
	
	hv = hash_pid(Pid);

	
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);

	for(pte = FVM_pvm_pid_tbl[hv]; pte && (pte->pid != Pid); pte = pte->next);
		
	if (pte == NULL) {
		ExReleaseResourceLite(&FVM_processVMRes);
		KeLeaveCriticalRegion();
		DbgPrint("checkClsid: pte is null, %d\n",Pid);		
		return FALSE;
	}

	if((pte->newClsid[0]==L'\0')||(pte->newProgId[0]==L'\0')||(pte->oldClsid[0]==L'\0')||(pte->oldProgId[0]==L'\0')){
		ExReleaseResourceLite(&FVM_processVMRes);
		KeLeaveCriticalRegion();
		return FALSE;		
	}
//	sprintf(clsidchr,"%S",pte->newClsid);
	if(wcsstr(regPath,pte->newClsid)){
		flag = TRUE;
		//DbgPrint("checkClsid return true, regPathStr=%s, newclsidchr=%s.\n",regPathStr,pte->newClsid);		
	}
	//sprintf(clsidchr,"%S",pte->oldClsid);
	if(wcsstr(regPath,pte->oldClsid)){
		flag = TRUE;
		//DbgPrint("checkClsid return true, regPathStr=%s, oldclsidchr=%s.\n",regPathStr,pte->oldClsid);		
	}
	
	//sprintf(newProgIdchr,"%S",pte->newProgId);
//	if(strstr(regPathchr,newProgIdchr))
	if(wcsstr(regPath,pte->newProgId)){
		//DbgPrint("checkClsid return true, regPathStr=%s, newProgId=%s.\n",regPathStr,pte->newProgId);		
		flag = TRUE;
	}
	if(wcsstr(regPath,pte->oldProgId)){
		//DbgPrint("checkClsid return true, regPathStr=%s, oldProgId=%s.\n",regPathStr,pte->oldProgId);		
		flag = TRUE;
	}	
//	if(wcsstr(regPath,pte->newTypeLibId))
	//	flag = TRUE;
		
//	DbgPrint("checkClsid: %S, %S, %S.\n",regPath,pte->newAppId,pte->newAppName);
//	if((wcsstr(regPath,L"AppID"))&&(pte->newAppId[0]!=L'\0')){
	//	if(wcsstr(regPath,pte->newAppId))
		//	flag = TRUE;
		//if((wcsstr(regPath,pte->newAppName)))
			//flag = TRUE;
	//}
	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();

	return flag;
}

