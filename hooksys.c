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
 *  This file has the main FVM driver implementations
 */

#include <ntddk.h>
#include <stdlib.h>
#include <ntstrsafe.h>
#include "fvm_table.h"
#include "fvm_util.h"
#include "fvm_file.h"
#include "fvm_reg.h"
#include "fvm_obj.h"
#include "fvm_syscalls.h"
#include "fvm_daemon.h"
#include "fvm_vm.h"

#define FVM_HOOKSYS_POOL_TAG '9GAT'

#define ID_TAG	'1TAG'


//
// Lookaside buffer allocation
//
PAGED_LOOKASIDE_LIST  FileFullPathLookaside; //_MAX_PATH*2*sizeof(WCHAR)
PAGED_LOOKASIDE_LIST  FilebufLookaside;         //2048*sizeof(CHAR)      //for copy file
PAGED_LOOKASIDE_LIST  WC1kLookaside;            //1024*sizeof(WCHAR)
PAGED_LOOKASIDE_LIST  WC512Lookaside;            //512*sizeof(WCHAR)
PAGED_LOOKASIDE_LIST  WC256Lookaside;            //256*sizeof(WCHAR)
PAGED_LOOKASIDE_LIST  C1kLookaside;            //1024*sizeof(CHAR)

PVOID gpEventObject = NULL;
BOOLEAN gReferenceEvent = FALSE;
CLIENT_ID gClientIdBuf = {0,0};
ULONG fvm_Calls_In_Progress = 0;

PDEVICE_OBJECT TdiDeviceObject = NULL;
PFILE_OBJECT TdiFileObject = NULL;

PFVMID_DPCPID DPCPidlist = NULL;

/* Windows release specific system call nos. */
static UINT ID_NTREADVIRTUALMEMORY;
static UINT ID_ZWQUERYINFORMATIONTHREADAD;
static UINT ID_ZWRESUMETHREADAD;
static UINT ID_ZWCREATETHREADA;
static UINT ID_NTQUERYATTRIBUTESFILE;
static UINT ID_NTQUERYFULLATTRIBUTESFILE;
static UINT ID_NTCREATENAMEDPIPEFILE;
static UINT ID_NTCREATEMAILSLOTFILE;
static UINT ID_NTOPENPROCESS;
static UINT ID_NTCREATEMUTANT;
static UINT ID_NTOPENMUTANT;
static UINT ID_NTCREATESEMAPHORE;
static UINT ID_NTOPENSEMAPHORE;
static UINT ID_NTCREATETIMER;
static UINT ID_NTOPENTIMER;
static UINT ID_NTCREATEIOCOMPLETION;
static UINT ID_NTOPENIOCOMPLETION;
static UINT ID_NTCREATEEVENTPAIR;
static UINT ID_NTOPENEVENTPAIR;
static UINT ID_NTCREATEPORT;
static UINT ID_NTCREATEWAITABLEPORT;
static UINT ID_NTSECURECONNECTPORT;
static UINT ID_NTSETVALUEKEY;

NTSYSAPI
NTSTATUS
NTAPI
ZwCreateSection (
	OUT PHANDLE phSection,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE hFile OPTIONAL
);

typedef enum _SYSTEM_INFORMATION_CLASS { 
	SystemBasicInformation, 				// 0 
	SystemProcessorInformation, 			// 1 
	SystemPerformanceInformation, 			// 2
	SystemTimeOfDayInformation, 			// 3
	SystemNotImplemented1, 				// 4
	SystemProcessesAndThreadsInformation, 		// 5
	SystemCallCounts, 					// 6
	SystemConfigurationInformation, 			// 7
	SystemProcessorTimes, 				// 8
	SystemGlobalFlag, 					// 9
	SystemNotImplemented2, 				// 10
	SystemModuleInformation, 				// 11
	SystemLockInformation, 				// 12
	SystemNotImplemented3, 				// 13
	SystemNotImplemented4, 				// 14
	SystemNotImplemented5, 				// 15
	SystemHandleInformation, 				// 16
	SystemObjectInformation, 				// 17
	SystemPagefileInformation, 				// 18
	SystemInstructionEmulationCounts, 			// 19
	SystemInvalidInfoClass1, 				// 20
	SystemCacheInformation, 				// 21
	SystemPoolTagInformation, 				// 22
	SystemProcessorStatistics, 				// 23
	SystemDpcInformation, 				// 24
	SystemNotImplemented6, 				// 25
	SystemLoadImage, 					// 26
	SystemUnloadImage, 				// 27
	SystemTimeAdjustment, 				// 28
	SystemNotImplemented7, 				// 29
	SystemNotImplemented8, 				// 30
	SystemNotImplemented9, 				// 31
	SystemCrashDumpInformation, 			// 32
	SystemExceptionInformation, 			// 33
	SystemCrashDumpStateInformation, 			// 34
	SystemKernelDebuggerInformation, 			// 35
	SystemContextSwitchInformation, 			// 36
	SystemRegistryQuotaInformation, 			// 37
	SystemLoadAndCallImage, 				// 38
	SystemPrioritySeparation, 				// 39
	SystemNotImplemented10, 				// 40
	SystemNotImplemented11, 				// 41
	SystemInvalidInfoClass2, 				// 42
	SystemInvalidInfoClass3, 				// 43
	SystemTimeZoneInformation, 				// 44
	SystemLookasideInformation, 			// 45
	SystemSetTimeSlipEvent, 				// 46
	SystemCreateSession, 				// 47
	SystemDeleteSession, 				// 48
	SystemInvalidInfoClass4, 				// 49
	SystemRangeStartInformation, 			// 50
	SystemVerifierInformation, 				// 51
	SystemAddVerifier, 				// 52
	SystemSessionProcessesInformation 			// 53
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	LONG State;
	LONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

int msi_owner = -1;
LONG num_process = 0;
int is_added = 0;

LONG service_pid = 0;
static int get_installerpid();
ULONG curr_inst_vmid = INVALID_VMID;

NTSTATUS
MakeAsynchronousRequestCompletion(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp,
    IN PVOID            Context
    )
{
    PMDL mdl, nextMdl;

    // 
    // If the target device object is set up to do buffered i/o 
    // (TopOfDeviceStack->Flags and DO_BUFFERED_IO), then 
    // IoBuildAsynchronousFsdRequest request allocates a system buffer
    // for read and write operation. If you stop the completion of the IRP
    // here, you must free that buffer.
    // 

    if(Irp->AssociatedIrp.SystemBuffer && (Irp->Flags & IRP_DEALLOCATE_BUFFER) ) {
            ExFreePool(Irp->AssociatedIrp.SystemBuffer);
    }
    
    // 
    // If the target device object is set up do direct i/o (DO_DIRECT_IO), then 
    // IoBuildAsynchronousFsdRequest creates an MDL to describe the buffer
    // and locks the pages. If you stop the completion of the IRP, you must unlock
    // the pages and free the MDL.
    // 
    
    else if (Irp->MdlAddress != NULL) {
        for (mdl = Irp->MdlAddress; mdl != NULL; mdl = nextMdl) {
            nextMdl = mdl->Next;
            MmUnlockPages( mdl ); IoFreeMdl( mdl ); // This function will also unmap pages.
        }
        Irp->MdlAddress = NULL;
    }

    if(Context) {
        ExFreePool(Context);
    }

    // 
    // If you intend to queue the IRP and reuse it for another request,
    // make sure you call IoReuseIrp(Irp, STATUS_SUCCESS) before you reuse.
    // 
    IoFreeIrp(Irp);

    // 
    // NOTE: this is the only status that you can return for driver-created asynchronous IRPs.
    // 
    return STATUS_MORE_PROCESSING_REQUIRED;
}


/*
 *-----------------------------------------------------------------------------
 * 
 * FVM_removeNDISKey
 *
 *
 * Results:
 *     This function passes the FVM ID to the NDIS layer for the corresponding
 *     set of keys to be removed from the NDIS layer.
 *
 *-----------------------------------------------------------------------------
 */
VOID DP_TdiWrite(char *buf, int size)
{
	UNICODE_STRING TdiDevice;
	NTSTATUS ret;

  
    PIRP                irp;
    IO_STATUS_BLOCK     ioStatus;
	LARGE_INTEGER	startingOffset;
	PIO_STACK_LOCATION	nextStack;
	PVOID context;

	

	// Add the pid and the VMID to the NDIS driver
	if (!TdiDeviceObject) {

		RtlInitUnicodeString(&TdiDevice, L"\\Device\\dpnetctl");
		
		ret = IoGetDeviceObjectPointer(&TdiDevice,
						   FILE_ALL_ACCESS,
						   &TdiFileObject,
						   &TdiDeviceObject);

		if( !NT_SUCCESS(ret) )	{
			DbgPrint("Failed to get device object for NDIS Driver. Error : 0x%x\n", ret);
			goto error;
		}
	}

	startingOffset.QuadPart = (LONGLONG) 0;

	

	irp = IoBuildAsynchronousFsdRequest(
				IRP_MJ_WRITE,
				TdiDeviceObject,
				buf,
				size,
				&startingOffset, // Optional
				NULL
				); 

	if (NULL == irp) {
		DbgPrint("Failed to create an IRP for talking to the NDIS Driver !\n");
		goto error;
	}

	// 
	// Allocate memory for context structure to be passed to the completion routine.
	// 
	context = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG_PTR), 'ITag');
	if (NULL == context) {
		IoFreeIrp(irp);
		DbgPrint("Failed to allocate memory for compeltion routine context structure !\n");
		goto error;
	}

	IoSetCompletionRoutine(irp,
				   MakeAsynchronousRequestCompletion,
				   context,
				   TRUE,
				   TRUE,
				   TRUE);
	// 
	// If you want to change any value in the IRP stack, you must
	// first obtain the stack location by calling IoGetNextIrpStackLocation.
	// This is the location that is initialized by the IoBuildxxx requests and	
	// is the one that the target device driver is going to view.
	// 
	nextStack = IoGetNextIrpStackLocation(irp);

	// 
	// Change the MajorFunction code to something appropriate.
	//
	nextStack->MajorFunction = IRP_MJ_WRITE;
	nextStack->Parameters.Write.Length = size;
    nextStack->Parameters.Write.ByteOffset = startingOffset;

	ret = IoCallDriver(TdiDeviceObject, irp);

	
error :
	return;

}


/*
 *-----------------------------------------------------------------------------
 * 
 * FVM_removeNDISKey
 *
 *
 * Results:
 *     This function passes the FVM ID to the NDIS layer for the corresponding
 *     set of keys to be removed from the NDIS layer.
 *
 *-----------------------------------------------------------------------------
 */
VOID FVM_removeNDISKey(ULONG vmID)
{
	

	char buf[24], pid[11], FVMID[11];
	NTSTATUS  status;

	// Add the FVM ID to the buffer to passed to the NDIS driver
	RtlZeroMemory(buf, sizeof(buf));

	status = RtlStringCbPrintfA(pid, sizeof(pid), "%lu", 0);			// Here we don't really care about the pid
	if (!NT_SUCCESS(status)){
      DbgPrint("Unable to write to string pid func: FVM_removeNDISKey code:%x\n", status);
      return;
	}

	status = RtlStringCbPrintfA(FVMID, sizeof(FVMID), "%lu", vmID);	// The only thing the NDIS driver needs is the FVM ID
	if (!NT_SUCCESS(status)){
      DbgPrint("Unable to write to string FVMID func: FVM_removeNDISKey code: %x\n", status);
      return;
	}
	buf[0] = 'R';
	
	memcpy(buf+1, pid, strlen(pid));
	
	memcpy(buf + 1+ sizeof(pid), FVMID,  strlen(FVMID));	
	buf[23] = '\0';

	DP_TdiWrite(buf, sizeof(buf));
	return;

}



/*
 *-----------------------------------------------------------------------------
 *
 * FVM_KillAllProcesses
 *
 * Results:
 *     This function kills all the processes running inside the VM with VMID
 *     passed as the parameter.
 *
 *-----------------------------------------------------------------------------
 */
VOID FVM_KillAllProcesses(ULONG vmID)
{
	int i;
	PFVM_PVM_TBL_ENTRY pte;
	HANDLE hProcess = 0;

	CLIENT_ID cid1;
	OBJECT_ATTRIBUTES attr;
	NTSTATUS status;

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&FVM_processVMRes, TRUE);

	for (i = 0; i < MAX_TBL_ENTRIES; i++) {
		for (pte=FVM_pvm_pid_tbl[i]; pte; pte=pte->next) {
			if (pte->pvm_id == vmID) {
				DbgPrint("******* Data Paladin Client Terminated ! Killing process :%lu\n", pte->pid);

				cid1.UniqueProcess = (HANDLE)pte->pid;
				cid1.UniqueThread = NULL;

				InitializeObjectAttributes(&attr, NULL, 0, NULL, NULL);				
				status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &attr, &cid1);

				if (status == STATUS_SUCCESS) {
					FvmVm_RemovePid(pte->pid);
					FvmVm_removeNewProcess(pte->pid);

					status = ZwTerminateProcess(hProcess, 0); 
					ZwClose(hProcess);
				}
			}
		}
	}

	ExReleaseResourceLite(&FVM_processVMRes);
	KeLeaveCriticalRegion();

}


/*
 *-----------------------------------------------------------------------------
 *
 * FVM_ProcessCallback
 *
 *
 *
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
VOID FVM_ProcessCallback(IN HANDLE  hParentId, IN HANDLE  hProcessId,
    IN BOOLEAN bCreate)
{
	int pvm_id, ppid, cpid;
	
	InterlockedIncrement(&fvm_Calls_In_Progress);

	try {
		ppid = (int)hParentId;
		cpid = (int)hProcessId;

		if (bCreate == TRUE) {
			pvm_id = FvmVm_GetPVMId(ppid);
			
			if (pvm_id != INVALID_VMID) {
				char *logs;
#ifdef RPCSS
				FvmVm_AddPid(cpid, pvm_id,-1);
#else
				FvmVm_AddPid(cpid, pvm_id);
#endif

#ifdef logNtCreateProcess
				logs = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
				if (logs == NULL) {
					DbgPrint("NtClose: ExAllocateFromPagedLookasideList fail\n");  
				}
				else{
					if(pvms[pvm_id]->logHandle){
						ticks tm = getticks();
						IO_STATUS_BLOCK Iosb;
						NTSTATUS status;
						status = RtlStringCbPrintfA(logs, _MAX_PATH*2*sizeof(WCHAR), 
							"%I64u, NtCreateProcess, %u, %u\r\n", tm.QuadPart, ppid, cpid);
						if (NT_SUCCESS(status)) {
							ZwWriteFile(pvms[pvm_id]->logHandle, NULL, NULL, NULL, 
								&Iosb, (void*)logs, strlen(logs)*sizeof(char), NULL, NULL);
						} else {
							DbgPrint("Error writing to log NtCreateProcess code: %x\n", status);
						}						
					}
					ExFreePool(logs);
				}
#endif
			}

			FvmVm_addNewProcess(cpid);

		} else {
		
			// If the process which is exiting is the DP Client, then we need to kill
			// all the processes which were running inside that VM.
			pvm_id = getDPClientVMID(cpid);

			if (pvm_id != INVALID_VMID) {

				if (VMexists(pvm_id)) {

					// Kill all the processes inside the VM
					FVM_KillAllProcesses(pvm_id);
					
					// Destroy the VM
					DbgPrint("\nData Paladin Client terminated unexpectedly. Terminating VM %d\n", pvm_id);
					FvmTable_DumpVMDeleteLog(pvm_id, 1); //lclam

					FvmTable_DeleteLogCleanup(pvm_id);
					FvmTable_HandleTableCleanup(pvm_id);

#ifdef USE_FS_MAP
					FvmTable_FVMFileListCleanup(pvm_id);
#endif

					FvmVm_DestroyPVM(pvm_id);

					// We need to clean up the keys from the NDIS Driver
					FVM_removeNDISKey(pvm_id);
				}
				
				removeDPClientPID(cpid);

			} else {

				pvm_id = FvmVm_GetPVMId((int)cpid);

				if (pvm_id != INVALID_VMID) {
					FvmVm_RemovePid(cpid);
				}
				FvmVm_removeNewProcess(cpid);
			}
		}
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("Exception occured in ProcessCallBack %x \n",GetExceptionCode());
	}
	InterlockedDecrement(&fvm_Calls_In_Progress);
}


NTSTATUS FVM_NewNtLoadDriver(IN PUNICODE_STRING driverRegistryEntry)
{
	NTSTATUS rc;
	ULONG vmid = INVALID_VMID;

	InterlockedIncrement(&fvm_Calls_In_Progress);

	vmid = FvmVm_GetPVMId((ULONG)PsGetCurrentProcessId());

	if(vmid == INVALID_VMID)
		//rc =  ((NtLoadDriverProc)(NtLoadDriverProc))(driverRegistryEntry);
		rc =  winNtLoadDriverProc(driverRegistryEntry);
	else {
		rc = STATUS_PRIVILEGE_NOT_HELD;
	}

	InterlockedDecrement (&fvm_Calls_In_Progress);
	return rc;
}

NTSTATUS NTAPI FVM_NtResumeThread(IN HANDLE threadHandle,
    OUT PULONG previousSuspendCount)
{
	NTSTATUS rc;
	PEPROCESS eProcess;
	int size, mSize = 0;
	int *rb;
	HANDLE ppid;
	PEB *peb;
	ULONG dwAddress;
	CLIENT_ID clid;
	HANDLE hProcess = 0, h_Process = 0;
	THREAD_BASIC_INFORMATION *tinfo = NULL;
	OBJECT_ATTRIBUTES attr = {sizeof(OBJECT_ATTRIBUTES), 0, NULL, OBJ_CASE_INSENSITIVE};
	PFVM_PROCESS_PARAMETERS par, temp1;
	WCHAR *name;
	LARGE_INTEGER timeout;
	struct FVM_new_process_t *npt = NULL;
	WCHAR tmpPath1[256];
	ULONG cpid;
	PWCHAR namePtr;
	LONG pvm_id, Status = 0;
	ULONG cbBuffer = 0x8000; // declare initial size of buffer - 32kb
    PSVC_TBL_ENTRY ste;
	PULONG  pBuffer = NULL;

	InterlockedIncrement(&fvm_Calls_In_Progress);
	h_Process = NtCurrentProcess();

	try {
		FvmUtil_GetBinaryPathName0(tmpPath1, 0);
		
		mSize = sizeof(THREAD_BASIC_INFORMATION) + 64 + sizeof(PEB) +
			        sizeof(PFVM_PROCESS_PARAMETERS)+512;
		tinfo = NULL;

		rc = FvmVm_AllocateVirtualMemory(NtCurrentProcess(), &tinfo, 0, &mSize,
			     MEM_COMMIT, PAGE_READWRITE);

		if (!NT_SUCCESS(rc)){
			goto end;
		}

		(char *) rb = (char *)tinfo + sizeof(THREAD_BASIC_INFORMATION)+8;
		(char *) peb = (char *) rb + 8;
		(char *) par = (char *)peb + sizeof(PEB)+4;
		(char *) name = (char *)par + sizeof(FVM_PROCESS_PARAMETERS)+4;


		rc = winNtQueryInformationThreadProc(threadHandle, ThreadBasicInformation,
			     tinfo, sizeof(THREAD_BASIC_INFORMATION), rb);
		if (!NT_SUCCESS(rc)){
			goto end;
		}
		//DbgPrint("Appln size = %ld\n", peb->AllocationSize);
		ppid = PsGetCurrentProcessId();
		//DbgPrint("ppid = %ld phandle = %ld\n",ppid,
			//tinfo->ClientId.UniqueProcess);

		if (ppid != tinfo->ClientId.UniqueProcess) {

			clid.UniqueProcess =  tinfo->ClientId.UniqueProcess;
			clid.UniqueThread = 0;

			rc = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &attr, &clid);
			if (!NT_SUCCESS(rc)) {
				goto end;
			}

			rc = PsLookupProcessByProcessId((ULONG)tinfo->ClientId.UniqueProcess,
				     &eProcess);
			if (!NT_SUCCESS(rc)) {
				DbgPrint("PsLookupProcessByProcessId()\n");
				goto end;
			}

			dwAddress = (ULONG)eProcess;
			if (dwAddress == 0 || dwAddress == INVALID_VMID)
				goto end;

			dwAddress += 0x1B0;
			if ((dwAddress = *(ULONG*)dwAddress) == 0)
				goto end;

			rc = winNtReadVirtualMemoryProc(hProcess, (PVOID)dwAddress, peb,
				     sizeof(PEB), rb);

			if (!NT_SUCCESS(rc)) {
				goto end;
			}
			rc = winNtReadVirtualMemoryProc(hProcess, peb->ProcessParameters, par,
				     sizeof(FVM_PROCESS_PARAMETERS), rb);
			if (!NT_SUCCESS(rc)) {
				goto end;
			}
			dwAddress = (ULONG)par->ApplicationName.Buffer +
				            (ULONG)peb->ProcessParameters;
			size = par->ApplicationName.Length;


			RtlZeroMemory(name, size + 2);
			rc = winNtReadVirtualMemoryProc(hProcess, (PVOID)dwAddress, name,
				     size, rb);
			if (!NT_SUCCESS(rc)) {
				goto end;
			}

			/*installer service begin*/
			if(0 == _wcsicmp(svc_inst_prog, name)) {
				//DbgPrint("inside installer service %S %S %S\n", svc_inst_prog,  name, tmpPath1);
				//only instance where msiexec.exe has a msiexec.exe parent, child shd belong to VM
				if(0 == _wcsicmp(svc_inst_prog, tmpPath1)) {
					if (curr_inst_vmid != INVALID_VMID) {
						//DbgPrint("Child process adding\n");
						DbgPrint("Inside resume thread\n");
						DbgPrint("ppid = %ld phandle = %ld\n",ppid,
							tinfo->ClientId.UniqueProcess);
						DbgPrint("name: %ws\n", name);
						
#ifdef RPCSS
						FvmVm_AddPid((ULONG)(tinfo->ClientId.UniqueProcess),curr_inst_vmid,-1);
#else
						FvmVm_AddPid((ULONG)(tinfo->ClientId.UniqueProcess),curr_inst_vmid);

#endif

						//DbgPrint("ChildProcess adding service process %ld\n", service_pid);
						if (service_pid != 0) {
#ifdef RPCSS
							FvmVm_AddPid(service_pid, curr_inst_vmid,-1);

#else
							FvmVm_AddPid(service_pid, curr_inst_vmid);

#endif							
							is_added = 1;
						}

						curr_inst_vmid = INVALID_VMID;
					}
				} else if(0 == _wcsicmp(svc_crt_prog, tmpPath1)) {
					if (curr_inst_vmid != INVALID_VMID) {
							service_pid = (ULONG)(tinfo->ClientId.UniqueProcess);
					}
				} else {//installer client
					pvm_id = FvmVm_GetPVMId((ULONG)ppid);
					if (pvm_id != INVALID_VMID)
						curr_inst_vmid = pvm_id;
					if (msi_owner == pvm_id) {
						num_process++;
					} else if (msi_owner == -1) {
						msi_owner = pvm_id;
						num_process = 1;
					}
				}
			}

			//check if Setup.exe launched
			else if(wcsstr(name, inst_cli_prog) != NULL) {
				pvm_id = FvmVm_GetPVMId((ULONG)ppid);
				curr_inst_vmid = pvm_id;
			}
			else if(0 == _wcsicmp(svc_crt_prog, tmpPath1) &&
			    NULL != (ste=IsService(name))) {
#ifdef RPCSS
				FvmVm_AddPid((ULONG)(tinfo->ClientId.UniqueProcess) , ste->pvm_id,-1);
#else
				FvmVm_AddPid((ULONG)(tinfo->ClientId.UniqueProcess) , ste->pvm_id);

#endif
			}
			/*installer service end*/

			cpid = (ULONG)tinfo->ClientId.UniqueProcess;

			namePtr = wcsrchr(name, L'\\');
			if (namePtr && _wcsicmp(namePtr, FVM_DAEMON_NAME) != 0) {
				npt = FvmVm_CheckProcessStatus(cpid, name);
			}

#ifdef logNtCreateProcess
			pvm_id = FvmVm_GetPVMId((ULONG)ppid);
			if (pvm_id != INVALID_VMID) {
				char *logs;
				DbgPrint("ppid = %ld phandle = %ld\n",ppid,
							tinfo->ClientId.UniqueProcess);
				DbgPrint("Image name: %ws\n", name);

				logs = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
				if (logs == NULL) {
					DbgPrint("NtResumeThread: ExAllocateFromPagedLookasideList fail\n");  
				}
				else{
					if(pvms[pvm_id]->logHandle){
						ticks tm = getticks();
						IO_STATUS_BLOCK Iosb;
						NTSTATUS status;
						RtlStringCbPrintfA(logs, _MAX_PATH*2*sizeof(WCHAR), 
							"%I64u, NtProcessImage, %ld, \\??\\%ws\r\n", tm.QuadPart, cpid, name);
						ZwWriteFile(pvms[pvm_id]->logHandle, NULL, NULL, NULL, 
								&Iosb, (void*)logs, strlen(logs)*sizeof(char), NULL, NULL);				
					}
					ExFreePool(logs);
				}
			}
#endif
			
			if (npt) {
				
				if (gReferenceEvent && gpEventObject) {
					memcpy(&gClientIdBuf, &tinfo->ClientId, sizeof(CLIENT_ID));
					KeSetEvent(gpEventObject, 0, FALSE);
				}
			}
		}
	end:
		if (tinfo) {
		    mSize = 0;
			FvmVm_FreeVirtualMemory(NtCurrentProcess(), &tinfo,
			    &mSize, MEM_RELEASE);
		}

		if (npt) {
			NTSTATUS lap;
			timeout.QuadPart = -50000000;
			if (npt->dllLoad){
				PKEVENT temp = npt->dllLoad;
			
				KeWaitForSingleObject(temp, Executive, KernelMode,
				      FALSE, &timeout);
				
				
				//ExFreePool(temp);
				
			}

			FvmVm_removeNewProcess(cpid);
		}
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FVM_NtResumeThread\n"));
	}

	//rc = RealZwResumeThread(threadHandle, previousSuspendCount);
	rc = winNtResumeThreadProc(threadHandle, previousSuspendCount);
	InterlockedDecrement(&fvm_Calls_In_Progress);

	return rc;
}


NTSTATUS FVM_HookServices(VOID)
{
   PsSetCreateProcessNotifyRoutine(FVM_ProcessCallback, FALSE);

	try {
		winNtReadVirtualMemoryProc = (NtReadVirtualMemoryProc)(SystemServiceByNo(ID_NTREADVIRTUALMEMORY));
		winNtQueryInformationThreadProc = (PVOID)(SystemServiceByNo(ID_ZWQUERYINFORMATIONTHREADAD));
		winNtResumeThreadProc = (NtResumeThreadProc)(SystemServiceByNo(ID_ZWRESUMETHREADAD));
		winNtLoadDriverProc = (NtLoadDriverProc)(SystemService(ZwLoadDriver));

		// File
		winNtCreateFileProc=(NtCreateFileProc)(SystemService(ZwCreateFile));
		winNtOpenFileProc = (NtOpenFileProc)(SystemService(ZwOpenFile));
		winNtReadFileProc = (NtReadFileProc)(SystemService(ZwReadFile));
		winNtWriteFileProc = (NtWriteFileProc)(SystemService(ZwWriteFile));
		winNtQueryAttributesFileProc = (NtQueryAttributesFileProc)(SystemServiceByNo(ID_NTQUERYATTRIBUTESFILE));
		winNtQueryFullAttributesFileProc = (NtQueryFullAttributesFileProc)(SystemServiceByNo(ID_NTQUERYFULLATTRIBUTESFILE));
		winNtQueryDirectoryFileProc = (NtQueryDirectoryFileProc)(SystemService(ZwQueryDirectoryFile));
		winNtQueryInformationFileProc = (NtQueryInformationFileProc)(SystemService(ZwQueryInformationFile));
		winNtSetInformationFileProc = (NtSetInformationFileProc)(SystemService(ZwSetInformationFile));
		winNtQueryVolumeInformationFileProc = (NtQueryVolumeInformationFileProc)(SystemService(ZwQueryVolumeInformationFile));
		winNtDeleteFileProc = (NtDeleteFileProc)(SystemService(ZwDeleteFile));
		winNtCreateNamedPipeFileProc = (NtCreateNamedPipeFileProc)(SystemServiceByNo(ID_NTCREATENAMEDPIPEFILE));
		winNtCreateMailslotFileProc = (NtCreateMailSlotFileProc)(SystemServiceByNo(ID_NTCREATEMAILSLOTFILE));
		winNtFsControlFileProc = (NtFsControlFileProc)(SystemServiceByNo(0x54));

		// Synchronization Object
		winNtCreateMutantProc = (NtCreateMutantProc)(SystemServiceByNo(ID_NTCREATEMUTANT));
		winNtOpenMutantProc = (NtOpenMutantProc)(SystemServiceByNo(ID_NTOPENMUTANT));
		winNtCreateSemaphoreProc = (NtCreateSemaphoreProc)(SystemServiceByNo(ID_NTCREATESEMAPHORE));
		winNtOpenSemaphoreProc = (NtOpenSemaphoreProc)(SystemServiceByNo(ID_NTOPENSEMAPHORE));
		winNtCreateEventProc = (NtCreateEventProc)(SystemService(ZwCreateEvent));
		winNtOpenEventProc = (NtOpenEventProc)(SystemService(ZwOpenEvent));
		winNtCreateTimerProc = (NtCreateTimerProc)(SystemServiceByNo(ID_NTCREATETIMER));
		winNtOpenTimerProc = (NtOpenTimerProc)(SystemServiceByNo(ID_NTOPENTIMER));
		winNtCreateIOCompletionProc = (NtCreateIOCompletionProc)(SystemServiceByNo(ID_NTCREATEIOCOMPLETION));
		winNtOpenIOCompletionProc = (NtOpenIOCompletionProc)(SystemServiceByNo(ID_NTOPENIOCOMPLETION));
		winNtCreateEventPairProc = (NtCreateEventPairProc)(SystemServiceByNo(ID_NTCREATEEVENTPAIR));
		winNtOpenEventPairProc = (NtOpenEventPairProc)(SystemServiceByNo(ID_NTOPENEVENTPAIR));

 		// Port Object
		winNtCreatePortProc = (NtCreatePortProc)(SystemServiceByNo(ID_NTCREATEPORT));
		winNtCreateWaitablePortProc = (NtCreateWaitablePortProc)(SystemServiceByNo(ID_NTCREATEWAITABLEPORT));
		winNtConnectPortProc = (NtConnectPortProc)(SystemService(ZwConnectPort));
		winNtSecureConnectPortProc = (NtSecureConnectPortProc)(SystemServiceByNo(ID_NTSECURECONNECTPORT));

		WinNtOpenProcess = (NTOpenProcess)(SystemServiceByNo(ID_NTOPENPROCESS));


		// Generic Object
		winNtCreateSectionProc = (NtCreateSectionProc)(SystemService(ZwCreateSection));
		winNtOpenSectionProc = (NtOpenSectionProc)(SystemService(ZwOpenSection));
		winNtCloseProc = (NtCloseProc)(SystemService(ZwClose));
		winNtQueryDirectoryObjectProc = (NtQueryDirectoryObjectProc)(SystemServiceByNo(0x92));

		// Registry
		
		winNtOpenKeyProc = (NtOpenKeyProc)(SystemService(ZwOpenKey));
		winNtCreateKeyProc = (NtCreateKeyProc)(SystemService(ZwCreateKey));
		winNtQueryKeyProc = (NtQueryKeyProc)(SystemService(ZwQueryKey));
		winNtDeleteKeyProc = (NtDeleteKeyProc)(SystemService(ZwDeleteKey));
		winNtDeleteValueKeyProc = (NtDeleteValueKeyProc)(SystemService(ZwDeleteValueKey));
		winNtSetValueKeyProc = (NtSetValueKeyProc)(SystemService(ZwSetValueKey));
		winNtQueryValueKeyProc = (NtQueryValueKeyProc)(SystemService(ZwQueryValueKey));
		winNtEnumerateKeyProc = (NtEnumerateKeyProc)(SystemService(ZwEnumerateKey));
		winNtEnumerateValueKeyProc = (NtEnumerateValueKeyProc)(SystemService(ZwEnumerateValueKey));
	
		_asm cli

		// Turn off the page write protection
		__asm {
			push eax
			mov eax, cr0
			and eax, not 10000h
			mov cr0, eax
			pop eax
		}

		// VM Management
		(NtResumeThreadProc)(SystemServiceByNo(ID_ZWRESUMETHREADAD)) = FVM_NtResumeThread;
		(NtLoadDriverProc)(SystemService(ZwLoadDriver)) = FVM_NewNtLoadDriver;
		
		// File
		
		(NtCreateFileProc)(SystemService(ZwCreateFile)) = FvmFile_NtCreateFile;
		(NtOpenFileProc)(SystemService(ZwOpenFile)) = FvmFile_NtOpenFile;
		(NtReadFileProc)(SystemService(ZwReadFile)) = FvmFile_NtReadFile;
		(NtWriteFileProc)(SystemService(ZwWriteFile)) = FvmFile_NtWriteFile;
		(NtQueryAttributesFileProc)(SystemServiceByNo(ID_NTQUERYATTRIBUTESFILE)) = FvmFile_NtQueryAttributesFile;
		(NtQueryFullAttributesFileProc)(SystemServiceByNo(ID_NTQUERYFULLATTRIBUTESFILE)) = FvmFile_NtQueryFullAttributesFile;
		
		(NtQueryDirectoryFileProc)(SystemService(ZwQueryDirectoryFile)) = FvmFile_NtQueryDirectoryFile;
		
		(NtDeleteFileProc)(SystemService(ZwDeleteFile)) = FvmFile_NtDeleteFile;
		(NtQueryInformationFileProc)(SystemService(ZwQueryInformationFile)) = FvmFile_NtQueryInformationFile;
		(NtQueryVolumeInformationFileProc)(SystemService(ZwQueryVolumeInformationFile)) = FvmFile_NtQueryVolumeInformationFile;
		(NtSetInformationFileProc)(SystemService(ZwSetInformationFile)) = FvmFile_NtSetInformationFile;
		
		(NtCreateNamedPipeFileProc)(SystemServiceByNo(ID_NTCREATENAMEDPIPEFILE)) = FvmFile_NtCreateNamedPipeFile;
		(NtCreateMailSlotFileProc)(SystemServiceByNo(ID_NTCREATEMAILSLOTFILE)) = FvmFile_NtCreateMailslotFile;
		//(NtFsControlFileProc)(SystemServiceByNo(0x54)) = FvmFile_NtFsControlFile;

		
 		// Synchronization Object
 		
		(NtCreateMutantProc)(SystemServiceByNo(ID_NTCREATEMUTANT)) = FvmObj_NtCreateMutant;
		(NtOpenMutantProc)(SystemServiceByNo(ID_NTOPENMUTANT)) = FvmObj_NtOpenMutant;
		(NtCreateSemaphoreProc)(SystemServiceByNo(ID_NTCREATESEMAPHORE)) = FvmObj_NtCreateSemaphore;
		(NtOpenSemaphoreProc)(SystemServiceByNo(ID_NTOPENSEMAPHORE)) = FvmObj_NtOpenSemaphore;
		(NtCreateEventProc)(SystemService(ZwCreateEvent)) = FvmObj_NtCreateEvent;
		(NtOpenEventProc)(SystemService(ZwOpenEvent)) = FvmObj_NtOpenEvent;
		(NtCreateTimerProc)(SystemServiceByNo(ID_NTCREATETIMER)) = FvmObj_NtCreateTimer;
		(NtOpenTimerProc)(SystemServiceByNo(ID_NTOPENTIMER)) = FvmObj_NtOpenTimer;
		(NtCreateIOCompletionProc)(SystemServiceByNo(ID_NTCREATEIOCOMPLETION)) = FvmObj_NtCreateIoCompletion;
		(NtOpenIOCompletionProc)(SystemServiceByNo(ID_NTOPENIOCOMPLETION)) = FvmObj_NtOpenIoCompletion;
		(NtCreateEventPairProc)(SystemServiceByNo(ID_NTCREATEEVENTPAIR)) = FvmObj_NtCreateEventPair;
		(NtOpenEventPairProc)(SystemServiceByNo(ID_NTOPENEVENTPAIR)) = FvmObj_NtOpenEventPair;
		
		(NTOpenProcess)(SystemServiceByNo(ID_NTOPENPROCESS)) = FvmObj_NtOpenProcess;
		
		// Port Object
		(NtCreatePortProc)(SystemServiceByNo(ID_NTCREATEPORT)) = FvmObj_NtCreatePort;
		(NtCreateWaitablePortProc)(SystemServiceByNo(ID_NTCREATEWAITABLEPORT)) = FvmObj_NtCreateWaitablePort;
		(NtConnectPortProc)(SystemService(ZwConnectPort)) = FvmObj_NtConnectPort;
		(NtSecureConnectPortProc)(SystemServiceByNo(ID_NTSECURECONNECTPORT)) = FvmObj_NtSecureConnectPort;

		// Generic Object
		(NtCreateSectionProc)(SystemService(ZwCreateSection)) = FvmObj_NtCreateSection;
		(NtOpenSectionProc)(SystemService(ZwOpenSection)) = FvmObj_NtOpenSection;
		(NtCloseProc)(SystemService(ZwClose)) = FvmObj_NtClose;
		(NtQueryDirectoryObjectProc)(SystemServiceByNo(0x92)) =  FvmObj_QueryDirectoryObjectProc;
		
		// Registry
		
		(NtOpenKeyProc)(SystemService(ZwOpenKey)) = FvmReg_NtOpenKey;
		(NtCreateKeyProc)(SystemService(ZwCreateKey)) = FvmReg_NtCreateKey;
		(NtQueryKeyProc)(SystemService(ZwQueryKey)) = FvmReg_NtQueryKey;
		(NtDeleteKeyProc)(SystemService(ZwDeleteKey)) =  FvmReg_NtDeleteKey;
		(NtEnumerateKeyProc)(SystemService(ZwEnumerateKey)) =  FvmReg_NtEnumerateKey;
		(NtSetValueKeyProc)(SystemService(ZwSetValueKey)) = FvmReg_NtSetValueKey;
		
		__asm {
			 push eax
			 mov eax, cr0
			 or eax, 10000h
			 mov cr0, eax
			 pop eax
		}
		_asm sti

		return STATUS_SUCCESS;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FVM_HookServices\n"));
		return STATUS_ACCESS_DENIED;
	}
}

VOID FVM_UnHookServices(VOID)
{
	try {
		_asm cli

		// Turn off the page write protection
		__asm{
			push eax
			mov eax, cr0
			and eax, not 10000h
			mov cr0, eax
			pop eax
		}


		// VM Management
		(NtResumeThreadProc)(SystemServiceByNo(ID_ZWRESUMETHREADAD)) = winNtResumeThreadProc;
		(NtLoadDriverProc)(SystemService(ZwLoadDriver)) = winNtLoadDriverProc;

		// File
		(NtCreateFileProc)(SystemService(ZwCreateFile))=winNtCreateFileProc;
		(NtOpenFileProc)(SystemService(ZwOpenFile)) = winNtOpenFileProc;
		(NtReadFileProc)(SystemService(ZwReadFile)) = winNtReadFileProc;
		(NtWriteFileProc)(SystemService(ZwWriteFile)) = winNtWriteFileProc;
		(NtQueryAttributesFileProc)(SystemServiceByNo(ID_NTQUERYATTRIBUTESFILE)) = winNtQueryAttributesFileProc;
		(NtQueryFullAttributesFileProc)(SystemServiceByNo(ID_NTQUERYFULLATTRIBUTESFILE)) = winNtQueryFullAttributesFileProc;
		(NtQueryDirectoryFileProc)(SystemService(ZwQueryDirectoryFile)) = winNtQueryDirectoryFileProc;
		(NtQueryInformationFileProc)(SystemService(ZwQueryInformationFile)) = winNtQueryInformationFileProc;
		(NtSetInformationFileProc)(SystemService(ZwSetInformationFile)) = winNtSetInformationFileProc;
		(NtQueryVolumeInformationFileProc)(SystemService(ZwQueryVolumeInformationFile)) = winNtQueryVolumeInformationFileProc;
		(NtDeleteFileProc)(SystemService(ZwDeleteFile)) = winNtDeleteFileProc;
		(NtCreateNamedPipeFileProc)(SystemServiceByNo(ID_NTCREATENAMEDPIPEFILE)) = winNtCreateNamedPipeFileProc;
		(NtCreateMailSlotFileProc)(SystemServiceByNo(ID_NTCREATEMAILSLOTFILE)) = winNtCreateMailslotFileProc;
		(NtFsControlFileProc)(SystemServiceByNo(0x54)) = winNtFsControlFileProc;
		// Synchronization Object
		(NtCreateMutantProc)(SystemServiceByNo(ID_NTCREATEMUTANT)) = winNtCreateMutantProc;
		(NtOpenMutantProc)(SystemServiceByNo(ID_NTOPENMUTANT)) = winNtOpenMutantProc;
		(NtCreateSemaphoreProc)(SystemServiceByNo(ID_NTCREATESEMAPHORE)) = winNtCreateSemaphoreProc;
		(NtOpenSemaphoreProc)(SystemServiceByNo(ID_NTOPENSEMAPHORE)) = winNtOpenSemaphoreProc;
		(NtCreateEventProc)(SystemService(ZwCreateEvent)) = winNtCreateEventProc;
		(NtOpenEventProc)(SystemService(ZwOpenEvent)) = winNtOpenEventProc;
		(NtCreateTimerProc)(SystemServiceByNo(ID_NTCREATETIMER)) = winNtCreateTimerProc;
		(NtOpenTimerProc)(SystemServiceByNo(ID_NTOPENTIMER)) = winNtOpenTimerProc;
		(NtCreateIOCompletionProc)(SystemServiceByNo(ID_NTCREATEIOCOMPLETION)) = winNtCreateIOCompletionProc;
		(NtOpenIOCompletionProc)(SystemServiceByNo(ID_NTOPENIOCOMPLETION)) = winNtOpenIOCompletionProc;
		(NtCreateEventPairProc)(SystemServiceByNo(ID_NTCREATEEVENTPAIR)) = winNtCreateEventPairProc;
		(NtOpenEventPairProc)(SystemServiceByNo(ID_NTOPENEVENTPAIR)) = winNtOpenEventPairProc;

 		(NTOpenProcess)(SystemServiceByNo(ID_NTOPENPROCESS)) = WinNtOpenProcess;

		// Port Object
 		(NtCreatePortProc)(SystemServiceByNo(ID_NTCREATEPORT)) = winNtCreatePortProc;
		(NtCreateWaitablePortProc)(SystemServiceByNo(ID_NTCREATEWAITABLEPORT)) = winNtCreateWaitablePortProc;
		(NtConnectPortProc)(SystemService(ZwConnectPort)) = winNtConnectPortProc;
		(NtSecureConnectPortProc)(SystemServiceByNo(ID_NTSECURECONNECTPORT)) = winNtSecureConnectPortProc;

		// Generic Object
		(NtCreateSectionProc)(SystemService(ZwCreateSection)) = winNtCreateSectionProc;
		(NtOpenSectionProc)(SystemService(ZwOpenSection)) = winNtOpenSectionProc;
		(NtCloseProc)(SystemService(ZwClose)) = winNtCloseProc;
		(NtQueryDirectoryObjectProc)(SystemServiceByNo(0x92)) =  winNtQueryDirectoryObjectProc;

		// Registry
		(NtOpenKeyProc)(SystemService(ZwOpenKey)) = winNtOpenKeyProc;
		(NtCreateKeyProc)(SystemService(ZwCreateKey)) = winNtCreateKeyProc;
		(NtQueryKeyProc)(SystemService(ZwQueryKey)) = winNtQueryKeyProc;
		(NtDeleteKeyProc)(SystemService(ZwDeleteKey)) =  winNtDeleteKeyProc;
		(NtSetValueKeyProc) (SystemServiceByNo(ID_NTSETVALUEKEY))= winNtSetValueKeyProc;
		(NtQueryValueKeyProc) (SystemService(ZwQueryValueKey)) = winNtQueryValueKeyProc;
		(NtEnumerateKeyProc)(SystemService(ZwEnumerateKey)) =  winNtEnumerateKeyProc;
		(NtEnumerateValueKeyProc) (SystemService(ZwEnumerateValueKey)) = winNtEnumerateValueKeyProc;

		__asm{
			push eax
			mov eax, cr0
			or eax, 10000h
			mov cr0, eax
			pop eax
		}
		_asm sti
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in FVM_UnHookServices\n"));
	}

	PsSetCreateProcessNotifyRoutine(FVM_ProcessCallback, TRUE);
}

NTSTATUS FVM_CommDriver_Create(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS FVM_CommDriver_Close(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS FVM_SysCallMonDeviceControl(IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG controlCode;
	PIO_STACK_LOCATION irpStack;
	ULONG *vmNumber, vmn = -1, pid = -1, DPclientPid = -1;
	WCHAR *vmName; //lclam vmName[32];
	WCHAR* buf = NULL;
	char buf2[32];
	WCHAR *vmIdStr; //lclam
	WCHAR *vmRoot; //lclam
	WCHAR *vmPidStr; //lclam
	ULONG vmIp = -1, vmContext = -1;
	int pvm_index, rcode, *rcd;
	int i, j;
	PFVM_PVM_TBL_ENTRY pte;
	ULONG vmid = 0, *pvmid;
	ULONG _length = 256;
//	WCHAR IOInputBuffer[1024];
	PWCHAR IOInputBuffer=NULL;
	ULONG outputBufferLength;
	size_t len;

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

       IOInputBuffer = ExAllocateFromPagedLookasideList( &WC1kLookaside );
       if (IOInputBuffer == NULL) {
              DbgPrint("FVM_SysCallMonDeviceControl: ExAllocateFromPagedLookasideList fail\n"); 
              status = STATUS_ACCESS_DENIED;
              goto nExit;
	}

	RtlZeroMemory(IOInputBuffer, sizeof(WCHAR) * 32);

	switch(controlCode) {
	case IO_REFERENCE_EVENT:
		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer) {
			HANDLE hEvent;
			OBJECT_HANDLE_INFORMATION objHandleInfo;

			gReferenceEvent = TRUE;
			hEvent = *(PHANDLE)
				         irpStack->Parameters.DeviceIoControl.Type3InputBuffer;
			status = ObReferenceObjectByHandle( hEvent, GENERIC_ALL, NULL,
				         KernelMode, &gpEventObject, &objHandleInfo);
			if (!NT_SUCCESS(status)){
				DbgPrint("ObReferenceObjectByHandle failed! status = %x\n",
				    status);
			}
		}
		break;

	case IO_QUERY_CLIENTID:
		if (Irp->UserBuffer != NULL) {
			PWCHAR createimage;

			memcpy(Irp->UserBuffer, &gClientIdBuf, sizeof(CLIENT_ID));
			createimage = FvmVm_FindProcessCreateImage(
						      (ULONG)gClientIdBuf.UniqueProcess);
			memset(&gClientIdBuf, 0, sizeof(CLIENT_ID));

			if (createimage) {
				/*
				wcscpy((PWCHAR)((PCHAR)Irp->UserBuffer+sizeof(CLIENT_ID)),
				    createimage);
			      */
				status = RtlStringCbCopyW((PWCHAR)((PCHAR)Irp->UserBuffer+sizeof(CLIENT_ID)), 
				irpStack->Parameters.DeviceIoControl.OutputBufferLength - sizeof(CLIENT_ID), createimage);

				if (NT_SUCCESS(status)) {

					Irp->IoStatus.Information = sizeof(CLIENT_ID) +
				    wcslen(createimage)*2 + 2;
					
				} else {
				
					DbgPrint("Copy Error in IO_QUERY_CLIENTID code : %x\n", status);
					Irp->IoStatus.Information = 0;
				}
				
			} else {
				Irp->IoStatus.Information = sizeof(CLIENT_ID);
			}
			KeClearEvent(gpEventObject);

			Irp->IoStatus.Status = status;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
//			return status;
                     goto nExit;
		}
		break;

	case IO_RESUME_PROCESS:
		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
			PCLIENT_ID pcid;

			pcid = (PCLIENT_ID)
				       (irpStack->Parameters.DeviceIoControl.Type3InputBuffer);
			FvmVm_UpdateProcessStatus((ULONG)pcid->UniqueProcess);
		}
		break;

	case IO_QUERY_VM_LIST:
		outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
		
		DbgPrint("Query VM List\n");
		try {
			IOInputBuffer[0] = L'\0';
			_length = _MAX_PATH*2;
			FvmUtil_FindProcessStrSID(IOInputBuffer, &_length);
			DbgPrint("Sid: %S\n", IOInputBuffer);

			FvmUtil_FindProcessStrSID(IOInputBuffer, &_length);
			rcd = (int*) Irp->UserBuffer;
			if (!rcd){
				DbgPrint("Invalid User Buffer\n");
				break;
			}

			buf = (WCHAR*)(rcd+1);
			*buf = 0;
			rcd[0]=0;

			for (pvm_index = 0; pvm_index < MAX_NUM_PVMS; pvm_index ++) {
				if (pvms[pvm_index] != NULL){
					if (wcscmp(pvms[pvm_index]->SidStr, IOInputBuffer)!=0)
						continue;
					status = RtlStringCbCopyW(buf, outputBufferLength, pvms[pvm_index]->idStr);
					if (!NT_SUCCESS(status)) {
						DbgPrint("Copy Error in IO_QUERY_VM_LIST code : %x\n", status);
						break;
					}
					//wcscpy(buf, pvms[pvm_index]->idStr);
					len = wcslen(buf);
					buf += len;
					outputBufferLength -= len;

					*(int *)buf = pvms[pvm_index]->status;
					buf += sizeof(int);
					outputBufferLength -= sizeof(int);

					rcd[0]++;
					DbgPrint("dump vmlist");
				}
			}
		} except(EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint(("Exception occured in UnloadDriver\n"));
		}

		Irp->IoStatus.Status = status;
		if (NT_SUCCESS(status)) {
			Irp->IoStatus.Information = (char *)buf - (char *)rcd;
		} else {
			Irp->IoStatus.Information = 0;
		}
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		//return STATUS_SUCCESS;
		status = STATUS_SUCCESS;
              goto nExit;

	case IO_QUERY_PROCESS_LIST:
	case IO_QUERY_SERVICE_LIST:
		// Dump hash to log and report caller about file name
		try {
			if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL){
				status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
					irpStack->Parameters.DeviceIoControl.Type3InputBuffer);

				if (!NT_SUCCESS(status)) {
					DbgPrint("Copy Error in IO_QUERY_PROCESS/SERVICE_LIST code : %x\n", status);
					break;
				}
				vmIdStr = IOInputBuffer; /*command format: vmid */

				rcd = (int*) Irp->UserBuffer;
				if (FvmVm_FindPVM(&vmn, vmIdStr) == 0) {
					IOInputBuffer[0] = L'\0';
					_length = _MAX_PATH*2;
					FvmUtil_FindProcessStrSID(IOInputBuffer, &_length);

					/* Security check */
					if (wcscmp(IOInputBuffer, pvms[vmn]->SidStr) != 0) {
						rcd[0] =  -1;
						break;
					}

					j = 1;
					for (i = 0; i < MAX_TBL_ENTRIES; i++) {
						for (pte=FVM_pvm_pid_tbl[i]; pte; pte=pte->next) {
							if (pte->pvm_id == vmn) {
								//DbgPrint("pid: %d\n", pte->pid);
								rcd[j] = pte->pid;
								if (rcd[0] == -1) {
								   rcd[0] = 1;
								} else {
								   rcd[0]++;
								}
								j++;
							}
						}
					}
				}
			}
		} except(EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint(("Exception occured in UnloadDriver\n"));
		}
		break;

	case IO_QUERY_SIDE_EFFECT_LIST:
	case IO_QUERY_DELETED_FILE_LIST:
	case IO_QUERY_DELETED_REG_LIST:
	case IO_QUERY_DELETED_OBJ_LIST:
	  // Dump hash to log and report caller about file name

		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
			status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
			    irpStack->Parameters.DeviceIoControl.Type3InputBuffer);

			if (!NT_SUCCESS(status)) {
				DbgPrint("Copy Error in IO_QUERY_SIDE/DELETED_LIST code : %x\n", status);
				break;
			}

			vmIdStr = IOInputBuffer; /*command format: vmid */

			if (FvmVm_FindPVM(&vmn, vmIdStr) == 0) {
				FvmTable_DumpVMDeleteLog(vmn, 0);
			}

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = 0; // sizeof(WCHAR)*wcslen(buf);
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			//return status;
			goto nExit;
		}
		break;

	case IO_CREATE_VM:
		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
			WCHAR *vmIpStr;
			WCHAR *vmContextStr;
			WCHAR *ddofsIp = NULL;
			WCHAR *ddofsDns = NULL;
			WCHAR *ddofsNetbiosName = NULL;
			WCHAR *ddofsDrive = NULL;
			WCHAR *encryptHandle = NULL;
			WCHAR *encryptKey = NULL;
			WCHAR *DPclientPidStr = NULL;
		
			status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
				irpStack->Parameters.DeviceIoControl.Type3InputBuffer);

			if (!NT_SUCCESS(status)) {
				DbgPrint("Copy Error in IO_CREATE_VM code : %x\n", status);
				break;
			}

			vmName = IOInputBuffer; /*command format: name?vmid?rootdir?pid*/
			buf = wcschr(vmName,L'?');

			//didn't find ':' in passed argument
			if (buf == NULL) {
				break;
			}
	 

			*buf = L'\0';
			buf++;
			vmIdStr = buf;

			buf = wcschr(buf, L'?');
			
	 
			if (buf == NULL) {
				break;
			}
			*buf = L'\0';
			buf++;
			vmRoot = buf;

			buf = wcschr(buf, L'?');
		 
			if (buf == NULL) {
				break;
			}
			*buf = L'\0';
			buf++;
			DPclientPidStr = buf;

			buf = wcschr(buf, L'?');
		 
			if (buf == NULL) {
				break;
			}
			*buf = L'\0';
			buf++;
			vmPidStr = buf;

			buf = wcschr(buf, L'?');
		 
			if (buf == NULL) {
				break;
			}
			*buf = L'\0';

			//ip address string
			buf++;
			vmIpStr = buf;
			buf = wcschr(buf, L'?');
			 
			if (buf == NULL) {
				break;
			}
			*buf = L'\0';

			//ip address string
			buf++;
			vmContextStr = buf;
			buf = wcschr(buf, L'?');
			 
			if (buf != NULL) {
			
			*buf = L'\0';

			buf++;

			if (*buf != L'\0'){
				//DDOFS server ip address
				ddofsIp = buf;
				buf = wcschr(buf, L'?');
				if (buf == NULL)
					ddofsIp = NULL;
				*buf = L'\0';
			
				//DDOFS server dns name
				buf++;
				if (*buf == L'?'){
					ddofsDns = NULL;
				}
				else {
					ddofsDns = buf;
					buf = wcschr(buf, L'?');
					if (buf == NULL)
						ddofsDns = NULL;
					*buf = L'\0';
				}
				
				buf++;
				if (buf[0] == L'?'){
					ddofsNetbiosName= NULL;
				}
				else {
					ddofsNetbiosName= buf;
					buf = wcschr(buf, L'?');
					if (buf == NULL)
						ddofsNetbiosName= NULL;
					*buf = L'\0';
				}
				buf++;
				if (buf[0] == L'?'){
					ddofsDrive= NULL;
				}
				else {
					ddofsDrive = buf;
					buf = wcschr(buf, L'?');
					if (buf == NULL)
						ddofsDrive= NULL;
					*buf = L'\0';
				}

				
				buf++;
				if (buf[0] == L'?'){
					encryptHandle = NULL;
				}
				else {
					encryptHandle = buf;
					buf = wcschr(buf, L'?');
					if (buf == NULL)
						encryptHandle = NULL;
					*buf = L'\0';
				}

				buf++;
				if (buf[0] == L'?'){
					encryptKey= NULL;
				}
				else {
					encryptKey = buf;
					buf = wcschr(buf, L'?');
					if (buf == NULL)
						encryptKey = NULL;
					*buf = L'\0';
				}
				
			}
				}

			RtlStringCbPrintfA(buf2, sizeof(buf2), "%S", vmIpStr);
			vmIp = atoi(buf2);

			RtlStringCbPrintfA(buf2, sizeof(buf2), "%S", vmContextStr);
			vmContext = atoi(buf2);

			RtlStringCbPrintfA(buf2, sizeof(buf2), "%S", vmPidStr);
			pid = atoi(buf2);

			RtlStringCbPrintfA(buf2, sizeof(buf2), "%S", DPclientPidStr);
			DPclientPid = atoi(buf2);
			
			DbgPrint("Create VM %S pid: %d\n", vmName, pid);
			DbgPrint(
			   "name: %S id: %S root: %S DPclientPid : %d pid: %d, vmIp: %u vmContext %u ddofsIP: %S ddofsDNS: %S ddofsNetbios: %S ddofsDriver %S handle: %S key: %S\n",
			    vmName, vmIdStr, vmRoot, DPclientPid, pid, vmIp, vmContext, ddofsIp, ddofsDns, ddofsNetbiosName, ddofsDrive, encryptHandle, encryptKey);
			    

			rcode = FvmVm_CreatePVM(&vmn, vmName, vmIdStr, vmRoot, vmIp, vmContext, ddofsIp, ddofsDns, ddofsNetbiosName, ddofsDrive, encryptHandle, encryptKey);
			
			IOInputBuffer[0] = L'\0';
			_length = _MAX_PATH*2;
			FvmUtil_FindProcessStrSID(IOInputBuffer, &_length);
			RtlStringCbCopyW(pvms[vmn]->SidStr, 
				sizeof(pvms[vmn]->SidStr), 
				IOInputBuffer);
			
			if (pid != 0) {
#ifdef RPCSS				
				FvmVm_AddPid(pid,vmn,-1);
#else
				FvmVm_AddPid(pid,vmn);
#endif
			}

			rcd = (int*) Irp->UserBuffer;
			*rcd = rcode;

			// Store the DPClient PId, the FVM ID pair
			if (rcode == CREATE_VM_SUCCESS) {
				
				
				
				addDPClientPID(DPclientPid, vmn);
				printDPClientPID();
			}
			
		} else {
			DbgPrint("irpStack->Parameters.DeviceIoControl.Type3InputBuffer "
			    "is NULL in create\n");
		}
		break;
		
		case IO_VM_RUNNING:
				if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
					rcode = 0;
					status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
								irpStack->Parameters.DeviceIoControl.Type3InputBuffer);

					if (!NT_SUCCESS(status)) {
						DbgPrint("Copy Error in IO_VM_RUNNING code : %x\n", status);
						break;
					}
		
					for (pvm_index = 0; pvm_index < MAX_NUM_PVMS; pvm_index ++) {
						if (pvms[pvm_index] != NULL){
							if (_wcsicmp(pvms[pvm_index]->idStr, IOInputBuffer)==0){
								rcode = 1;
							}
						}
					}
		
					DbgPrint("is %S running: %d", IOInputBuffer, rcode);
					rcd = (int*) Irp->UserBuffer;
					*rcd = rcode;
				}
				break;

	case IO_ASSOCIATE_VM:
		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
			status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
			    irpStack->Parameters.DeviceIoControl.Type3InputBuffer);

			if (!NT_SUCCESS(status)) {
				DbgPrint("Copy Error in IO_ASSOCIATE_VM code : %x\n", status);
				break;
			}

			vmIdStr = IOInputBuffer; /*command format: vmid?pid?*/
			buf = wcschr(vmIdStr, L'?');

			//didn't find '?' in passed argument
			if (buf == NULL) {
				break;
			}

			*buf = L'\0';
			buf++;
			vmPidStr = buf;

			buf = wcschr(buf, L'?');
			if (buf == NULL) {
				break;
			}
			*buf = L'\0';

			RtlStringCbPrintfA(buf2, sizeof(buf2), "%S", vmPidStr);
			pid = atoi(buf2);

			if (FvmVm_FindPVM(&vmn, vmIdStr) == 0) {
#ifdef RPCSS				
				FvmVm_AddPid(pid, vmn,-1);
#else
				FvmVm_AddPid(pid, vmn);
#endif
			}
		}
		break;

	case IO_ASSOCIATE_VM_BYID:
		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
			status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
					irpStack->Parameters.DeviceIoControl.Type3InputBuffer);

			if (!NT_SUCCESS(status)) {
				DbgPrint("Copy Error in IO_ASSOCIATE_VM_BYID code : %x\n", status);
				break;
			}
            DbgPrint("IO_ASSOCIATE_VM_BYID IOInputBuffer %S\n",IOInputBuffer);
                     
			vmIdStr = IOInputBuffer; /*command format: vmid?pid?*/
			buf = wcschr(vmIdStr, L'?');

			//didn't find '?' in passed argument
			if (buf == NULL) {
				break;
			}

			*buf = L'\0';
			buf++;
			vmPidStr = buf;

			buf = wcschr(buf, L'?');
			if (buf == NULL) {
				break;
			}
			*buf = L'\0';

			RtlStringCbPrintfA(buf2, sizeof(buf2), "%S", vmPidStr);
			pid = atoi(buf2);
            RtlStringCbPrintfA(buf2, sizeof(buf2), "%S", vmIdStr);
			vmn = atoi(buf2);

                     DbgPrint("IO_ASSOCIATE_VM_BYID %d %d\n",pid,vmn);
#ifdef RPCSS				
				FvmVm_AddPid(pid, vmn,-1);
#else
				FvmVm_AddPid(pid, vmn);
#endif
		}
		break;


	case IO_RESUME_VM:  /* means to add a fvmshell to a running vm */
		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
			status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
					irpStack->Parameters.DeviceIoControl.Type3InputBuffer);

			if (!NT_SUCCESS(status)) {
				DbgPrint("Copy Error in IO_RESUME_VM code : %x\n", status);
				break;
			}

			vmIdStr = IOInputBuffer; /*command format: vmid?pid */
			buf = wcschr(vmIdStr,L'?');

			if (buf == NULL) {
				break;
			}

			*buf = L'\0';
			buf++;
			vmPidStr = buf;

			RtlStringCbPrintfA(buf2, sizeof(buf2), "%S", vmPidStr);
			pid = atoi(buf2);
			DbgPrint("resumming VM %S pid: %d\n", vmPidStr, pid);

			rcd = (int*) Irp->UserBuffer;
			if (FvmVm_FindPVM(&vmn, vmIdStr) == 0) {
#ifdef RPCSS				
				FvmVm_AddPid(pid,vmn,-1);
#else
				FvmVm_AddPid(pid,vmn);
#endif
				*rcd = ADD_SHELL_SUCCESS;
			} else {
				*rcd = ADD_SHELL_VMNOTFD;
				DbgPrint("%S vm is not found.\n", vmPidStr);
			}
		} else {
			DbgPrint("irpStack->Parameters.DeviceIoControl.Type3InputBuffer "
			    "is NULL in create\n");
		}
		break;

	case IO_TERMINATE_VM:
		try {
			if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL){
				status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
					irpStack->Parameters.DeviceIoControl.Type3InputBuffer);

				if (!NT_SUCCESS(status)) {
					DbgPrint("Copy Error in IO_TERMINATE_VM code : %x\n", status);
					break;
				}
				vmIdStr = IOInputBuffer; /*command format: vmid */

				rcd = (int*) Irp->UserBuffer;
				if (FvmVm_FindPVM(&vmn, vmIdStr) == 0) {
					IOInputBuffer[0] = L'\0';
					_length = _MAX_PATH*2;
					FvmUtil_FindProcessStrSID(IOInputBuffer, &_length);

					/* security check */
					if (wcscmp(IOInputBuffer, pvms[vmn]->SidStr) != 0) {
						*rcd =  TERMINATE_VM_PERDENY;
						break;
					}

					for (i = 0; i < MAX_TBL_ENTRIES; i++) {
						for (pte=FVM_pvm_pid_tbl[i]; pte; pte=pte->next) {
							if (pte->pvm_id == vmn) {
							*rcd = TERMINATE_VM_PROCESS;
							break;
							}
						}
					}

					if (*rcd == TERMINATE_VM_PROCESS)
						break;

					if (pvms[vmn]->handle||1)
						FVM_removeNDISKey(vmn);
					
					DbgPrint("Terminate VM %d\n", vmn);
					FvmTable_DumpVMDeleteLog(vmn, 1); //lclam

					FvmTable_DeleteLogCleanup(vmn);
					FvmTable_HandleTableCleanup(vmn);

#ifdef USE_FS_MAP
					FvmTable_FVMFileListCleanup(vmn);
#endif

					FvmVm_DestroyPVM(vmn);
					*rcd =  TERMINATE_VM_SUCCESS;
				} else {
					*rcd = TERMINATE_VM_NOTFUND;
					DbgPrint("%S vm is not found.\n", vmIdStr);
				}
			}
		} except(EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint(("Exception occured in UnloadDriver\n"));
		}
		break;

	case IO_STATUS_VM:
		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {

			status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
					irpStack->Parameters.DeviceIoControl.Type3InputBuffer);
			if (!NT_SUCCESS(status)) {
				DbgPrint("Copy Error in IO_STATUS_VM code : %x\n", status);
				break;
			}
			
			vmIdStr = IOInputBuffer; /*command format: vmid?status */
			buf = wcschr(vmIdStr, L'?');

			if (buf == NULL) {
				break;
			}

			*buf = L'\0';
			buf++;

		RtlStringCbPrintfA(buf2, sizeof(buf2), "%S", buf);
			j = atoi(buf2);
                     if(j>=2) {j=1;} //check status if unknow set as stopped

			for (i=0; i<MAX_NUM_PVMS; i++) {
				if (pvms[i] != NULL) {
				   if (wcscmp(pvms[i]->idStr, vmIdStr) == 0) {
				      pvms[i]->status = j;
				      break;
				   }
				}
			}
		}
		break;

	case IO_QUERY_IS_SAME_VM:
		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
			FVM_PDDEProcessIDInfo PtrDDEInfo;
			ULONG clientVMid, serverVMid;
			BOOLEAN IsSameVM = FALSE;
			BOOLEAN ClientVM = TRUE, ServerVM = TRUE;
			BOOLEAN *pbool;

			PtrDDEInfo = (FVM_PDDEProcessIDInfo)
						     (irpStack->Parameters.DeviceIoControl.Type3InputBuffer);

			clientVMid = FvmVm_GetPVMId(PtrDDEInfo->client_pid);
			serverVMid = FvmVm_GetPVMId(PtrDDEInfo->server_pid);

			if (clientVMid == -1 || clientVMid == INVALID_VMID)
				ClientVM = FALSE;
			if (serverVMid == -1 || serverVMid == INVALID_VMID)
				ServerVM = FALSE;

			if ((!ClientVM) && (!ServerVM)) {
				IsSameVM = TRUE;
			} else if (ClientVM && ServerVM && clientVMid == serverVMid) {
				IsSameVM = TRUE;
			}

			pbool= (BOOLEAN *) Irp->UserBuffer;
			if (!pbool) {
				DbgPrint("Invalid User Buffer\n");
				break;
			}
			*pbool = IsSameVM;

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof(BOOLEAN);
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			//return status;
			goto nExit;
		}
		break;

	case IO_QUERY_VM_ID:
		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
			PULONG ppid;
#ifdef RPCSS
//			WCHAR binpath[_MAX_PATH*2];
                     PWCHAR binpath = NULL;
			int comServerType=0;
#endif
			ppid = (PULONG)
				       (irpStack->Parameters.DeviceIoControl.Type3InputBuffer);
#ifdef RPCSS
#if 0
                     binpath = ExAllocateFromPagedLookasideList( &FileFullPathLookaside );
                     ASSERT(binpath);
			FvmUtil_GetBinaryPathName(binpath);
		//	DbgPrint("QueryVmId: try to add process %d %S into vm\n", PsGetCurrentProcessId(),binpath); 					
			vmid = FvmVm_GetPVMIdByComServerPath(binpath,&comServerType);
                     ExFreeToPagedLookasideList( &FileFullPathLookaside, binpath );
			if(vmid!=-1)
				FvmVm_AddPid((ULONG)PsGetCurrentProcessId(),vmid,comServerType); 		
			/*	if(wcscmp(binpath,)){ 
					char szANSIString [10];
					WCHAR *chr = wcsstr(binpath,L"\\FVM");
					WCHAR *vmChr = wcsstr(chr,L"-");
					if(!vmChr)
						break;
					*vmChr = L'\0';
					sprintf(szANSIString,"%S",chr);
					FvmVm_AddPid((ULONG)PsGetCurrentProcessId(),(ULONG)atoi(szANSIString),TRUE);
					DbgPrint("%d process %S is added to vmid=%s, vmid=%d\n", PsGetCurrentProcessId(),binpath,szANSIString,atoi(szANSIString));			
				}*/
			else{
		//		if(wcsstr(binpath,L"AdskScSrv"))
			//		FvmVm_AddPid((ULONG)PsGetCurrentProcessId(),0,1);
				vmid = FvmVm_GetPVMId(*ppid);
				
			}
#endif
		vmid = FvmVm_GetPVMId(*ppid);
#endif

#ifndef RPCSS
			vmid = FvmVm_GetPVMId(*ppid);
#endif

			pvmid = (PULONG) Irp->UserBuffer;
			if (!pvmid) {
				DbgPrint("Invalid User Buffer\n");
				break;
			}
			*pvmid = vmid;

			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = sizeof(ULONG);
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			//return status;
			goto nExit;
		}
		break;

	case IO_QUERY_VM_IP:
		pid = (ULONG)PsGetCurrentProcessId();
		vmid = FvmVm_GetPVMId(pid);
		if (vmid == INVALID_VMID) {
			vmIp = INVALID_VMID;
		} else {
			vmIp = pvms[vmid]->pvm_vmIp;
		}
		pvmid = (PULONG) Irp->UserBuffer;
		if (!pvmid) {
			DbgPrint("Invalid User Buffer\n");
			break;
		}
		*pvmid = vmIp;

		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(ULONG);
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		//return status;
		goto nExit;

	case IO_QUERY_VM_IP_CONTEXT:
		if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {

			status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
					irpStack->Parameters.DeviceIoControl.Type3InputBuffer);
			if (!NT_SUCCESS(status)) {
				DbgPrint("Copy Error in IO_QUERY_VM_IP_CONTEXT code : %x\n", status);
				break;
			}
			vmIdStr = IOInputBuffer;
			if (FvmVm_FindPVM(&vmid, vmIdStr) == 0) {
				vmContext = pvms[vmid]->pvm_vmContext;

				pvmid = (PULONG) Irp->UserBuffer;
				if (!pvmid) {
					DbgPrint("Invalid User Buffer\n");
					break;
				}
				*pvmid = vmContext;

				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = sizeof(ULONG);
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				//return status;
				goto nExit;
			}
		}
		break;
		
		case IO_CREATE_CLSID_KEY:	//for COM virtualization
				if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
				//char para[500];
				WCHAR* buf;
				WCHAR* newClsid,*newProgId,*oldClsid,*oldProgId,*newTypeLibId;
				
				status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
					irpStack->Parameters.DeviceIoControl.Type3InputBuffer);
				if (!NT_SUCCESS(status)) {
					DbgPrint("Copy Error in IO_CREATE_CLSID_KEY code : %x\n", status);
					break;
				}
				
				DbgPrint("get IO_CREATE_CLSID_KEY command, para=%S\n",IOInputBuffer);
				/*para format: newClsid?newProgId?oldClsid?oldProgId */ 					
				newClsid = IOInputBuffer;
				buf = wcschr(newClsid,L'?');
				if (buf == NULL) {
					break;
				}
				*buf = L'\0';
		
				newProgId = buf+1;
				buf = wcschr(newProgId,L'?');
				if (buf == NULL) {
					break;
				}
				*buf = L'\0';
		
				oldClsid= buf+1;
				buf = wcschr(oldClsid,L'?');
				if (buf == NULL) {
					break;
				}
				*buf = L'\0';
		
				oldProgId= buf+1;
				buf = wcschr(oldProgId,L'?');
				if (buf == NULL) {
					break;
				}
				*buf = L'\0';
		
				/*newTypeLibId= buf+1;
				buf = wcschr(newTypeLibId,L'?');
				if (buf == NULL) {
					break;
				}
				*buf = L'\0';*/
		
				DbgPrint("createClsidKey: newclsid=%S, newprogid=%S, oldclsid=%S, oldprogid=%S\n",newClsid,newProgId,oldClsid,oldProgId);
		
				FvmVm_SaveClsid((ULONG)PsGetCurrentProcessId(),oldClsid,newClsid,oldProgId,newProgId);
		
				rcd = (int*) Irp->UserBuffer;
		
				*rcd = 0;
			
			//	*rcd = CreateClsidKey(newClsid,newProgId,newClsidKey,oldClsid,oldProgId,oldClsidKey);
		
		//	*rcd = CreateClsidKey(newClsid,newProgId,newClsidKey,oldClsid,oldProgId,oldClsidKey);

			
		} else {
			DbgPrint("irpStack->Parameters.DeviceIoControl.Type3InputBuffer "
				"is NULL in create\n");
		}
		break;
		
		case IO_CREATE_APPID_KEY:	//for COM virtualization
			if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
				WCHAR* buf;
				WCHAR* newAppId,*newAppName;
				
				status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
					irpStack->Parameters.DeviceIoControl.Type3InputBuffer);
				if (!NT_SUCCESS(status)) {
					DbgPrint("Copy Error in IO_CREATE_APPID_KEY code : %x\n", status);
					break;
				}
				DbgPrint("get IO_CREATE_APPID_KEY command, para=%s\n",IOInputBuffer);
				/*para format: newAppId?newAppName */					
				newAppId = IOInputBuffer;
				buf = wcschr(newAppId,L'?');
				if (buf == NULL) {
					break;
				}
				*buf = L'\0';
		
				newAppName = buf+1;
				buf = wcschr(newAppName,L'?');
				if (buf == NULL) {
					break;
				}
				*buf = L'\0';			
		
				//DbgPrint("createAppIdKey: %S, %S\n",newAppId,newAppName);
		
				FvmVm_SaveAppId((ULONG)PsGetCurrentProcessId(),newAppId,newAppName);
		
				rcd = (int*) Irp->UserBuffer;	
				*rcd = 0;
				
			} else {
				DbgPrint("irpStack->Parameters.DeviceIoControl.Type3InputBuffer "
					"is NULL in create\n");
			}
			break;
			
			case IO_ADD_COM_SERVER: //for COM virtualization
				if (irpStack->Parameters.DeviceIoControl.Type3InputBuffer != NULL) {
					WCHAR* buf;
					WCHAR* comServerPath,*type;
					char typeChr[5];
					
					status = RtlStringCbCopyW(IOInputBuffer, sizeof(WCHAR)* 1024, 
						irpStack->Parameters.DeviceIoControl.Type3InputBuffer);
					if (!NT_SUCCESS(status)) {
						DbgPrint("Copy Error in IO_ADD_COM_SERVER code : %x\n", status);
						break;
					}
					DbgPrint("get IO_ADD_COM_SERVER command, para=%S\n",IOInputBuffer);
					/*para format: newAppName */					
					comServerPath = IOInputBuffer;
					buf = wcschr(comServerPath,L'?');
					if (buf == NULL) {
						break;
					}
					*buf = L'\0';		
			DbgPrint("before FvmVm_SaveComServerPath, comServer=%S\n",comServerPath);					
					type= buf+1;					
					buf = wcschr(type,L'?');
					if (buf == NULL) {
						break;
					}
					*buf = L'\0';	

					status = RtlStringCbPrintfA(typeChr, sizeof(typeChr), "%S", type);
					if (!NT_SUCCESS(status)) {
						DbgPrint("sprintf Error in  IO_ADD_COM_SERVER code : %x\n", status);
						break;
					}
					
					FvmVm_SaveComServerPath((ULONG)PsGetCurrentProcessId(),comServerPath,atoi(typeChr));
			DbgPrint("after FvmVm_SaveComServerPath, comServer=%S, type=%d\n",comServerPath,atoi(typeChr));
					rcd = (int*) Irp->UserBuffer;	
					*rcd = 0;
					
				} else {
					DbgPrint("irpStack->Parameters.DeviceIoControl.Type3InputBuffer "
						"is NULL in create\n");
				}
				break;
		
		

	default:
		DbgPrint("Default\n");
		break;
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
nExit:    
       if (IOInputBuffer) {
              ExFreeToPagedLookasideList( &WC1kLookaside, IOInputBuffer );
	} 
	return status;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status;
	WCHAR  deviceLinkBuffer[] = L"\\DosDevices\\rnifvmdr";
	UNICODE_STRING  deviceLinkUnicodeString;
	UINT  i;
	LARGE_INTEGER  liDelay;
	UNICODE_STRING  UnicodeFilespec;
	OBJECT_ATTRIBUTES  objectAttributes;
	HANDLE  fileHandle;
	WCHAR  buf[256];
	IO_STATUS_BLOCK  iostatus;
	int  memsize = 0;
	int  retry = 0;
	struct FVM_new_process_t *pr1, *pr2;
	
	try {
		FvmTable_WriteVMStatusFile();

		DbgPrint("Unloading the driver... %d\n", fvm_Calls_In_Progress);
		while (fvm_Calls_In_Progress) {
			/* refuse to unload.  Will BSOD otherwise */
			liDelay.QuadPart = -1000000;
			KeDelayExecutionThread (KernelMode, FALSE, &liDelay);
			DbgPrint("Unload Driver: %d Calls in Progress = %d\n",
			    retry, fvm_Calls_In_Progress);
			retry ++;
		}

#if 1
		FVM_UnHookServices();
#endif

		for (i=0; i<MAX_TBL_ENTRIES; i++) {
			PFVM_PVM_TBL_ENTRY pte1, pte2;
			if (FVM_pvm_pid_tbl[i] != NULL){
				pte1 = FVM_pvm_pid_tbl[i];
				while(pte1) {
					pte2 = pte1;
					pte1 = pte1->next;
					ExFreePool(pte2);
				}
			}
		}

		for (i=0; i<MAX_NUM_PVMS; i++) {
			if(pvms[i] != NULL){
				if (FVM_ObjectDirectoryHandle[i]) {
					ZwClose(FVM_ObjectDirectoryHandle[i]);
					FVM_ObjectDirectoryHandle[i] = NULL;
				}

				if (FVM_PortDirectoryHandle[i]) {
					ZwClose(FVM_PortDirectoryHandle[i]);
					FVM_PortDirectoryHandle[i] = NULL;
				}
				ExFreePool(pvms[i]);
				pvms[i] = NULL;
			}
		}

		pr1 = FVM_new_processes;
		while(pr1){
			pr2 = pr1;
			pr1 = pr1->next;

			if(pr2->imageName) {
				ExFreePool(pr2->imageName);
			}
			ExFreePool(pr2);
		}
		FVM_new_processes = NULL;

		for ( i = 0; i < MAX_VM; i++ ) {
			FvmTable_DeleteLogCleanup(i);
			FvmTable_HandleTableCleanup(i);

#ifdef USE_FS_MAP
			FvmTable_FVMFileListCleanup(i);
#endif
			if (FVM_ObjectDirectoryHandle[i])
				ZwClose(FVM_ObjectDirectoryHandle[i]);
			if (FVM_PortDirectoryHandle[i])
				ZwClose(FVM_PortDirectoryHandle[i]);
		}

		if(fvm_DeleteState) {
			ExFreePool(fvm_DeleteState);
		}

		if(fvm_HandleTable) {
			ExFreePool(fvm_HandleTable);
		}
#ifdef USE_FS_MAP
		if (fvm_FileList) {
			ExFreePool(fvm_FileList);
		}
#endif
		if (gpEventObject) {
			ObDereferenceObject(gpEventObject);
		}

		ExDeleteResourceLite(&FVM_newProcessResource);
		ExDeleteResourceLite(&FVM_processVMRes);
		ExDeleteResourceLite(&fvm_DeleteLogResource);
		ExDeleteResourceLite(&fvm_HandleTableResource);

#ifdef USE_FS_MAP
		ExDeleteResourceLite(&fvm_FSResource);
#endif
              ExDeletePagedLookasideList( &FileFullPathLookaside );
              ExDeletePagedLookasideList( &FilebufLookaside );
              ExDeletePagedLookasideList( &WC1kLookaside );
              ExDeletePagedLookasideList( &WC512Lookaside );
              ExDeletePagedLookasideList( &WC256Lookaside );
              ExDeletePagedLookasideList( &C1kLookaside );
		RtlInitUnicodeString (&deviceLinkUnicodeString, deviceLinkBuffer);

		IoDeleteSymbolicLink (&deviceLinkUnicodeString);
		IoDeleteDevice (DriverObject->DeviceObject);

		DbgPrint("Driver Unloaded\n");
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in UnloadDriver\n"));
	}
}


static int
get_installerpid() {

	ULONG cbBuffer = 0x8000; // declare initial size of buffer - 32kb
	PULONG  pBuffer = NULL; // declare pointer to a buffer
	NTSTATUS Status;
	PSYSTEM_PROCESS_INFORMATION pInfo;
	LPWSTR pszProcessName;
	ULONG ppid;

	do
	{
		pBuffer = ExAllocatePoolWithTag (NonPagedPool, cbBuffer,
			FVM_HOOKSYS_POOL_TAG);
			//allocate memory for the buffer of size cbBuffer
		if (pBuffer == NULL) 
			// if memory allocation failed, exit
		{
			return 1;
		}
		// try to obtain system information into the buffer
		Status = ZwQuerySystemInformation(
				SystemProcessesAndThreadsInformation, pBuffer,
				    cbBuffer, NULL);
		// if the size of the information is larger than the size of the buffer
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(pBuffer); // free the memory associated with the buffer 
			cbBuffer *= 2; // and increase buffer size twice its original size
		}
		else if (!NT_SUCCESS(Status)) // if operation is not succeeded by any other reason
		{
			ExFreePool(pBuffer); // free the memory
			return 1; //and exit
		}
	}
	while (Status == STATUS_INFO_LENGTH_MISMATCH); 

	pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
	for (;;) {
		LPWSTR pszProcessName = pInfo->ProcessName.Buffer;
		if ((pszProcessName != NULL) && (wcscmp(pszProcessName,
			L"SERVICES.EXE") == 0)) {
			//gPrint("pszProcessName = %S %ld %ld\n", pszProcessName,
			//  pInfo->ProcessId, pInfo->InheritedFromProcessId);
			ppid = pInfo->ProcessId;
		}
		

		if (pInfo->NextEntryDelta == 0)		
			break;
		pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) +
			pInfo->NextEntryDelta);
	}

	pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
	for (;;) {
		LPWSTR pszProcessName = pInfo->ProcessName.Buffer;
		if ((pszProcessName != NULL) && (wcscmp(pszProcessName,
			L"msiexec.exe") == 0) && (pInfo->InheritedFromProcessId == ppid)) {
			DbgPrint("pszProcessName = %S %ld %ld\n", pszProcessName,
			    pInfo->ProcessId, pInfo->InheritedFromProcessId);
			service_pid = pInfo->ProcessId;
		}
		

		if (pInfo->NextEntryDelta == 0)		
			break;
		pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) +
			pInfo->NextEntryDelta);
	}
	return 0;
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS  ntStatus;
	PDEVICE_OBJECT  deviceObject = NULL;
	WCHAR  deviceNameBuffer[] = L"\\Device\\rnifvmdr";
	UNICODE_STRING  deviceNameUnicodeString;
	WCHAR  deviceLinkBuffer[]  = L"\\DosDevices\\rnifvmdr";
	UNICODE_STRING  deviceLinkUnicodeString;
	UINT i, j;
	UINT idx;
	ULONG tmp_len = 256;
	

	/* Set the syscall nos. depending on the Windows version we are running on.
	  * Right now the versions supported are Windows 2000 and XP.
	  */
	if ((IoIsWdmVersionAvailable(1, 0x10)) &&
		(!IoIsWdmVersionAvailable(1, 0x20))) {
		 /* Windows 2000 */
		 ID_NTREADVIRTUALMEMORY = 0xa4;
		 ID_ZWQUERYINFORMATIONTHREADAD = 0x87L;
		 ID_ZWRESUMETHREADAD = 0xb5L;
		 ID_ZWCREATETHREADA = 0x2eL;
		 ID_NTQUERYATTRIBUTESFILE = 0x7a;
		 ID_NTQUERYFULLATTRIBUTESFILE = 0x81;
		 ID_NTCREATENAMEDPIPEFILE = 0x26;
		 ID_NTCREATEMAILSLOTFILE = 0x24;
		 ID_NTCREATEMUTANT = 0x25;
		 ID_NTOPENPROCESS = 0x006a;
		 ID_NTOPENMUTANT = 0x68;
		 ID_NTCREATESEMAPHORE = 0x2c;
		 ID_NTOPENSEMAPHORE = 0x6d;
		 ID_NTCREATETIMER = 0x2f;
		 ID_NTOPENTIMER = 0x71;
		 ID_NTCREATEIOCOMPLETION = 0x21;
		 ID_NTOPENIOCOMPLETION = 0x65;
		 ID_NTCREATEEVENTPAIR = 0x1f;
		 ID_NTOPENEVENTPAIR = 0x63;
		 ID_NTCREATEPORT = 0x28;
		 ID_NTCREATEWAITABLEPORT = 0x31;
		 ID_NTSECURECONNECTPORT = 0xb8;
		 ID_NTSETVALUEKEY = 0xd7;
	
	} else if ((IoIsWdmVersionAvailable(1, 0x20)) &&
		  (!IoIsWdmVersionAvailable(1, 0x30))) {
		 /* Windows XP */		 
		 ID_NTREADVIRTUALMEMORY = 0xba;
		 ID_ZWQUERYINFORMATIONTHREADAD = 0x9bL;
		 ID_ZWRESUMETHREADAD = 0xceL;
		 ID_ZWCREATETHREADA = 0x35L;
		 ID_NTQUERYATTRIBUTESFILE = 0x8b;
		 ID_NTQUERYFULLATTRIBUTESFILE = 0x95;
		 ID_NTCREATENAMEDPIPEFILE = 0x2c;
		 ID_NTCREATEMAILSLOTFILE = 0x2a;
		 ID_NTCREATEMUTANT = 0x2b;
		 ID_NTOPENPROCESS = 0x007a;
		 ID_NTOPENMUTANT = 0x78;
		 ID_NTCREATESEMAPHORE = 0x33;
		 ID_NTOPENSEMAPHORE = 0x7e;
		 ID_NTCREATETIMER = 0x36;
		 ID_NTOPENTIMER = 0x83;
		 ID_NTCREATEIOCOMPLETION = 0x26;
		 ID_NTOPENIOCOMPLETION = 0x75;
		 ID_NTCREATEEVENTPAIR = 0x24;
		 ID_NTOPENEVENTPAIR = 0x73;
		 ID_NTCREATEPORT = 0x2e;
		 ID_NTCREATEWAITABLEPORT = 0x38;
		 ID_NTSECURECONNECTPORT = 0xd2;
		 ID_NTSETVALUEKEY = 0xf7;
	
	}

	try {
		RtlInitUnicodeString (&deviceNameUnicodeString, deviceNameBuffer);
		ntStatus = IoCreateDevice (DriverObject, 0, &deviceNameUnicodeString,
				       FILE_DEVICE_HOOKSYS, 0, FALSE, &deviceObject);

		if (!NT_SUCCESS(ntStatus)) {
			DbgPrint("Unable To Create Device\n");
			return ntStatus;
		}

		RtlInitUnicodeString (&deviceLinkUnicodeString, deviceLinkBuffer);
		ntStatus = IoCreateSymbolicLink (&deviceLinkUnicodeString,
				       &deviceNameUnicodeString);

		if (!NT_SUCCESS(ntStatus)) {
			IoDeleteDevice (deviceObject);
			return ntStatus;
		}

		ExInitializeResourceLite(&FVM_newProcessResource);
		ExInitializeResourceLite(&FVM_processVMRes);
		ExInitializeResourceLite(&fvm_DeleteLogResource);
		ExInitializeResourceLite(&fvm_HandleTableResource);

#ifdef USE_FS_MAP
		ExInitializeResourceLite(&fvm_FSResource);
#endif
//
// Initialize a lookaside for file names
//
             ExInitializePagedLookasideList( &FileFullPathLookaside, NULL, NULL,
                 0, _MAX_PATH*2*sizeof(WCHAR), FVM_HOOKSYS_POOL_TAG, 384 );

//DbgPrint("remove remove me _MAX_PATH:%d",_MAX_PATH*2*sizeof(WCHAR));

             ExInitializePagedLookasideList( &FilebufLookaside, NULL, NULL,
                 0, 2048*sizeof(CHAR), FVM_HOOKSYS_POOL_TAG, 32 );
             ExInitializePagedLookasideList( &WC1kLookaside, NULL, NULL,
                 0, 1024*sizeof(WCHAR), FVM_HOOKSYS_POOL_TAG, 32 );
             ExInitializePagedLookasideList( &WC512Lookaside, NULL, NULL,
                 0, 512*sizeof(WCHAR), FVM_HOOKSYS_POOL_TAG, 16 );
             ExInitializePagedLookasideList( &WC256Lookaside, NULL, NULL,
                 0, 256*sizeof(WCHAR), FVM_HOOKSYS_POOL_TAG, 16 );
             ExInitializePagedLookasideList( &C1kLookaside, NULL, NULL,
                 0, 1024*sizeof(CHAR), FVM_HOOKSYS_POOL_TAG, 8 );


		fvm_DeleteState = ExAllocatePoolWithTag(PagedPool,
		    MAX_VM*sizeof(FVM_PDeleteLogEntry), FVM_HOOKSYS_POOL_TAG);
		if (fvm_DeleteState) {
			for (i = 0; i < MAX_VM; i++ ) fvm_DeleteState[i] = NULL;
		}

		fvm_HandleTable = ExAllocatePoolWithTag( PagedPool,
            MAX_VM*sizeof(FVM_PHandleTableEntry), FVM_HOOKSYS_POOL_TAG);
		if (fvm_HandleTable) {
			for (i = 0; i < MAX_VM; i++ ) fvm_HandleTable[i] = NULL;
		}

#ifdef USE_FS_MAP
		fvm_FileList = ExAllocatePoolWithTag(PagedPool,
		    MAX_VM*sizeof(PFVM_File_Entry), FVM_HOOKSYS_POOL_TAG);
		if (fvm_FileList) {
			for (i = 0; i < MAX_VM; i++ ) fvm_FileList[i] = NULL;
		}
#endif

		for (i = 0; i < MAX_VM; i++ ) {
			FVM_ObjectDirectoryHandle[i] = NULL;
			FVM_PortDirectoryHandle[i] = NULL;
		}

		//init the pvm data structures here
		for(idx=0; idx<MAX_NUM_PVMS; idx++) {
			pvms[idx] = NULL;
		}
		n_pvms = 0;
		for(idx=0; idx<MAX_TBL_ENTRIES; idx++) {
			FVM_pvm_pid_tbl[idx] = NULL;
		}

#if 1
		ntStatus = FVM_HookServices();

		if (!NT_SUCCESS(ntStatus)) {
			DbgPrint("Unable To hook System call.\n");
			goto Error;
		}
#endif


		get_installerpid();
	//----------------------------------------------------------------------------
		GetSystemDirectory(svc_crt_prog, &tmp_len);
		wcscat(svc_crt_prog, L"\\");
		if (!NT_SUCCESS(ntStatus)) {
			DbgPrint("Unable To concatenate create program separator '\\' code: %x\n", ntStatus);
			goto Error;
		}
		wcscat(svc_crt_prog, SERVICE_CREATE_PROGRAM);
		if (!NT_SUCCESS(ntStatus)) {
			DbgPrint("Unable to concatenate create program exe name code: %x\n", ntStatus);
			goto Error;
		}
		
		GetSystemDirectory(svc_inst_prog, &tmp_len);
		wcscat(svc_inst_prog, L"\\");
		if (!NT_SUCCESS(ntStatus)) {
			DbgPrint("Unable To concatenate install program separator '\\' code: %x\n", ntStatus);
			goto Error;
		}
		wcscat(svc_inst_prog, SERVICE_INSTALLER_PROGRAM);
		if (!NT_SUCCESS(ntStatus)) {
			DbgPrint("Unable to concatenate install program exe name code: %x\n", ntStatus);
			goto Error;
		}
		
		//DbgPrint("svc_crt_prog = %S\n", svc_crt_prog);
		//DbgPrint("svc_inst_prog = %S\n", svc_inst_prog);
		//DbgPrint("inst_cli_prog = %S\n", inst_cli_prog);
	//----------------------------------------------------------------------------
		

		DriverObject->MajorFunction[IRP_MJ_CREATE] = FVM_CommDriver_Create;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = FVM_CommDriver_Close;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FVM_SysCallMonDeviceControl;
		DriverObject->DriverUnload = DriverUnload;

		return STATUS_SUCCESS;

Error:
		if (fvm_DeleteState) {
			ExFreePool(fvm_DeleteState);
		}

		if (fvm_HandleTable) {
			ExFreePool(fvm_HandleTable);
		}

#ifdef USE_FS_MAP
		if (fvm_FileList) {
			ExFreePool(fvm_FileList);
		}
#endif
		ExDeleteResourceLite(&FVM_newProcessResource);
		ExDeleteResourceLite(&FVM_processVMRes);
		ExDeleteResourceLite(&fvm_DeleteLogResource);
		ExDeleteResourceLite(&fvm_HandleTableResource);

#ifdef USE_FS_MAP
		ExDeleteResourceLite(&fvm_FSResource);
#endif
		IoDeleteSymbolicLink(&deviceLinkUnicodeString);
		IoDeleteDevice (deviceObject);

		return ntStatus;
	} except(EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint(("Exception occured in DriverEntry\n"));

		if(fvm_DeleteState) {
			ExFreePool(fvm_DeleteState);
		}
		if(fvm_HandleTable) {
			ExFreePool(fvm_HandleTable);
		}

#ifdef USE_FS_MAP
		if (fvm_FileList) {
			ExFreePool(fvm_FileList);
		}
#endif
		IoDeleteSymbolicLink(&deviceLinkUnicodeString);
		IoDeleteDevice (deviceObject);

		return STATUS_SUCCESS;
	}
}

VOID addDPClientPID(ULONG DPCpid, ULONG fvmID)
{
	PFVMID_DPCPID node = NULL;

	if (getDPClientVMID(DPCpid) != INVALID_VMID)
		return;

	// New pid, allocate storage and add the pid and FVM ID pair to the list
	node = (PFVMID_DPCPID)ExAllocatePoolWithTag(NonPagedPool, sizeof(FVMID_DPCPID), ID_TAG);
	if (node != NULL) {

		node->DPCpid = DPCpid;
		node->fvmID = fvmID;

		// Add to the head of the linked list
		node->next = DPCPidlist;
		DPCPidlist = node;

	} else {
		DbgPrint("Failed to allocate memory for new (DPC pid, fvmID) pair !\n");
		return;
	}

	return;
}

void printDPClientPID(VOID)
{
	PFVMID_DPCPID temp = DPCPidlist;

	DbgPrint("\n****** Printing the DP Client PID, FVMID pairs...\n");
	while (temp != NULL) {
		DbgPrint("PID : %lu, VMID : %lu\n", temp->DPCpid, temp->fvmID);
		temp = temp->next;
	}
	DbgPrint("****** END : DPC PID, FVMID pairs...\n\n");
}

VOID removeDPClientPID(ULONG DPCpid)
{
	PFVMID_DPCPID prev, curr;
	
	prev = curr = DPCPidlist;

	while (curr != NULL) {
		
		if (curr->DPCpid == DPCpid) {
			
			if (curr == DPCPidlist)
				DPCPidlist = curr->next;
			else
				prev->next = curr->next;

			// Free the node with the hit
			ExFreePoolWithTag(curr, ID_TAG);
			break;

		} else {
			prev = curr;
			curr = curr->next;
		}
	}
}

ULONG getDPClientVMID(ULONG DPCpid)
{
	PFVMID_DPCPID curr = DPCPidlist;
	
	while (curr != NULL) {
		if (curr->DPCpid == DPCpid)
			return curr->fvmID;
		else
			curr = curr->next;
	}

	return INVALID_VMID;
}

BOOLEAN VMexists(ULONG vmid)
{
	int i;
	PFVM_PVM_TBL_ENTRY pte;
	
	for (i = 0; i < MAX_TBL_ENTRIES; i++) {
		for (pte=FVM_pvm_pid_tbl[i]; pte; pte=pte->next) {
			if (pte->pvm_id == vmid)
				return TRUE;
		}
	}

	return FALSE;
}

