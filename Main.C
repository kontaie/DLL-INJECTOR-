#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>
#include <stdint.h>
#include <tlhelp32.h>

#define Disable_Warning(code) __pragma(warning(push)) __pragma(warning(disable : code))
#define Restore_Warnings()    __pragma(warning(pop))
#define _log_Error(msg, line) printf("\n[-]error_%s\n\t-->line: %i", msg, line)
#define log_Error(msg) _log_Error(msg, __LINE__)

#define SET_COLOR(c) SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), c)

#pragma pack(push, 1) 
typedef struct {
	DWORD size;
	HANDLE* file_handle;
	char* file_name;
} file_info;
#pragma pack(pop)

typedef struct {
	HANDLE thread_handle;
	CONTEXT* context_ptr;
} thread_info;

static void __fastcall CleanUp(file_info* File_info, PROCESSENTRY32W* process_entry, void* buffer) {
	if (File_info) {
		free(File_info);
	}

	if (process_entry) {
		free(process_entry);
	}

	if (buffer) {
		free(buffer);
	}
}

file_info* __cdecl DllReadFile(const char* file_name) {
	Disable_Warning(C6387)

	char* last_index = strchr(file_name, '\\');
	if (last_index) {
		file_name = last_index;
	}

	HANDLE file = malloc(sizeof(HANDLE));
	file = CreateFileA(file_name, GENERIC_READ, FILE_SHARE_READ && FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);

	if (file == INVALID_HANDLE_VALUE) {
		log_Error("invalid dll");
		return EXIT_FAILURE;
	}

	volatile DWORD file_size = 0;
	file_size = GetFileSize(file, NULL);

	file_info* File_info = malloc(sizeof(file_info));

	if (File_info) {
		File_info->file_handle = file;
		File_info->size = file_size;
		File_info->file_name = file_name;

		return File_info;
	}
	Restore_Warnings()
	CloseHandle(file);
	return NULL;
}

static DWORD __fastcall printBaseplate(file_info* File_info) {
	printf("+--------+--------------------+------------------+\n");
	SET_COLOR(6);
	printf("| SIZE   | FILE NAME          | POINTER          |\n");
	SET_COLOR(7);
	printf("+--------+--------------------+------------------+\n");
	SET_COLOR(4); 
	printf("| %-6d | %-18s | %-16p |\n", File_info->size, File_info->file_name, File_info->file_handle);
	SET_COLOR(7); 
	printf("+--------+--------------------+------------------+\n");

	DWORD pid = 0;
	SET_COLOR(2);
	printf("please enter process id: ");
	SET_COLOR(7);

	Disable_Warning(C6031)
		if (!scanf("%d", &pid)) { log_Error("Scanf Failed"); return; };
	Restore_Warnings()

	if (pid == 0) {
		log_Error("invalid process id");
		return NULL;
	}

	return pid;
}

PROCESSENTRY32W* __cdecl CaptureProcess(DWORD* pid) {
	HANDLE snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	if (snap_shot == INVALID_HANDLE_VALUE) { 
		log_Error("snapshot error");
		return NULL;
	};
	PROCESSENTRY32W* process_entry = malloc(sizeof(PROCESSENTRY32W));
	if (!process_entry) {
		log_Error("process entry fail");
		goto exit_fail;
	}
	process_entry->dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(snap_shot, process_entry)) {
		log_Error("process capture 1 failed");
		goto exit_fail;
	}

	do { 
		if (process_entry->th32ProcessID == *pid) {
			SET_COLOR(2);
			printf("\n#- found process: %d", process_entry->th32ParentProcessID);
			SET_COLOR(7);
			return process_entry;
		}
	} while (Process32NextW(snap_shot, process_entry));

	log_Error("couldn't find process id");
	goto exit_fail;

exit_fail:
	return NULL;
}

LPVOID __cdecl AllocateMem(PROCESSENTRY32W* process_entry, file_info* File_info, HANDLE* process_h) {
	HANDLE process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, process_entry->th32ProcessID);

	if (!process) {  
		log_Error("OpenProcess failed");
		return NULL;
	}

	void* Executable_address = VirtualAllocEx(process, NULL, File_info->size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!Executable_address) {
		log_Error("Memory allocation failed");
		CloseHandle(process);
		return NULL;
	}

	*process_h = process;
	return Executable_address;
}


BYTE* ReadDllBytes(file_info* File_Info) {
	if (!File_Info) {
		log_Error("invalid File info");
		goto exit_fail;
	}
	void* buffer = calloc(1, File_Info->size);
	if (!buffer) {
		log_Error("invalid calloc");
		goto exit_fail;
	}
	DWORD byte_read = 0;
	if (!ReadFile(File_Info->file_handle, buffer, File_Info->size, &byte_read, NULL)) {
		log_Error("couldn't read file");
		goto exit_fail;
	};

	return (BYTE*)buffer;

exit_fail:
	return NULL;
}

HANDLE InjectInProcess(HANDLE process, LPVOID mem_address, BYTE* dll, unsigned int dll_size) {
	if (!mem_address) {
		log_Error("invalid mem_address");
		return NULL;
	}
	WriteProcessMemory(process, mem_address, dll, dll_size, NULL);

	HANDLE thread = CreateRemoteThreadEx(process, NULL, 0, (LPTHREAD_START_ROUTINE)mem_address, NULL, CREATE_SUSPENDED, NULL, NULL);
	if (!thread || thread == INVALID_HANDLE_VALUE) {  
		log_Error("thread error");
		return NULL;
	}
	return thread;
}


CONTEXT* ExamineThread(HANDLE thread) {
	if (!thread || thread == INVALID_HANDLE_VALUE) {
		log_Error("Invalid thread handle in ExamineThread");
		return NULL;
	}

	CONTEXT* thread_context = (CONTEXT*)malloc(sizeof(CONTEXT));
	if (!thread_context) {
		log_Error("Malloc failed");
		return NULL;
	}

	thread_context->ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(thread, thread_context)) {
		log_Error("GetThreadContext failed");
		free(thread_context);
		return NULL;
	}

	return thread_context;
}


int main(int argc, char** argv) {

	if (argc > 2 || !argv[1]) {
		log_Error("please enter a DLL");
		return EXIT_FAILURE;
	}
	
	file_info* File_info = DllReadFile(argv[1]);
	DWORD pid = printBaseplate(File_info);
	PROCESSENTRY32W* process_entry = CaptureProcess(&pid);

	HANDLE process = 0;
	LPVOID address = AllocateMem(process_entry, File_info, &process);
	if (address) {
		printf("\n#- allocated address (Execute Read Write) : %p", address);
	}

	BYTE* buffer = ReadDllBytes(File_info);

	if (buffer) {
		printf("\n\n[-] DLL BYTES: \n");
		for (DWORD i = 0; i < File_info->size; i++) {
			if (i % 30 == 0) {
				if (i != 0) printf("}\n");
				printf("{");
			}
			printf("%02x,", buffer[i]);  
		}
		printf("}\n\n");
	}

	if (process == INVALID_HANDLE_VALUE) {
		log_Error("invalid process handle");
		CleanUp(File_info, process_entry, buffer);
		return EXIT_FAILURE;
	}

	thread_info Thread_info;
	Thread_info.thread_handle = InjectInProcess(process, address, buffer, File_info->size);
	if (!Thread_info.thread_handle) {
		log_Error("Thread injection failed");
		return EXIT_FAILURE;
	}
	printf("\n[+] Thread injected successfully: %p", Thread_info.thread_handle);

	Thread_info.context_ptr = ExamineThread(Thread_info.thread_handle);
	if (!Thread_info.context_ptr) {
		log_Error("ExamineThread failed");
		return EXIT_FAILURE;
	}
	printf("\n[+] Examined thread context at: %p", Thread_info.context_ptr);

	uint8_t run = 0;
	SET_COLOR(4);
	printf("\n\n[1] Run DLL\n");
	printf("[2] APC attack\n");
	printf("[3] Thread Hijack\n");
	printf("[4] Hook Function IAT\n");
	printf("[5] Hook Function EAT");

	printf("\n\nDLL injector ~~> ");
	if (!scanf("%3d", &run)) {
		log_Error("scanf fail"); return NULL;
	};
	switch (run)
	{
	case 1:
		if (!ResumeThread(Thread_info.thread_handle)) { log_Error("couldnt resume thread"); }
		else {
			SET_COLOR(3);
			printf("DLL IS RUNNING...");
		};
		break;
	default:
		printf("error wrong number or not supported yet\n");
		break;
	}
	//change thread to ACTIVE

	CleanUp(File_info, process_entry, buffer);
	free(address);
	CloseHandle(process);
}