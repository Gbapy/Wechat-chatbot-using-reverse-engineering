// WechatHook.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "WechatHook.h"
#include "RemoteOps.h"

#include <Shlwapi.h>

static void deobfuscate_str(char *str, UINT64 val)
{
	UCHAR *dec_val = (UCHAR *)&val;
	int i = 0;

	while (*str != 0) {
		int pos = i / 2;
		bool bottom = (i % 2) == 0;
		UCHAR *ch = (UCHAR *)str;
		UCHAR xor = bottom ? LOWER_HALFBYTE(dec_val[pos])
			: UPPER_HALFBYTE(dec_val[pos]);

		*ch ^= xor;

		if (++i == sizeof(UINT64) * 2)
			i = 0;

		str++;
	}
}

void *get_obfuscated_func(HMODULE module, const char *str, UINT64 val)
{
	char new_name[128];
	strcpy(new_name, str);
	deobfuscate_str(new_name, val);
	return GetProcAddress(module, new_name);
}

int inject_library_obf(HANDLE process, const wchar_t *dll,
	const char *create_remote_thread_obf, UINT64 obf1,
	const char *write_process_memory_obf, UINT64 obf2,
	const char *virtual_alloc_ex_obf, UINT64 obf3,
	const char *virtual_free_ex_obf, UINT64 obf4,
	const char *load_library_w_obf, UINT64 obf5)
{
	int ret = -1;
	DWORD last_error = 0;
	BOOL success = false;
	SIZE_T written_size;
	DWORD thread_id;
	HANDLE thread = NULL;
	size_t size;
	void *mem;

	/* -------------------------------- */

	HMODULE kernel32 = GetModuleHandleW(L"KERNEL32");
	create_remote_thread_t create_remote_thread;
	write_process_memory_t write_process_memory;
	virtual_alloc_ex_t virtual_alloc_ex;
	virtual_free_ex_t virtual_free_ex;
	FARPROC load_library_w;

	create_remote_thread =
		(create_remote_thread_t)get_obfuscated_func(kernel32, create_remote_thread_obf, obf1);
	write_process_memory =
		(write_process_memory_t)get_obfuscated_func(kernel32, write_process_memory_obf, obf2);
	virtual_alloc_ex =
		(virtual_alloc_ex_t)get_obfuscated_func(kernel32, virtual_alloc_ex_obf, obf3);
	virtual_free_ex =
		(virtual_free_ex_t)get_obfuscated_func(kernel32, virtual_free_ex_obf, obf4);
	load_library_w =
		(FARPROC)get_obfuscated_func(kernel32, load_library_w_obf, obf5);

	/* -------------------------------- */

	size = (wcslen(dll) + 1) * sizeof(wchar_t);
	mem = virtual_alloc_ex(process, NULL, size, MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);
	if (!mem) {
		goto fail;
	}

	success = write_process_memory(process, mem, dll, size, &written_size);
	if (!success) {
		goto fail;
	}

	thread = create_remote_thread(process, NULL, 0,
		(LPTHREAD_START_ROUTINE)load_library_w,
		mem, 0, &thread_id);
	if (!thread) {
		goto fail;
	}

	if (WaitForSingleObject(thread, 4000) == WAIT_OBJECT_0) {
		DWORD code;
		GetExitCodeThread(thread, &code);
		ret = (code != 0) ? 0 : -1;

		SetLastError(0);
	}

fail:
	if (ret == -2) {
		last_error = GetLastError();
	}
	if (thread) {
		CloseHandle(thread);
	}
	if (mem) {
		virtual_free_ex(process, mem, 0, MEM_RELEASE);
	}
	if (last_error != 0) {
		SetLastError(last_error);
	}

	return ret;
}

static inline int inject_library(HANDLE process, const wchar_t *dll)
{
	return inject_library_obf(process, dll, "D|hkqkW`kl{k\\osofj",
		0xa178ef3655e5ade7, "[uawaRzbhh{tIdkj~~",
		0x561478dbd824387c, "[fr}pboIe`dlN}",
		0x395bfbc9833590fd, "\\`zs}gmOzhhBq",
		0x12897dd89168789a, "GbfkDaezbp~X",
		0x76aff7238788f7db);
}

WECHATHOOK_API int WHInitialize(DWORD pid)
{
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
	//process = open_process(PROCESS_ALL_ACCESS, false, pNox->processID);
	if (!process) {
		int error = GetLastError();
		return -2;
	}

	HMODULE h = GetRemoteModuleHandle(process, "WechatMain.dll");
	if (h == NULL) {
		wchar_t buf[MAX_PATH] = { 0 };
		wchar_t	hook_dll_path[MAX_PATH] = { 0 };
		wchar_t *hook_dll = L"WechatMain.dll";

		GetModuleFileNameW(GetModuleHandle(NULL), buf, MAX_PATH);
		for (int i = wcslen(buf) - 1; i >= 0; i--) {
			if (buf[i] == '\\') {
				for (int j = 0; j <= i; j++) {
					hook_dll_path[j] = buf[j];
				}
				for (int j = 0; j < wcslen(hook_dll); j++) {
					hook_dll_path[i + j + 1] = hook_dll[j];
				}
				break;
			}
		}

		if (!PathFileExistsW(hook_dll_path)) {
			OutputDebugStringW(L"WechatMain.dll not found");
			CloseHandle(process);
			return ERROR_FILE_NOT_FOUND;
		}

		if (inject_library(process, hook_dll_path))
		{
			OutputDebugStringW(L"InjectDll1 failed");
			CloseHandle(process);
			return -1;
		}
	}
	CloseHandle(process);
	return ERROR_SUCCESS;
}

WECHATHOOK_API int WHSendImgMsg(DWORD pid, const wchar_t *wxID, const wchar_t *wzFile) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
	if (!hProcess) {
		return 1;
	}
	HMODULE h = GetRemoteModuleHandle(hProcess, "WechatMain.dll");
	if (h == NULL) {
		CloseHandle(hProcess);
		return 2;
	}
	DWORD funcPtr = (DWORD)GetRemoteProcAddress(hProcess, h, "WMSendImageMsg", 0, FALSE);
	if (!funcPtr) {
		CloseHandle(hProcess);
		return 6;
	}
	DWORD td;
	MSGPARAM param;
	write_process_memory_t write_process_memory;
	virtual_alloc_ex_t virtual_alloc_ex;
	virtual_free_ex_t virtual_free_ex;
	HMODULE kernel32 = GetModuleHandleW(L"KERNEL32");

	if (kernel32 == NULL) {
		CloseHandle(hProcess);
		return 3;
	}
	write_process_memory =
		(write_process_memory_t)get_obfuscated_func(kernel32, "[uawaRzbhh{tIdkj~~", 0x561478dbd824387c);
	virtual_alloc_ex =
		(virtual_alloc_ex_t)get_obfuscated_func(kernel32, "[fr}pboIe`dlN}", 0x395bfbc9833590fd);
	virtual_free_ex =
		(virtual_free_ex_t)get_obfuscated_func(kernel32, "\\`zs}gmOzhhBq", 0x12897dd89168789a);

	memset(&param, 0, sizeof(MSGPARAM));
	wsprintfW(param.wxID, wxID);
	wsprintfW(param.wzContext, wzFile);
	size_t size = sizeof(MSGPARAM);
	DWORD written_size;

	void *mem = virtual_alloc_ex(hProcess, NULL, size, MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE);
	if (!mem) {
		CloseHandle(hProcess);
		return 4;
	}

	BOOL success = write_process_memory(hProcess, mem, &param, size, &written_size);
	if (!success || written_size != size) {
		CloseHandle(hProcess);
		return 5;
	}
	CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)funcPtr, (LPVOID)mem, CREATE_SUSPENDED, &td); //0x0047C580
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, td);
	ResumeThread(hThread);
	if (WaitForSingleObject(hThread, INFINITE) == WAIT_OBJECT_0) {
		DWORD code;
		GetExitCodeThread(hThread, &code);
		SetLastError(0);
	}
	if (mem) {
		virtual_free_ex(hProcess, mem, 0, MEM_RELEASE);
	}
	CloseHandle(hProcess);
	return 0;
}
// This is the constructor of a class that has been exported.
// see WechatHook.h for the class definition
CWechatHook::CWechatHook()
{
	return;
}
