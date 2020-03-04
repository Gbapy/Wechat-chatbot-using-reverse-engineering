// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the WECHATHOOK_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// WECHATHOOK_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef WECHATHOOK_EXPORTS
#define WECHATHOOK_API __declspec(dllexport)
#else
#define WECHATHOOK_API __declspec(dllimport)
#endif

// This class is exported from the WechatHook.dll
class WECHATHOOK_API CWechatHook {
public:
	CWechatHook(void);
	// TODO: add your methods here.
};

typedef struct _MSG_PARAM_
{
	wchar_t wxID[MAX_PATH];
	wchar_t wzContext[1024];
}MSGPARAM, *PMSGPARAM;

#define LOWER_HALFBYTE(x) ((x)&0xF)
#define UPPER_HALFBYTE(x) (((x) >> 4) & 0xF)

typedef int(*PFNRECVTEXTMSG_CALLBACK)(int pid, wchar_t* wxid, wchar_t* msg);
typedef int(*PFNRECVMONEYMSG_CALLBACK)(int pid, wchar_t* wxid, wchar_t* tid, wchar_t* msg);
typedef HANDLE(WINAPI *create_remote_thread_t)(HANDLE, LPSECURITY_ATTRIBUTES,
	SIZE_T, LPTHREAD_START_ROUTINE,
	LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI *write_process_memory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T,
	SIZE_T *);
typedef LPVOID(WINAPI *virtual_alloc_ex_t)(HANDLE, LPVOID, SIZE_T, DWORD,
	DWORD);
typedef BOOL(WINAPI *virtual_free_ex_t)(HANDLE, LPVOID, SIZE_T, DWORD);

EXTERN_C{
	WECHATHOOK_API int WHInitialize(DWORD pid);
	WECHATHOOK_API int WHSendImgMsg(DWORD pid, const wchar_t *wxID, const wchar_t *wzFile);
}