// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the WECHATMAIN_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// WECHATMAIN_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef WECHATMAIN_EXPORTS
#define WECHATMAIN_API __declspec(dllexport)
#else
#define WECHATMAIN_API __declspec(dllimport)
#endif


typedef char(__stdcall* PFN_SendImageMessage)(DWORD ptr1, DWORD ptr2, DWORD ptr3);

typedef struct _CMD_
{
	DWORD	command;
	WCHAR	*path;
	DWORD	len;
	DWORD	maxLen;
}CMD, *PCMD;

typedef struct _IMGMSGPARAM_
{
	PCMD	lpCmd;
	DWORD	reserve;
}IMGSENDPARAM, *PIMGSENDPARAM;

typedef struct _MSG_PARAM_
{
	wchar_t wxID[MAX_PATH];
	wchar_t wzContext[1024];
}MSGPARAM, *PMSGPARAM;

// This class is exported from the WechatMain.dll
class WECHATMAIN_API CWechatMain {
public:
	CWechatMain(void);
	// TODO: add your methods here.
};

extern BYTE *espPtr;
extern BOOL bStopFlag;
extern BOOL bIsBusy;

void SendImageMsg(void *threadArg);

EXTERN_C{
	WECHATMAIN_API void WMSendImageMsg(PMSGPARAM lpParam);
}