// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "WechatMain.h"

#include <stdlib.h>

BYTE *espPtr;
BOOL bStopFlag;
BOOL bIsBusy;
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		bIsBusy = true;
		bStopFlag = false;
		espPtr = (BYTE *)malloc(8192);
		HANDLE capture_thread = CreateThread(
			NULL, 0, (LPTHREAD_START_ROUTINE)SendImageMsg,
			NULL, 0, 0);
		if (!capture_thread) {
			return false;
		}
	}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		if (espPtr) free(espPtr);
		bStopFlag = true;
		Sleep(3000);
		break;
	}
	return TRUE;
}

