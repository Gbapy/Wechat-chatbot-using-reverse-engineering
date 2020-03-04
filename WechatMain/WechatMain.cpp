// WechatMain.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "WechatMain.h"
#include <exception>
#include <vector>

using namespace std;

vector<MSGPARAM> mParams;
// This is the constructor of a class that has been exported.
// see WechatMain.h for the class definition
CWechatMain::CWechatMain()
{
	return;
}

WECHATMAIN_API void WMSendImageMsg(PMSGPARAM lpMsgParam){
	bIsBusy = true;
	MSGPARAM mp;
	memset(&mp, 0, sizeof(MSGPARAM));
	wcscpy(mp.wxID, lpMsgParam->wxID);
	wcscpy(mp.wzContext, lpMsgParam->wzContext);
	mParams.push_back(mp);
	bIsBusy = false;
}

void SendImageMsg(void *threadArg) {
	while (bStopFlag == false) {
		MSGPARAM mp;
		DWORD thisObj[238];
		DWORD *thisPtr = thisObj;
		CMD cmd;
		PCMD pCmd = &cmd;
		DWORD reserve1;
		DWORD reserve2;
		DWORD reserve3 = (DWORD)thisPtr + 0x410;
		IMGSENDPARAM param;
		HMODULE hMod = GetModuleHandleA("WechatWin.dll");
		if (hMod == NULL) goto _final;
		PFN_SendImageMessage	sendImgFunc = PFN_SendImageMessage((DWORD)hMod + 0x2E3810);
		PIMGSENDPARAM lpParam = &param;
		DWORD cmdPtr = (DWORD)lpParam;
		char result[0x1000] = { 0 };
		void	*ptr1 = result;
		DWORD	ptr2 = (DWORD)thisPtr + 24;
		DWORD	ptr3 = (DWORD)pCmd + 4;
		DWORD	msgSendMgr = (DWORD)hMod + 0x126A0A8;
		BYTE	*preEspEnd;

		if (bIsBusy) goto _final;
		if (espPtr == NULL) break;
		if (mParams.size() == 0) goto _final;

		mp = mParams[0];
		for (int i = 0; i < mParams.size() - 1; i++) {
			mParams[i] = mParams[i + 1];
		}
		mParams.resize(mParams.size() - 1);

		reserve1 = (DWORD)hMod + 0x10003B4;
		reserve2 = (DWORD)hMod + 0x1001C24;
		thisObj[0] = (DWORD)hMod + 0x10021E0;
		thisObj[1] = (DWORD)hMod + 0x10021EC;
		thisObj[2] = (DWORD)&reserve1;
		thisObj[6] = (DWORD)(WCHAR *)mp.wxID;
		thisObj[7] = (DWORD)wcslen(mp.wxID);
		thisObj[8] = (DWORD)wcslen(mp.wxID) + 0x10;
		thisObj[260] = (DWORD)&reserve3;
		thisObj[282] = (DWORD)&reserve2;

		
		cmd.path = mp.wzContext;
		cmd.len = wcslen(mp.wzContext);
		cmd.maxLen = wcslen(mp.wzContext) + 0x10;
		param.lpCmd = pCmd;
		param.reserve = (DWORD)pCmd + 0x24;
		
		_asm {
			mov preEspEnd, esp
		}
		//BYTE *preEstStart = preEspEnd - 8191;
		//for (int i = 0; i < 8192; i++) {
		//	espPtr[i] = preEstStart[i];
		//}
		_asm {
			mov ecx, msgSendMgr
			push ptr3
			push ptr2
			push ptr1
			call sendImgFunc
		}
		//for (int i = 0; i < 8192; i++) {
		//	preEstStart[i] = espPtr[i];
		//}
		_asm {
			mov esp, preEspEnd
		}
	_final:
		Sleep(30);
	}
	return;
}