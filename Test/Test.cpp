// Test.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "Test.h"
#include "sdk.h"
#include "RemoteOps.h"

#include <stdio.h>
#include <TlHelp32.h>
#include <commdlg.h>
#include <io.h>

using namespace std;
#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name

// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
DWORD pid;
WCHAR wzFile[MAX_PATH];
WCHAR wzWxID[MAX_PATH];

typedef INT(WINAPIV* LPWHINITIALIZE)(DWORD);
typedef VOID(WINAPIV* LPWHSENDIMGMSG)(DWORD, WCHAR *, WCHAR *);

LPWHINITIALIZE		WHInitialize;
LPWHSENDIMGMSG		WHSendImgMsg;
const char **szFiles;

int GetProcIds(LPCSTR Name, DWORD* Pids)
{
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	int num = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap)
	{
		if (Process32First(hSnap, &pe32))
		{
			do {
				if (!strcmp(Name, pe32.szExeFile))
				{
					if (Pids)
					{
						Pids[num++] = pe32.th32ProcessID;
					}
				}
			} while (Process32Next(hSnap, &pe32));
		}
		CloseHandle(hSnap);
	}

	return num;
}

int TestRecvMoneyMsg(int pid, wchar_t* wxid, wchar_t* tid, wchar_t* msg)
{
	wsprintfW(wxid, L"%ws -> %ws, %ws\n", tid, msg);
	return 0;
}

int TestRecvTextMsg(int pid, wchar_t* wxid, wchar_t* msg)
{
	wsprintfW(wxid, L"%ws->%ws\n", msg);
	return 0;
}

void Warn(HWND hWnd, char *msg) {
	MessageBox(hWnd, msg, "WechatSDK", MB_OK);
}

int GetWeChatPath(char* Path)
{
	int ret = -1;
	//HKEY_CURRENT_USER\Software\Tencent\WeChat InstallPath = xx
	HKEY hKey = NULL;
	if (ERROR_SUCCESS != RegOpenKey(HKEY_CURRENT_USER, "Software\\Tencent\\WeChat", &hKey))
	{
		ret = GetLastError();
		return ret;
	}

	DWORD Type = REG_SZ;
	// WCHAR Path[MAX_PATH] = { 0 };
	DWORD cbData = MAX_PATH * sizeof(WCHAR);
	if (ERROR_SUCCESS != RegQueryValueEx(hKey, "InstallPath", 0, &Type, (LPBYTE)Path, &cbData))
	{
		ret = GetLastError();
		goto __exit;
	}

	strcat(Path, "WeChat.exe");

__exit:
	if (hKey)
	{
		RegCloseKey(hKey);
	}

	return ERROR_SUCCESS;
}

int IsAlreadyInjected(DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
	if (!hProcess) {
		int error = GetLastError();
		//warn("hook_direct: could not open process: %s (%lu)");
		return 1;
	}
	HMODULE h = GetRemoteModuleHandle(hProcess, "WechatSDKCore.dll");
	if (h == NULL) return 0;
	return 2;
}

int InitWechat() {
	DWORD Pids[100] = { 0 };

	DWORD num = GetProcIds("WeChat.exe", Pids);

	if (num > 1) {
		Warn(NULL, "More than a Wechat detected!");
		return -1;
	}
	if (num == 0){
		char Path[MAX_PATH] = { 0 };
		STARTUPINFO si = { sizeof(si) };
		PROCESS_INFORMATION pi = { 0 };

		if (ERROR_SUCCESS != GetWeChatPath(Path)) {
			Warn(NULL, "Unabled to find a Wechat");
			return -2;
		}

		if (!CreateProcess(NULL, Path, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
			Warn(NULL, "Unabled to run a Wechat");
			return -3;
		}

		Pids[0] = pi.dwProcessId;
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	pid = Pids[0];
	if (pid <= 0) {
		Warn(NULL, "open wechat error!");
		return -4;
	}

	WHInitialize(pid);
	return 0;
}

typedef INT(WINAPI* LPTEST)(INT, INT);
int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

 	// TODO: Place code here.
	HACCEL hAccelTable;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_TEST, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);


	hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_TEST));
	HMODULE handle = LoadLibrary("WeChatHook.dll");

	WHInitialize = (LPWHINITIALIZE)GetProcAddress(handle, "WHInitialize");
	WHSendImgMsg = (LPWHSENDIMGMSG)GetProcAddress(handle, "WHSendImgMsg");
	if (InitWechat() != 0) {
		Warn(NULL, "Unable to run the SDK!");
		return -1;
	}
	// Main message loop:
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DLG_MAIN), NULL, (DLGPROC)WndProc);
	return 0;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, MAKEINTRESOURCE(IDI_TEST));
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= MAKEINTRESOURCE(IDC_TEST);
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassEx(&wcex);
}

bool FileExists(const WCHAR *filePathPtr)
{
	WCHAR filePath[_MAX_PATH];

	// Strip quotation marks (if any)
	if (filePathPtr[0] == '"')
	{
		wcscpy(filePath, filePathPtr + 1);
	}
	else
	{
		wcscpy(filePath, filePathPtr);
	}

	// Strip quotation marks (if any)
	if (filePath[wcslen(filePath) - 1] == L'"')
		filePath[wcslen(filePath) - 1] = 0;
	
	return (_waccess(filePath, 0) != -1);
}

void TimerProc() {
	WHSendImgMsg(pid, wzWxID, wzFile);
}
//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;

	switch (message)
	{
	case WM_INITDIALOG:
		SetWindowTextW(GetDlgItem(hWnd, IDC_WECHAT_ID), L"wxid_rdp53aprecws22");
		break;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
		case IDC_BROWSE:
			{
				OPENFILENAMEW ofn;

				ZeroMemory(&ofn, sizeof(ofn));
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = hWnd;
				ofn.lpstrFile = wzFile;

				ofn.lpstrFile[0] = '\0';
				ofn.nMaxFile = sizeof(wzFile);
				ofn.lpstrFilter = L"Jpg\0*.Jpg\0Jpeg\0 *.jpeg\0Bmp\0*.bmp\0Png\0*.png";
				ofn.nFilterIndex = 1;
				ofn.lpstrFileTitle = NULL;
				ofn.nMaxFileTitle = 0;
				ofn.lpstrInitialDir = NULL;
				ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
				GetOpenFileNameW(&ofn);
				SetWindowTextW(GetDlgItem(hWnd, IDC_FILE_PATH), wzFile);
			}
			break;
		case IDOK:
			{
				if (!FileExists(wzFile)) {
					Warn(hWnd, "File could not be found!");
					break;
				}

				GetWindowTextW(GetDlgItem(hWnd, IDC_WECHAT_ID), wzWxID, MAX_PATH);
				if (wcslen(wzWxID) == 0) {
					Warn(hWnd, "Please Enter the Wechat ID!");
					break;
				}
				//whSendImgMsg(pid, wzWxID, wzFile);
				SetTimer(hWnd, 1, 10000, (TIMERPROC)TimerProc);
			}
			break;
		case IDCANCEL:
			DestroyWindow(hWnd);
			break;
		}
		break;
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		// TODO: Add any drawing code here...
		EndPaint(hWnd, &ps);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
