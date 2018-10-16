// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <Windows.h>
#include <iostream>  
#include <thread>
#include "main.h"
#include "externals\IniReader\IniReader.h"
#include <fstream>
using namespace std;

void ChangeMemory(DWORD baseaddress, int value, DWORD offset1, DWORD offset2)
{
	DWORD* address = (DWORD*)((*(DWORD*)(baseaddress + offset1)) + offset2);

	if (address)
		*(int*)address = value;
}
void PatchAOB(char* pattern, char* mask, char* processname, char* valuetowrite, int size, int position)
{
	DWORD pVariable = FindPattern(processname, pattern, mask);
	pVariable += position;
	if (pVariable != 0)
		WriteToMemory(pVariable, valuetowrite, size);
}

void Patch(int fps)
{
	while(!IsWindowVisible(FindWindow("YYGameMakerYY", "Heat Signature")))
		std::this_thread::yield();
	ChangeMemory((DWORD)GetModuleHandle(NULL), fps, 0x044EBB58, 0xC);
	PatchAOB((char*)"\x89\x41\x0C\x8A\xC3\x5B\x83\xC4\x08\xC3\x6A\x00\x68", (char*)"xxxxxxxxxxxxx", (char*)"Heat_Signature.exe", (char*)"\x90\x90\x90",3, 0);

}

void Init()
{
	CIniReader fpscap("fpscap.ini");
	int fps = fpscap.ReadInteger("MAIN", "frameratelimit", 0);
	if (fps > 0)
		Patch(fps);
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Init, NULL, NULL, NULL);
		break;
	}
	return TRUE;
}