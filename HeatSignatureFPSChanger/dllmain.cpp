// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <thread>
#include "main.h"
#include "externals\IniReader\IniReader.h"
#include <fstream>

void ChangeMemory(DWORD pointervalue, DWORD offset2, int value)
{
	DWORD* address = (DWORD*)(*(DWORD*)pointervalue + offset2);
	if (*(int*)address == 60 || *(int*)address == 30)
		*(int*)address = value;
}

void PatchAOB(DWORD address, char* valuetowrite, int size, int position)
{
	DWORD pVariable = address;
	pVariable += position;
	if (pVariable != 0)
		WriteToMemory(pVariable, valuetowrite, size);
}

DWORD GetFPSAddress(char* pattern, char* mask)
{
	DWORD pAddress = FindPattern((char*)"Heat_Signature.exe", pattern, mask);
	return pAddress;
}

void Patch(int fps)
{
	while (!IsWindowVisible(FindWindow("YYGameMakerYY", "Heat Signature")))
		std::this_thread::yield();
	char* pattern = ((char*)"\x89\x41\x0C\x8A\xC3\x5B\x83\xC4\x08\xC3\x6A\x00\x68");
	char* mask = (char*)"xxxxxxxxxxxxx";
	DWORD pAddress = GetFPSAddress(pattern, mask);
	DBOUT("[FPSChanger] FPS Write Address: ");
	DBOUT(pAddress);
	DBOUT("\n");
	DWORD pPointer = FindPointer((char*)"Heat_Signature.exe", pAddress, -4);
	ChangeMemory(pPointer, 0x0C, fps);
	PatchAOB(pAddress, (char*)"\x90\x90\x90", 3, 0);
}

void Init()
{
	DBOUT("[FPSChanger] Successfully injected. \n");
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