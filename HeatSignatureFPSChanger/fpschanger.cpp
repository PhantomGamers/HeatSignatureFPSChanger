// HeatSignatureFPSChanger.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>  
#include "fpschanger.h" //this is our header file we created.
using namespace std;


void ChangeMemory(DWORD baseadress, int value, DWORD offset1, DWORD offset2, bool msg)
{
	DWORD d, ds;
	DWORD* adress = (DWORD*)((*(DWORD*)(baseadress + offset1)) + offset2);

	if (msg)
	{
		char szTest[10];
		sprintf_s(szTest, "The final adress is : %X", adress);
		MessageBoxA(NULL, szTest, NULL, NULL);
	}

	//VirtualProtect((LPVOID)adress, sizeof(value), PAGE_EXECUTE_READWRITE, &d);    
	*(int*)adress = value;
	//VirtualProtect((LPVOID)adress ,sizeof(value),d,&ds);
}

void Main()
{
}


