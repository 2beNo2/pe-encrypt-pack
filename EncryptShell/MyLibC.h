#pragma once

#include <Windows.h>


void  MyZeroMem(void* lpDstAddress, int dwSize);
DWORD MyMemCmp(void* lpDstAddress, void* lpSrcAddress, int dwSize);
void  MyMemCopy(void* lpDstAddress, void* lpSrcAddress, int dwSize);
int   MyStrLen(const char* pSrc);

void Pascal2CStr(char* pDst, const char* pSrc, int nSize);
void CStr2Pascal(char* pDst, const char* pSrc, int nSize);
BOOL CmpPascalStrWithCStr(const char* pPascalStr, const char* pCStr, int nCStrSize);