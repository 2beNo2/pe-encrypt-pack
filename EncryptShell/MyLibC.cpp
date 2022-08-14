#include "MyLibC.h"


void MyZeroMem(void* lpDstAddress, int dwSize) {
    __asm {
        cld;
        mov edi, lpDstAddress;
        mov ecx, dwSize;
        mov eax, 0
            rep stosb;
    }
}

DWORD MyMemCmp(void* lpDstAddress, void* lpSrcAddress, int dwSize) {
    DWORD dwRet = 0;
    __asm {
        cld;
        mov edi, lpDstAddress;
        mov esi, lpSrcAddress;
        mov ecx, dwSize;
        repz cmpsb;
        jnz NOT_EQUAL;
        mov eax, 0;
        jmp EXIT_FUN;
    NOT_EQUAL:
        sub edi, esi;
        mov eax, edi;
    EXIT_FUN:
        mov dwRet, eax
    }
    return dwRet;
}

void MyMemCopy(void* lpDstAddress, void* lpSrcAddress, int dwSize) {
    __asm {
        cld;
        mov edi, lpDstAddress;
        mov esi, lpSrcAddress;
        mov eax, dwSize;
        xor edx, edx;
        mov ecx, 4;
        div ecx;
        mov ecx, eax;
        rep movsd;
        mov ecx, edx;
        rep movsb;
    }
}

int MyStrLen(const char* pSrc) {
    int nLen = 0;
    while (pSrc[nLen] != '\0') {
        nLen++;
    }
    return nLen;
}

void Pascal2CStr(char* pDst, const char* pSrc, int nSize) {
    int nIndex = 0;
    for (int i = 0; i < nSize; i += 2) {
        pDst[nIndex] = pSrc[i];
        nIndex++;
    }
}

void CStr2Pascal(char* pDst, const char* pSrc, int nSize) {
    int nIndex = 0;
    for (int i = 0; i < nSize; ++i) {
        pDst[nIndex] = pSrc[i];
        pDst[nIndex + 1] = '\0';
        nIndex += 2;
    }
}

BOOL CmpPascalStrWithCStr(const char* pPascalStr, const char* pCStr, int nCStrSize) {
    int nIndex = 0;
    for (int i = 0; i < nCStrSize; ++i) {
        if (pCStr[i] != pPascalStr[nIndex] && pCStr[i] != (pPascalStr[nIndex] + 32)) {
            return FALSE;
        }
        nIndex += 2;
    }

    if (pPascalStr[nIndex] != '\0') {
        return FALSE;
    }
    return TRUE;
}