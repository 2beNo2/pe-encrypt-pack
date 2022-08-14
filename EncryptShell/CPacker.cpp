#include "CPacker.h"

CPacker::CPacker() {
}

CPacker::~CPacker() {
}

BOOL CPacker::Pack(const char* pSrcPath, const char* pDstPath) {
    return 0;
}

DWORD CPacker::MoveImportTable(PBYTE pImportTableBuff) {
    return 0;
}

void CPacker::ClearImportTable() {
}

DWORD CPacker::MoveRelocTable(PBYTE pRelocTableBuff) {
    return 0;
}

void CPacker::ClearRelocTable() {
}

BOOL CPacker::DoCompress() {
    return 0;
}

BOOL CPacker::GetShellCode() {
    return 0;
}

BOOL CPacker::RebuildSection() {
    return 0;
}

BOOL CPacker::RebuildPeHeader() {
    return 0;
}

BOOL CPacker::WritePackerFile(const char* pDstPath) {
    return 0;
}
