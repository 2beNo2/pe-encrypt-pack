#include "pch.h"
#include "CPe.h"
#include "MyLibC.h"

CPe::CPe() {
    Init();
}


CPe::CPe(void* pFileBuff) {
    Init();
    m_bIsMemInit = 1;
    InitPeFormat(pFileBuff);
}


CPe::CPe(const char* strFilePath) {
    Init();
    m_bIsMemInit = 0;
    InitPeFormat(strFilePath);
}


CPe::~CPe() {
    if (m_lpFileBuff != NULL && m_bIsMemInit != 1) {
        ::UnmapViewOfFile(m_lpFileBuff);
        m_lpFileBuff = NULL;
    }

    if (m_hFileMap != NULL) {
        ::CloseHandle(m_hFileMap);
        m_hFileMap = NULL;
    }

    if (m_hFile != INVALID_HANDLE_VALUE) {
        ::CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
}


void CPe::Init() {
    m_lpFileBuff = NULL;
    m_pDosHeader = NULL;
    m_pNtHeader = NULL;
    m_pFileHeader = NULL;
    m_pOptionHeader = NULL;
    m_pSectionHeader = NULL;
    m_pExportDirectory = NULL;
    m_pImportDirectory = NULL;
    m_pResourceDirectory = NULL;
    m_pRelocDirectory = NULL;
    m_pTlsDirectory = NULL;
    m_dwExportSize = 0;
    m_dwImportSize = 0;
    m_dwRelocSize = 0;

    m_wNumberOfSections = 0;
    m_dwAddressOfEntryPoint = 0;
    m_dwImageBase = 0;
    m_dwSectionAlignment = 0;
    m_dwFileAlignment = 0;
    m_dwSizeOfImage = 0;
    m_dwSizeOfHeaders = 0;
    m_dwNumberOfRvaAndSizes = 0;

    m_hFile = INVALID_HANDLE_VALUE;
    m_dwFileSize = 0;
    m_hFileMap = NULL;
    m_bIsMemInit = 0;
}


void CPe::InitPeFormat(void* pFileBuff) {
    if (pFileBuff == NULL) return;

    if (IsPeFile(pFileBuff) != FILE_IS_PE) {
        return;
    }
    m_lpFileBuff = pFileBuff;
    m_pDosHeader = (PIMAGE_DOS_HEADER)pFileBuff;
    m_pNtHeader = (PIMAGE_NT_HEADERS)((char*)pFileBuff + m_pDosHeader->e_lfanew);
    m_pFileHeader = (PIMAGE_FILE_HEADER)(&m_pNtHeader->FileHeader);
    m_pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&m_pNtHeader->OptionalHeader);
    m_pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)m_pOptionHeader + m_pFileHeader->SizeOfOptionalHeader);

    m_wNumberOfSections = m_pFileHeader->NumberOfSections;
    m_dwAddressOfEntryPoint = m_pOptionHeader->AddressOfEntryPoint;
    m_dwImageBase = m_pOptionHeader->ImageBase;
    m_dwSectionAlignment = m_pOptionHeader->SectionAlignment;
    m_dwFileAlignment = m_pOptionHeader->FileAlignment;
    m_dwSizeOfImage = m_pOptionHeader->SizeOfImage;
    m_dwSizeOfHeaders = m_pOptionHeader->SizeOfHeaders;
    m_dwNumberOfRvaAndSizes = m_pOptionHeader->NumberOfRvaAndSizes;

    m_dwFileSize = m_pSectionHeader[m_wNumberOfSections - 1].PointerToRawData + m_pSectionHeader[m_wNumberOfSections - 1].SizeOfRawData;

    // ������
    DWORD dwExportRva = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    m_dwExportSize = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    DWORD dwFa = Rva2Fa(dwExportRva, pFileBuff);
    if (dwFa == -1) {
        m_pExportDirectory = NULL;
    }
    else {
        m_pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwFa + (char*)m_lpFileBuff);
    }


    // �����
    DWORD dwImportRva = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    m_dwImportSize = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    dwFa = Rva2Fa(dwImportRva, pFileBuff);
    if (dwFa == -1) {
        m_pImportDirectory = NULL;
    }
    else {
        m_pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(dwFa + (char*)m_lpFileBuff);
    }

    // ��Դ��
    DWORD dwResourceRva = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    dwFa = Rva2Fa(dwResourceRva, pFileBuff);
    if (dwFa == -1) {
        m_pResourceDirectory = NULL;
    }
    else {
        m_pResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)(dwFa + (char*)m_lpFileBuff);
    }

    // �ض�λ��
    DWORD dwRelocRva = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    m_dwRelocSize = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    dwFa = Rva2Fa(dwRelocRva, pFileBuff);
    if (dwFa == -1) {
        m_pRelocDirectory = NULL;
    }
    else {
        m_pRelocDirectory = (PIMAGE_BASE_RELOCATION)(dwFa + (char*)m_lpFileBuff);
    }

    // TLS��
    DWORD dwTlsRva = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    dwFa = Rva2Fa(dwTlsRva, pFileBuff);
    if (dwFa == -1) {
        m_pTlsDirectory = NULL;
    }
    else {
        m_pTlsDirectory = (PIMAGE_TLS_DIRECTORY)(dwFa + (char*)m_lpFileBuff);
    }
}


void CPe::InitPeFormat(const char* strFilePath) {
    if (strFilePath == NULL) return;

    if (IsPeFile(strFilePath) != FILE_IS_PE) {
        return;
    }
    // ���ļ�
    m_hFile = ::CreateFile(strFilePath,             // �ļ�·��
        GENERIC_READ | GENERIC_WRITE,  // �ļ��Ĵ򿪷�ʽ
        FILE_SHARE_READ,        // ����ģʽ�������ļ��ɶ�
        NULL,                   // ��ȫ���ԣ�����ȷ�����صľ���Ƿ���Ա��ӽ��̼̳�
        OPEN_EXISTING,          // �򿪷�ʽ
        FILE_ATTRIBUTE_NORMAL,  // �ļ�����
        NULL);
    if (m_hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    // ��ȡ�ļ���С
    m_dwFileSize = ::GetFileSize(m_hFile, NULL);

    // �����ļ�ӳ�����
    m_hFileMap = ::CreateFileMapping(m_hFile,  // �ļ����
        NULL,      // ��ȫ���ԣ�����ȷ�����صľ���Ƿ���Ա��ӽ��̼̳�
        PAGE_READWRITE, // ӳ����ڴ�ҳ���ڴ�����
        NULL,      // ����4Gʱ����
        m_dwFileSize, // ӳ���С
        NULL);     // �ļ�ӳ���������ƣ����ú�����ڽ��̼�ͨ��
    if (m_hFileMap == NULL) {
        goto EXIT_PROC;
    }

    // ���ļ�ӳ�䵽�ڴ�
    m_lpFileBuff = ::MapViewOfFile(m_hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (m_lpFileBuff == NULL) {
        goto EXIT_PROC;
    }

    InitPeFormat(m_lpFileBuff);
    return;

EXIT_PROC:

    if (m_hFileMap != NULL) {
        ::CloseHandle(m_hFileMap);
        m_hFileMap = NULL;
    }

    if (m_hFile != INVALID_HANDLE_VALUE) {
        ::CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
}


int CPe::IsPeFile(void* pFileBuff) {
    if (pFileBuff == NULL)
        return FILE_NOT_PE;

    // �ж��Ƿ�PE�ļ�
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuff;
    if (pDosHeader->e_magic != 'ZM') {
        return FILE_NOT_PE;
    }
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pFileBuff + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != 'EP') {
        return FILE_NOT_PE;
    }

    return FILE_IS_PE;
}


int CPe::IsPeFile(const char* strFilePath) {
    if (strFilePath == NULL)
        return FIlE_OPEN_FAILD;

    // ���ļ�
    HANDLE hFile = ::CreateFile(strFilePath,            // �ļ�·��
        GENERIC_READ | GENERIC_WRITE,  // �ļ��Ĵ򿪷�ʽ
        FILE_SHARE_READ,        // ����ģʽ�������ļ��ɶ�
        NULL,                   // ��ȫ���ԣ�����ȷ�����صľ���Ƿ���Ա��ӽ��̼̳�
        OPEN_EXISTING,          // �򿪷�ʽ
        FILE_ATTRIBUTE_NORMAL,  // �ļ�����
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FIlE_OPEN_FAILD;
    }

    // ��ȡMZ��־
    WORD wMzMagic = 0;
    DWORD dwNumberOfBytesRead = 0;
    int nRet = ::ReadFile(hFile, &wMzMagic, sizeof(WORD), &dwNumberOfBytesRead, NULL);
    if (nRet == 0) { goto OPENFAILD; }
    if (wMzMagic != 'ZM') { goto NOTPE; }

    // ��ȡPE��־
    DWORD dwOffset = 0;
    WORD wPeMagic = 0;
    DWORD dwPtr = ::SetFilePointer(hFile, 0x3c, NULL, FILE_BEGIN);
    if (dwPtr == INVALID_SET_FILE_POINTER) { goto OPENFAILD; }

    nRet = ::ReadFile(hFile, &dwOffset, sizeof(DWORD), &dwNumberOfBytesRead, NULL);
    if (nRet == 0) { goto OPENFAILD; }

    dwPtr = ::SetFilePointer(hFile, dwOffset, NULL, FILE_BEGIN);
    if (dwPtr == INVALID_SET_FILE_POINTER) { goto OPENFAILD; }

    nRet = ::ReadFile(hFile, &wPeMagic, sizeof(wPeMagic), &dwNumberOfBytesRead, NULL);
    if (nRet == 0) { goto OPENFAILD; }
    if (wPeMagic != 'EP') { goto NOTPE; }

    // �ر��ļ�
    ::CloseHandle(hFile);
    return FILE_IS_PE;

OPENFAILD:
    if (hFile != INVALID_HANDLE_VALUE) {
        ::CloseHandle(hFile);
    }
    return FIlE_OPEN_FAILD;

NOTPE:
    if (hFile != INVALID_HANDLE_VALUE) {
        ::CloseHandle(hFile);
    }
    return FILE_NOT_PE;
}


int CPe::WriteMemoryToFile(void* pFileBuff, int nFileSize, const char* strFilePath) {
    if (pFileBuff == NULL || strFilePath == NULL)
        return FIlE_OPEN_FAILD;

    // ���ļ�
    HANDLE hFile = ::CreateFile(strFilePath,            // �ļ�·��
        GENERIC_WRITE,          // �ļ��Ĵ򿪷�ʽ
        FILE_SHARE_READ,        // ����ģʽ�������ļ��ɶ�
        NULL,                   // ��ȫ���ԣ�����ȷ�����صľ���Ƿ���Ա��ӽ��̼̳�
        CREATE_ALWAYS,          // �򿪷�ʽ
        FILE_ATTRIBUTE_NORMAL,  // �ļ�����
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FIlE_OPEN_FAILD;
    }

    DWORD dwNumberOfBytesWritten = 0;
    DWORD dwBytesToWrite = 0;
    while (dwBytesToWrite != nFileSize) {
        if (!::WriteFile(hFile,
            (char*)pFileBuff + dwBytesToWrite,
            nFileSize - dwBytesToWrite,
            &dwNumberOfBytesWritten, NULL)) {
            ::CloseHandle(hFile);
            return FIlE_WRITE_FAILD;
        }
        dwBytesToWrite += dwNumberOfBytesWritten;
    }

    ::FlushFileBuffers(hFile);
    ::CloseHandle(hFile);
    return FIlE_WRITE_SUC;
}

DWORD CPe::GetFileSize() {
    return m_dwFileSize;
}


LPVOID CPe::GetDosHeaderPointer() const {
    return m_pDosHeader;
}

LPVOID CPe::GetNtHeaderPointer() const {
    return m_pNtHeader;
}

LPVOID CPe::GetFileHeaderPointer() const {
    return m_pFileHeader;
}

LPVOID CPe::GetOptionHeaderPointer() const {
    return m_pOptionHeader;
}

LPVOID CPe::GetSectionHeaderPointer() const {
    return m_pSectionHeader;
}

LPVOID CPe::GetExportDirectoryPointer() const {
    return m_pExportDirectory;
}

DWORD CPe::GetExportDirectorySize() const {
    return m_dwExportSize;
}

LPVOID CPe::GetImportDirectoryPointer() const {
    return m_pImportDirectory;
}

LPVOID CPe::GetResourceDirectoryPointer() const {
    return m_pResourceDirectory;
}

LPVOID CPe::GetRelocDirectoryPointer() const {
    return m_pRelocDirectory;
}

DWORD CPe::GetRelocDirectorySize() const {
    return m_dwRelocSize;
}

LPVOID CPe::GetTlsDirectoryPointer() const {
    return m_pTlsDirectory;
}

WORD CPe::GetNumberOfSections() const {
    return m_wNumberOfSections;
}

DWORD CPe::GetAddressOfEntryPoint() const {
    return m_dwAddressOfEntryPoint;
}

DWORD CPe::GetImageBase() const {
    return m_dwImageBase;
}

DWORD CPe::GetSectionAlignment() const {
    return m_dwSectionAlignment;
}

DWORD CPe::GetFileAlignment() const {
    return m_dwFileAlignment;
}

DWORD CPe::GetSizeOfImage() const {
    return m_dwSizeOfImage;
}

DWORD CPe::GetSizeOfHeaders() const {
    return m_dwSizeOfHeaders;
}

DWORD CPe::GetNumberOfRvaAndSizes() const {
    return m_dwNumberOfRvaAndSizes;
}


/*
�������ܣ�PE�е�RVAת����FA
������
  dwRva��     ���ݵ�RVA
  lpFileBuff��PE�ļ���ģ���ַ
����ֵ��
  �ɹ��������ݵ�FA
  ʧ�ܷ���-1
*/
DWORD CPe::Rva2Fa(DWORD dwRva, LPVOID lpFileBuff) {
    if (lpFileBuff == NULL)
        return -1;

    // PE��ʽ����
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuff;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

    // �ж�RVA�Ƿ���Ч,RVA�������ģ���ַ��
    DWORD dwImageBase = (DWORD)lpFileBuff;
    DWORD dwVa = dwImageBase + dwRva;
    if (dwVa < dwImageBase || dwVa >= dwImageBase + pOptionHeader->SizeOfImage) {
        return -1;
    }

    // �����ڱ���ȡFA
    for (int i = 0; i < pFileHeader->NumberOfSections; ++i) {
        DWORD dwVirtualAddress = pSectionHeader->VirtualAddress;  // ӳ�䵽�ڴ�ĵ�ַ��RVA
        DWORD dwVirtualSize = pSectionHeader->Misc.VirtualSize;   // ӳ�䵽�ڴ�����ݴ�С��OS�Ὣ��ֵ����������ڴ�
        DWORD dwPointerToRawData = pSectionHeader->PointerToRawData; // �ļ������ݵ�ƫ��
        DWORD dwSizeOfRawData = pSectionHeader->SizeOfRawData;    // �ļ������ݶ�����С

        if (dwRva >= dwVirtualAddress && dwRva < dwVirtualAddress + dwSizeOfRawData) {
            return dwRva - dwVirtualAddress + dwPointerToRawData;
        }
        pSectionHeader++;
    }
    return -1;
}


/*
�������ܣ���ȡ���ݵĶ���ֵ
������
  dwDataSize�����ݵĴ�С
  dwAlign��   Ҫ����Ĵ�С
����ֵ��
  �������ݵĶ���ֵ
*/
DWORD CPe::GetAlignSize(DWORD dwDataSize, DWORD dwAlign) {
    if (dwDataSize == 0)
        return 0;

    if (dwDataSize % dwAlign == 0) {
        return dwDataSize;
    }
    return (dwDataSize / dwAlign + 1) * dwAlign;
}


/*
�������ܣ������ڱ�
������
  lpOldFileBuff��PE�ļ����ڴ��ַ
  dwOldFileSize��PE�ļ���ԭʼ��С
  lpDataBuff   �������ڱ������
  dwDataSize   �������ڱ�����ݵĴ�С
����ֵ��
  �ɹ�PE�ļ��µ��ڴ��ַ
  ʧ�ܷ���NULL
ע�⣺
  dwDataSize = 0ʱ����ʾ����һ��û���ļ�ӳ��Ľ�
  ���ص��ڴ��ַ��malloc����ģ�ʹ����ǵõ���free
*/
LPVOID CPe::AddSection(LPVOID lpOldFileBuff, DWORD dwOldFileSize, LPVOID lpDataBuff, DWORD dwDataSize) {
    if (lpOldFileBuff == NULL)
        return NULL;

    // PE��ʽ����
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpOldFileBuff;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

    // �������ļ��Ĵ�С
    DWORD dwNewFileSize = dwOldFileSize + GetAlignSize(dwDataSize, pOptionHeader->FileAlignment);

    // �����µ��ڴ棬���ɵ��ļ��ڴ�������ڱ����ݿ�����ȥ
    LPVOID lpNewFileBuff = malloc(dwNewFileSize);
    if (lpNewFileBuff == NULL) {
        return NULL;
    }
    ::RtlZeroMemory(lpNewFileBuff, dwNewFileSize);

    memcpy(lpNewFileBuff, lpOldFileBuff, dwOldFileSize);
    if (lpDataBuff != NULL && dwDataSize != 0) {
        memcpy(((char*)lpNewFileBuff + dwOldFileSize), lpDataBuff, dwDataSize);
    }

    // ���PEͷ�Ƿ����㹻�ռ����ӽڱ���
    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)lpNewFileBuff;
    PIMAGE_NT_HEADERS pNewNtHeader = (PIMAGE_NT_HEADERS)((char*)pNewDosHeader + pNewDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pNewFileHeader = (PIMAGE_FILE_HEADER)(&pNewNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pNewOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNewNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pNewOptionHeader + pNewFileHeader->SizeOfOptionalHeader);

    DWORD dwReserved = pNewOptionHeader->SizeOfHeaders -
        ((DWORD)pNewSectionHeader + pNewFileHeader->NumberOfSections * 0x28 - (DWORD)pNewDosHeader);
    if (dwReserved < 0x28) {
        // �ռ䲻��ʱ������ѡ���������ƣ�ռ��DOS Stub�Ŀռ�
        free(lpNewFileBuff);
        return NULL;
    }

    // ��������ڱ����λ�ã������Ƿ�Ϊ0
    IMAGE_SECTION_HEADER structAddSection = { 0 };
    PIMAGE_SECTION_HEADER pAddSectionHeader = pNewSectionHeader + pNewFileHeader->NumberOfSections;
    if (memcmp(pAddSectionHeader, &structAddSection, sizeof(IMAGE_SECTION_HEADER)) != NULL) {
        // ���ܻḲ������ʱ��Ҳ����ѡ���������ƣ�ռ��DOS Stub�Ŀռ�
        free(lpNewFileBuff);
        return NULL;
    }

    // �����µĽڱ���
    DWORD dwLastSectionHeaderIndex = pNewFileHeader->NumberOfSections - 1;
    structAddSection.Misc.VirtualSize = GetAlignSize(dwDataSize, pOptionHeader->SectionAlignment);
    structAddSection.VirtualAddress = pNewSectionHeader[dwLastSectionHeaderIndex].VirtualAddress +
        GetAlignSize(pNewSectionHeader[dwLastSectionHeaderIndex].Misc.VirtualSize, pOptionHeader->SectionAlignment);

    structAddSection.SizeOfRawData = GetAlignSize(dwDataSize, pOptionHeader->FileAlignment);
    structAddSection.PointerToRawData = pNewSectionHeader[dwLastSectionHeaderIndex].PointerToRawData +
        GetAlignSize(pNewSectionHeader[dwLastSectionHeaderIndex].SizeOfRawData, pOptionHeader->FileAlignment);

    // �����½ڱ���ڱ�ĩβ
    memcpy(pAddSectionHeader, &structAddSection, sizeof(IMAGE_SECTION_HEADER));

    // �޸�PE������ֶΣ�SizeOfImage NumberOfSections
    pNewOptionHeader->SizeOfImage = pAddSectionHeader->VirtualAddress + pAddSectionHeader->Misc.VirtualSize;
    pNewFileHeader->NumberOfSections += 1;

    return lpNewFileBuff;
}


/*
�������ܣ�ͨ��ģ������ȡģ������
������
  hInst��Ŀ��ģ����
  lpModuleName�����������ҵ���ģ������
����ֵ��
  ͨ����������Ŀ��ģ�������
*/
void CPe::MyGetModuleName(HMODULE hInst, OUT LPSTR lpModuleName) {
    if (hInst == NULL)
        return;

    MY_LIST_ENTRY* pCurNode = NULL;
    MY_LIST_ENTRY* pPrevNode = NULL;
    MY_LIST_ENTRY* pNextNode = NULL;
    MY_LIST_ENTRY* pFirstNode = NULL;

    // ͨ��TEB��ȡģ����Ϣ��
    __asm {
        pushad;
        mov eax, fs: [0x18] ;   //teb
        mov eax, [eax + 0x30];  //peb
        mov eax, [eax + 0x0c];  //_PEB_LDR_DATA
        mov eax, [eax + 0x0c];  //ģ����Ϣ��_LIST_ENTRY,��ģ��
        mov pCurNode, eax;
        mov ebx, dword ptr[eax];
        mov pPrevNode, ebx;
        mov ebx, dword ptr[eax + 0x4];
        mov pNextNode, ebx;
        popad;
    }

    pFirstNode = pCurNode;
    if (pCurNode == NULL || pPrevNode == NULL || pNextNode == NULL) {
        return;
    }

    // ����ģ����Ϣ��
    MY_LIST_ENTRY* pTmp = NULL;
    while (pPrevNode != pFirstNode) {
        if (hInst == pCurNode->hInstance) {
            // �ҵ���Ŀ��ģ��Ľڵ�
            Pascal2CStr(lpModuleName, (char*)pCurNode->pUnicodeFileName, pCurNode->sLengthOfFile);
            return;
        }

        pTmp = pPrevNode;
        pCurNode = pTmp;
        pPrevNode = pTmp->Flink;
        pNextNode = pTmp->Blink;
    }
}



/*
�������ܣ�ͨ��ģ������ȡģ��·��
������
  hInst��Ŀ��ģ����
  lpModulePath�����������ҵ���ģ��·��
����ֵ��
  ͨ����������Ŀ��ģ���·��
*/
void CPe::MyGetModulePath(HMODULE hInst, OUT LPSTR lpModulePath) {
    if (hInst == NULL)
        return;

    MY_LIST_ENTRY* pCurNode = NULL;
    MY_LIST_ENTRY* pPrevNode = NULL;
    MY_LIST_ENTRY* pNextNode = NULL;
    MY_LIST_ENTRY* pFirstNode = NULL;

    // ͨ��TEB��ȡģ����Ϣ��
    __asm {
        pushad;
        mov eax, fs: [0x18] ;   //teb
        mov eax, [eax + 0x30];  //peb
        mov eax, [eax + 0x0c];  //_PEB_LDR_DATA
        mov eax, [eax + 0x0c];  //ģ����Ϣ��_LIST_ENTRY,��ģ��
        mov pCurNode, eax;
        mov ebx, dword ptr[eax];
        mov pPrevNode, ebx;
        mov ebx, dword ptr[eax + 0x4];
        mov pNextNode, ebx;
        popad;
    }

    pFirstNode = pCurNode;
    if (pCurNode == NULL || pPrevNode == NULL || pNextNode == NULL) {
        return;
    }

    // ����ģ����Ϣ��
    MY_LIST_ENTRY* pTmp = NULL;
    while (pPrevNode != pFirstNode) {
        if (hInst == pCurNode->hInstance) {
            // �ҵ���Ŀ��ģ��Ľڵ�
            Pascal2CStr(lpModulePath, (char*)pCurNode->pUnicodePathName, pCurNode->sLengthOfPath);
            return;
        }

        pTmp = pPrevNode;
        pCurNode = pTmp;
        pPrevNode = pTmp->Flink;
        pNextNode = pTmp->Blink;
    }
}



/*
�������ܣ���TEB�У�ͨ��ģ������/ģ��·����ȡģ����
������
  lpModuleName��ģ������/ģ��·��
����ֵ��
  �ɹ�����ģ����
  ʧ�ܷ���NULL��ģ����Ϣ���п���û��Ҫ���ҵ�ģ��
ע�⣺
  ���������ΪNULLʱ����ʾ��ȡ��ģ��ľ��
*/
HMODULE CPe::MyGetModuleBase(LPCSTR lpModuleName) {
    typedef HMODULE(WINAPI* PFN_LOADLIBRARYA)(LPCSTR);
    char szKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };

    MY_LIST_ENTRY* pCurNode = NULL;
    MY_LIST_ENTRY* pPrevNode = NULL;
    MY_LIST_ENTRY* pNextNode = NULL;
    MY_LIST_ENTRY* pFirstNode = NULL;

    // ͨ��TEB��ȡģ����Ϣ��
    __asm {
        pushad;
        mov eax, fs: [0x18] ;   //teb
        mov eax, [eax + 0x30];  //peb
        mov eax, [eax + 0x0c];  //_PEB_LDR_DATA
        mov eax, [eax + 0x0c];  //ģ����Ϣ��_LIST_ENTRY,��ģ��
        mov pCurNode, eax;
        mov ebx, dword ptr[eax];
        mov pPrevNode, ebx;
        mov ebx, dword ptr[eax + 0x4];
        mov pNextNode, ebx;
        popad;
    }

    pFirstNode = pCurNode;
    if (pCurNode == NULL || pPrevNode == NULL || pNextNode == NULL) {
        return NULL;
    }

    if (lpModuleName == NULL)
        return pCurNode->hInstance;

    // ����ģ����Ϣ��
    MY_LIST_ENTRY* pTmp = NULL;
    while (pPrevNode != pFirstNode) {
        // �Ƚ�ģ������
        if (CmpPascalStrWithCStr((char*)pCurNode->pUnicodeFileName, lpModuleName, MyStrLen(lpModuleName))) {
            return pCurNode->hInstance;
        }

        // �Ƚ�ģ��·��
        if (CmpPascalStrWithCStr((char*)pCurNode->pUnicodePathName, lpModuleName, MyStrLen(lpModuleName))) {
            return pCurNode->hInstance;
        }
        pTmp = pPrevNode;
        pCurNode = pTmp;
        pPrevNode = pTmp->Flink;
        pNextNode = pTmp->Blink;
    }

    HMODULE hKernel32 = MyGetModuleBase(szKernel32);
    PFN_LOADLIBRARYA  pfnLoadLibraryA = (PFN_LOADLIBRARYA)MyGetProcAddress(hKernel32, szLoadLibraryA);
    return  pfnLoadLibraryA(lpModuleName); // ģ����Ϣ����û��Ҫ���ҵ�ģ�飬����ϵͳLoadLibrary
}


/*
�������ܣ���ʵ�ֵ�LoadLibrary
������
  lpModulePath��ģ��·��
����ֵ��
  �ɹ�����ģ����
  ʧ�ܷ���NULL
*/
LPVOID CPe::MyLoadLibrary(LPCSTR lpModulePath) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hFileMap = NULL;
    LPVOID lpFileBuff = NULL;
    IMAGE_IMPORT_DESCRIPTOR ZeroImport = { 0 };
    DWORD dwRelocSize = 0;
    DWORD dwAddressOfEntryPoint = 0;

    typedef HMODULE(WINAPI* PFN_LOADLIBRARYA)(LPCSTR);
    char szKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };

    if (lpModulePath == NULL)
        return NULL;

    // ����ģ���б��в���ģ���Ƿ��Ѿ�����
    HMODULE hInst = (HMODULE)CPe::MyGetModuleBase(lpModulePath);
    if (hInst != NULL) {
        return hInst;
    }

    // LoadDll
    // ����Ƿ�ΪPE��ʽ
    if (IsPeFile(lpModulePath) != FILE_IS_PE) {
        return NULL;
    }

    // ���ļ�
    hFile = ::CreateFile(lpModulePath,           // �ļ�·��
        GENERIC_READ | GENERIC_WRITE,  // �ļ��Ĵ򿪷�ʽ
        FILE_SHARE_READ,        // ����ģʽ�������ļ��ɶ�
        NULL,                   // ��ȫ���ԣ�����ȷ�����صľ���Ƿ���Ա��ӽ��̼̳�
        OPEN_EXISTING,          // �򿪷�ʽ
        FILE_ATTRIBUTE_NORMAL,  // �ļ�����
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    // ��ȡ�ļ���С
    DWORD dwFileSize = ::GetFileSize(hFile, NULL);

    // �����ļ�ӳ�����
    hFileMap = ::CreateFileMapping(hFile,     // �ļ����
        NULL,      // ��ȫ���ԣ�����ȷ�����صľ���Ƿ���Ա��ӽ��̼̳�
        PAGE_READWRITE, // ӳ����ڴ�ҳ���ڴ�����
        NULL,      // ����4Gʱ����
        dwFileSize,// ӳ���С
        NULL);     // �ļ�ӳ���������ƣ����ú�����ڽ��̼�ͨ��
    if (hFileMap == NULL) {
        goto EXIT_PROC;
    }

    // ���ļ�ӳ�䵽�ڴ�
    lpFileBuff = ::MapViewOfFile(hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpFileBuff == NULL) {
        goto EXIT_PROC;
    }

    // PE ��ʽ����
    CPe* pDll = new CPe(lpFileBuff);
    DWORD dwSizeOfImage = pDll->GetSizeOfImage();

    // �����ڴ�ռ䣬����ͨ��ģ����Ϣ���ȡ������ַ
    LPVOID lpDllBuff = ::VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpDllBuff == NULL) {
        goto EXIT_PROC;
    }

    // ����PEͷ
    MyMemCopy(lpDllBuff, pDll->GetDosHeaderPointer(), pDll->GetSizeOfHeaders());

    // ����ڱ�
    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)pDll->GetSectionHeaderPointer();
    for (int i = 0; i < pDll->GetNumberOfSections(); ++i) {
        // �ж������ļ�ӳ��
        if (pSection[i].SizeOfRawData != 0) {
            MyMemCopy((char*)lpDllBuff + pSection[i].VirtualAddress,
                (char*)lpFileBuff + pSection[i].PointerToRawData,
                pSection[i].SizeOfRawData);
        }
    }

    // �޸������
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)pDll->GetImportDirectoryPointer();

    while (MyMemCmp(pImport, &ZeroImport, sizeof(IMAGE_IMPORT_DESCRIPTOR) != 0)) {
        // �ж��Ƿ���Ч�������
        if (*(DWORD*)((char*)lpDllBuff + pImport->FirstThunk) != NULL) {
            // �ж�INT�Ƿ�Ϊ�գ�INTΪ��ʱ��ʹ��IAT
            DWORD* pThunk = (DWORD*)((char*)lpDllBuff + pImport->OriginalFirstThunk);
            if (pImport->OriginalFirstThunk == NULL) {
                pThunk = (DWORD*)((char*)lpDllBuff + pImport->FirstThunk);
            }

            // ѭ��INT/IAT
            while (*pThunk != NULL) {
                LPVOID lpThunkData = NULL;
                // �ж���Original����Name
                if (((*pThunk) & 0x80000000) > 0) {
                    lpThunkData = (LPVOID)((*pThunk) & 0xffff);
                }
                else {
                    lpThunkData = (LPVOID)((char*)lpDllBuff + (*pThunk) + 2);
                }

                // ��ȡ������ַ
                HMODULE hKernel32 = MyGetModuleBase(szKernel32);
                PFN_LOADLIBRARYA  pfnLoadLibraryA = (PFN_LOADLIBRARYA)MyGetProcAddress(hKernel32, szLoadLibraryA);
                HMODULE hModule = pfnLoadLibraryA((char*)lpDllBuff + pImport->Name);
                LPVOID lpFunAddr = CPe::MyGetProcAddress(hModule, (LPCSTR)lpThunkData);

                // �IAT��
                *(DWORD*)((char*)lpDllBuff + pImport->FirstThunk) = (DWORD)lpFunAddr;

                pThunk++;
            }
        }
        pImport++;
    }

    // �޸��ض�λ����
    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)pDll->GetRelocDirectoryPointer();
    dwRelocSize = pDll->GetRelocDirectorySize();
    while (dwRelocSize != 0) {
        DWORD dwRelocPageRva = pReloc->VirtualAddress;
        DWORD dwSizeOfBlock = pReloc->SizeOfBlock;
        DWORD dwItemCount = (dwSizeOfBlock - 8) / 2;
        WORD* pItem = (WORD*)((char*)pReloc + 8);
        for (DWORD i = 0; i < dwItemCount; ++i) {
            WORD wItem = pItem[i];
            // �޸���ʽ
            if ((wItem >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                char* pDstData = (char*)lpDllBuff + (wItem & 0xfff) + dwRelocPageRva;
                *(DWORD*)pDstData = (DWORD)lpDllBuff - pDll->GetImageBase() + *(DWORD*)pDstData;
            }
        }

        dwRelocSize = dwRelocSize - dwSizeOfBlock;
        pReloc = (PIMAGE_BASE_RELOCATION)((char*)pReloc + dwSizeOfBlock);
    }

    // ����dllmain
    //dwAddressOfEntryPoint = pDll->GetAddressOfEntryPoint();
    //PFN_DLLMAIN pFnDllMain = (PFN_DLLMAIN)((char*)lpDllBuff + dwAddressOfEntryPoint);
    //pFnDllMain((HMODULE)lpDllBuff, DLL_PROCESS_ATTACH, NULL);

    if (lpFileBuff != NULL) {
        ::UnmapViewOfFile(lpFileBuff);
    }

    if (hFileMap != NULL) {
        ::CloseHandle(hFileMap);
    }

    if (hFile != INVALID_HANDLE_VALUE) {
        ::CloseHandle(hFile);
    }

    return lpDllBuff;

EXIT_PROC:
    if (lpFileBuff != NULL) {
        ::UnmapViewOfFile(lpFileBuff);
    }

    if (hFileMap != NULL) {
        ::CloseHandle(hFileMap);
    }

    if (hFile != INVALID_HANDLE_VALUE) {
        ::CloseHandle(hFile);
    }
    return NULL;
}


/*
�������ܣ�ͨ��������ַ��ȡ��������/���
������
  pfnAddr��Ŀ�꺯����ַ
����ֵ��
  �ɹ����غ������ƻ����
  ʧ�ܷ���NULL
*/
LPVOID CPe::MyGetProcFunName(LPVOID pfnAddr) {
    if (pfnAddr == NULL)
        return NULL;

    MY_LIST_ENTRY* pCurNode = NULL;
    MY_LIST_ENTRY* pPrevNode = NULL;
    MY_LIST_ENTRY* pNextNode = NULL;
    MY_LIST_ENTRY* pFirstNode = NULL;

    // ͨ��TEB��ȡģ����Ϣ��
    __asm {
        pushad;
        mov eax, fs: [0x18] ;   //teb
        mov eax, [eax + 0x30];  //peb
        mov eax, [eax + 0x0c];  //_PEB_LDR_DATA
        mov eax, [eax + 0x0c];  //ģ����Ϣ��_LIST_ENTRY,��ģ��
        mov pCurNode, eax;
        mov ebx, dword ptr[eax];
        mov pPrevNode, ebx;
        mov ebx, dword ptr[eax + 0x4];
        mov pNextNode, ebx;
        popad;
    }

    pFirstNode = pCurNode;
    if (pCurNode == NULL || pPrevNode == NULL || pNextNode == NULL) {
        return NULL;
    }

    // ����ģ����Ϣ����ģ��ĵ������в���
    HMODULE hModule = NULL;
    MY_LIST_ENTRY* pTmp = NULL;
    while (pPrevNode != pFirstNode) {
        hModule = pCurNode->hInstance;
        if (((DWORD)pfnAddr > (DWORD)hModule) &&
            ((DWORD)pfnAddr < (DWORD)hModule + pCurNode->nSizeOfImage)) {
            // �ҵ�������ַ���ڵ�ģ�飬�ٽ��е��������
            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
            PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
            PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
            PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);

            DWORD dwExportTableRva = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((char*)hModule + dwExportTableRva);

            // ��ȡ�ڴ��У����������������ĵ�ַ
            DWORD dwAddressOfFunctionsRva = pExport->AddressOfFunctions;
            DWORD dwAddressOfNamesRva = pExport->AddressOfNames;
            DWORD dwAddressOfNameOrdinalsRva = pExport->AddressOfNameOrdinals;
            DWORD* pAddressOfFunctions = (DWORD*)(dwAddressOfFunctionsRva + (char*)hModule);
            DWORD* pAddressOfNames = (DWORD*)(dwAddressOfNamesRva + (char*)hModule);
            WORD* pAddressOfNameOrdinals = (WORD*)(dwAddressOfNameOrdinalsRva + (char*)hModule);

            // ���Ȼ�ȡ������ַ�ڵ�����ַ���е�����
            DWORD dwIndex = -1;
            for (DWORD i = 0; i < pExport->NumberOfFunctions; ++i) {
                if ((pAddressOfFunctions[i] + (char*)hModule) == pfnAddr) {
                    dwIndex = i;
                    break;
                }
            }
            if (dwIndex == -1)
                return NULL;

            // ����������������ű����Ƿ���ڣ��������ʾ�����Ƶ�������������ŵ���
            for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
                if (pAddressOfNameOrdinals[i] == dwIndex) {
                    return pAddressOfNames[i] + (char*)hModule;
                }
            }
            return (LPVOID)(dwIndex + pExport->Base);
        }

        pTmp = pPrevNode;
        pCurNode = pTmp;
        pPrevNode = pTmp->Flink;
        pNextNode = pTmp->Blink;
    }
    return NULL;
}


/*
�������ܣ�ͨ����������/��ţ���ȡ������ַ
������
  hInst��     ģ����
  lpProcName����������/���
����ֵ��
  �ɹ����ز��ҵ��ĺ�����ַ
  ʧ�ܷ���NULL
*/
LPVOID CPe::MyGetProcAddress(HMODULE hInst, LPCSTR lpProcName) {
    if (hInst == NULL || lpProcName == NULL)
        return NULL;

    // ��ģ���ַ����PE��ʽ����
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hInst;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader +
        pFileHeader->SizeOfOptionalHeader);

    // ��ȡ�������λ��
    DWORD dwExportTableRva = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD dwExportTableSize = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((char*)hInst + dwExportTableRva);
    DWORD dwExportEnd = (DWORD)pExport + dwExportTableSize; // �����Ĵ�С�������ж��Ƿ�Ϊ����ת��

    // ��ȡ�ڴ��У����������������ĵ�ַ
    DWORD dwAddressOfFunctionsRva = pExport->AddressOfFunctions;
    DWORD dwAddressOfNamesRva = pExport->AddressOfNames;
    DWORD dwAddressOfNameOrdinalsRva = pExport->AddressOfNameOrdinals;
    DWORD* pAddressOfFunctions = (DWORD*)(dwAddressOfFunctionsRva + (char*)hInst);
    DWORD* pAddressOfNames = (DWORD*)(dwAddressOfNamesRva + (char*)hInst);
    WORD* pAddressOfNameOrdinals = (WORD*)(dwAddressOfNameOrdinalsRva + (char*)hInst);

    DWORD dwIndex = -1;
    // �����ж������ƻ������,�õ�AddressOfFunctions������
    if (((DWORD)lpProcName & 0xFFFF0000) > 0) {
        // ���Ʋ�ѯ�����Ȼ�ȡĿ�������ڵ������Ʊ��е�����
        for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
            char* pName = (pAddressOfNames[i] + (char*)hInst);
            if (MyMemCmp(pName, (void*)lpProcName, MyStrLen(lpProcName)) == 0 &&
                MyStrLen(lpProcName) == MyStrLen(pName)) {
                // �ҵ�Ŀ���ַ�����ͬ�±�ȥ����������ű��õ����յ�����
                dwIndex = pAddressOfNameOrdinals[i];
            }
        }
    }
    else {
        // ʹ����Ų�ѯʱ��the high-order word must be zero
        dwIndex = ((DWORD)lpProcName & 0xFFFF) - pExport->Base;
    }

    if (dwIndex == -1) {
        return NULL;
    }

    // �ж��Ƿ�Ϊ����ת��
    DWORD dwProcAddr = (DWORD)(pAddressOfFunctions[dwIndex] + (char*)hInst);
    if ((dwProcAddr >= (DWORD)pExport) && (dwProcAddr < dwExportEnd)) {
        // ����ǵ���ת��������Ҫ�ݹ���ң���Ӧ�ĵ�ַ�����ת����dll���ƺͺ�������
        char dllName[MAXBYTE];
        MyZeroMem(dllName, MAXBYTE);
        __asm {
            pushad;
            mov esi, dwProcAddr;
            lea edi, dllName;
            mov ecx, MAXBYTE;
            xor edx, edx;
        LOOP_BEGIN:
            mov dl, byte ptr ds : [esi] ;
            cmp dl, 0x2e;
            jz LOOP_END;
            movsb;
            loop LOOP_BEGIN;
        LOOP_END:
            inc esi;
            mov dwProcAddr, esi;
            popad;
        }

        HMODULE hModule = (HMODULE)MyGetModuleBase(dllName);
        return MyGetProcAddress(hModule, (char*)dwProcAddr); // �ݹ����
    }

    return (void*)dwProcAddr;
}


/*
�������ܣ������ע��
������
  lpFileBuff��PE�ļ����ڴ��ַ
  lpDllName ��ע���dll����
  lpProcName��ע��ĺ�������
����ֵ��
  �ɹ�����PE�ļ��µ��ڴ��ַ
  ʧ�ܷ���NULL
*/
LPVOID CPe::MyAddImportTableItem(LPVOID lpFileBuff, LPCSTR lpDllName, LPCSTR lpProcName) {
    if (lpFileBuff == NULL || lpDllName == NULL || lpProcName == NULL)
        return NULL;

    // PE��ʽ����
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuff;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

    // ��ȡ�ɵĵ�����λ�ú�����
    DWORD dwImportRva = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD dwImportFa = CPe::Rva2Fa(dwImportRva, lpFileBuff);
    LPVOID lpOldImportTable = (char*)lpFileBuff + dwImportFa;

    //
    DWORD dwOldImportCount = 0;
    IMAGE_IMPORT_DESCRIPTOR structAddImport = { 0 };
    PIMAGE_IMPORT_DESCRIPTOR lpTmp = (PIMAGE_IMPORT_DESCRIPTOR)lpOldImportTable;
    while (memcmp(lpTmp, &structAddImport, sizeof(IMAGE_IMPORT_DESCRIPTOR)) != 0) {
        dwOldImportCount++;
        lpTmp++;
    }

    // ����һ���½ڣ�ͬʱ��ԭ���ĵ���������½�
    DWORD dwOldFileSize = pSectionHeader[pFileHeader->NumberOfSections - 1].SizeOfRawData +
        pSectionHeader[pFileHeader->NumberOfSections - 1].PointerToRawData;
    LPVOID lpNewFileBuff = CPe::AddSection(lpFileBuff,
        dwOldFileSize,
        lpOldImportTable,
        dwOldImportCount * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    if (lpNewFileBuff == NULL) {
        // �����ڱ�ʧ��
        return NULL;
    }

    // ��ȡ�����ڱ���
    PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)lpNewFileBuff;
    PIMAGE_NT_HEADERS pNewNtHeader = (PIMAGE_NT_HEADERS)((char*)pNewDosHeader + pNewDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pNewFileHeader = (PIMAGE_FILE_HEADER)(&pNewNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pNewOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNewNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pNewOptionHeader + pNewFileHeader->SizeOfOptionalHeader);
    PIMAGE_SECTION_HEADER pAddSectionHeader = &pNewSectionHeader[pNewFileHeader->NumberOfSections - 1];
    DWORD dwAddSectionVirtualAddress = pAddSectionHeader->VirtualAddress;
    DWORD dwAddSectionPointerToRawData = pAddSectionHeader->PointerToRawData;

    // ���쵼�����Ҫ��dll���ƺ�ThunkData
    PIMAGE_IMPORT_DESCRIPTOR pNewImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pNewDosHeader + dwAddSectionPointerToRawData);

    PIMAGE_IMPORT_DESCRIPTOR pNewImportTableItem = pNewImportTable + dwOldImportCount;
    PVOID pDllName = (char*)(pNewImportTableItem + 2);
    PVOID pProcName = (char*)pDllName + strlen(lpDllName) + 0x10;
    PVOID pThunkData = (char*)pProcName + strlen(lpProcName) + 0x10;
    memcpy(pDllName, lpDllName, strlen(lpDllName) + 1);
    memcpy((char*)pProcName + 2, lpProcName, strlen(lpProcName) + 1);
    *(DWORD*)pThunkData = (DWORD)pProcName - (DWORD)lpNewFileBuff - dwAddSectionPointerToRawData + dwAddSectionVirtualAddress;

    // ����Ҫ���ӵĵ������ע����Rva
    structAddImport.OriginalFirstThunk = NULL;
    structAddImport.Name = (DWORD)pDllName - (DWORD)lpNewFileBuff - dwAddSectionPointerToRawData + dwAddSectionVirtualAddress;
    structAddImport.FirstThunk = (DWORD)pThunkData - (DWORD)lpNewFileBuff - dwAddSectionPointerToRawData + dwAddSectionVirtualAddress;

    // �������ĵ�������д�����������
    memcpy(pNewImportTableItem, &structAddImport, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    // �޸�����Ŀ¼�У�������Rva
    pNewOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
        (DWORD)pNewImportTable - (DWORD)lpNewFileBuff - dwAddSectionPointerToRawData + dwAddSectionVirtualAddress;

    return lpNewFileBuff;
}
