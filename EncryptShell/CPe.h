#pragma once

#pragma once
#include <Windows.h>


/*
ģ����Ϣ��{
  +0  //ǰһ����ĵ�ַ
  +4  //��һ����ĵ�ַ
  +18 //��ǰģ��Ļ�ַ hInstance
  +1C //ģ�����ڵ�
  +20 //SizeOfImage
  +24 //Rtl��ʽ��unicode�ַ�����������ģ���·��
      {
        +0 //�ַ���ʵ�ʳ���
        +2 //�ַ�����ռ�Ŀռ��С
        +4 //unicode�ַ����ĵ�ַ
      }
  +2C //Rtl��ʽ��unicode�ַ�����������ģ�������
      {
        +0 //�ַ���ʵ�ʳ���
        +2 //�ַ�����ռ�Ŀռ��С
        +4 //unicode�ַ����ĵ�ַ
      }
}
*/
struct MY_LIST_ENTRY {
    struct MY_LIST_ENTRY* Flink;  //0x0
    struct MY_LIST_ENTRY* Blink;  //0x4
    int n1;    //0x8
    int n2;    //0xC
    int n3;    //0x10
    int n4;    //0x14
    HMODULE hInstance;      //0x18
    void* pEntryPoint;      //0x1C
    int nSizeOfImage;       //0x20

    short sLengthOfPath;    //0x24
    short sSizeOfPath;      //0x26
    int* pUnicodePathName;  //0x28

    short sLengthOfFile;    //0x2C
    short sSizeOfFile;      //0x2E
    int* pUnicodeFileName;  //0x30
};


#define OUT
#define IN
#define INOUT

class CPe {
public:
    CPe();
    CPe(void* pFileBuff);
    CPe(const char* strFilePath);
    ~CPe();

private:
    HANDLE m_hFile;
    HANDLE m_hFileMap;
    DWORD  m_dwFileSize;
    LPVOID m_lpFileBuff;
    BOOL   m_bIsMemInit; // �������ʱ��������ڴ��ַ������Ҫȡ���ļ�ӳ��

private:
    void Init();
    void InitPeFormat(void* pFileBuff);
    void InitPeFormat(const char* strFilePath);

public:
    // �ļ��������
    enum {
        FIlE_OPEN_FAILD,
        FIlE_WRITE_FAILD,
        FIlE_WRITE_SUC,
        FILE_NOT_PE,
        FILE_IS_PE
    };
    static int  IsPeFile(void* pFileBuff);
    static int  IsPeFile(const char* strFilePath);
    // static BOOL IsCanPack(const char* strFilePath);
    static int  WriteMemoryToFile(void* pFileBuff, int nFileSize, const char* strFilePath);
    DWORD GetFileSize();

public:
    // PEͷ������
    LPVOID GetDosHeaderPointer() const;
    LPVOID GetNtHeaderPointer() const;
    LPVOID GetFileHeaderPointer() const;
    LPVOID GetOptionHeaderPointer() const;
    LPVOID GetSectionHeaderPointer() const;

    LPVOID GetExportDirectoryPointer() const;
    LPVOID GetImportDirectoryPointer() const;
    LPVOID GetResourceDirectoryPointer() const;
    LPVOID GetRelocDirectoryPointer() const;
    LPVOID GetTlsDirectoryPointer() const;

    DWORD  GetExportDirectorySize() const;
    DWORD  GetRelocDirectorySize() const;

private:
    PIMAGE_DOS_HEADER      m_pDosHeader;
    PIMAGE_NT_HEADERS      m_pNtHeader;
    PIMAGE_FILE_HEADER     m_pFileHeader;
    PIMAGE_OPTIONAL_HEADER m_pOptionHeader;
    PIMAGE_SECTION_HEADER  m_pSectionHeader;

    PIMAGE_EXPORT_DIRECTORY   m_pExportDirectory;   // ������λ������Ŀ¼��0��
    PIMAGE_IMPORT_DESCRIPTOR  m_pImportDirectory;   // �����λ������Ŀ¼��1��
    PIMAGE_RESOURCE_DIRECTORY m_pResourceDirectory; // ��Դ��λ������Ŀ¼��2��
    PIMAGE_BASE_RELOCATION    m_pRelocDirectory;    // �ض�λ��λ������Ŀ¼��5��
    PIMAGE_TLS_DIRECTORY      m_pTlsDirectory;      // TLSλ������Ŀ¼��9��

    DWORD m_dwExportSize; // �������size�����õ�
    DWORD m_dwImportSize; // importʹ��ȫ0�ṹ��β
    DWORD m_dwRelocSize;  // �ض�λ���size�����õģ�����ʱ������

public:
    // PE�ṹ������Ҫ�ֶ�
    WORD  GetNumberOfSections() const;
    DWORD GetAddressOfEntryPoint() const;
    DWORD GetImageBase() const;
    DWORD GetSectionAlignment() const;
    DWORD GetFileAlignment() const;
    DWORD GetSizeOfImage() const;
    DWORD GetSizeOfHeaders() const;
    DWORD GetNumberOfRvaAndSizes() const;

private:
    WORD  m_wNumberOfSections;      // �ڱ�ĸ���
    DWORD m_dwAddressOfEntryPoint;  // ������ڵ㣬RVA
    DWORD m_dwImageBase;            // ����Ľ���װ�ص�ַ
    DWORD m_dwSectionAlignment;     // ���ڴ��еĶ��� 
    DWORD m_dwFileAlignment;        // ���ļ��еĶ���
    DWORD m_dwSizeOfImage;          // �ļ������ڴ沢�����Ĵ�С
    DWORD m_dwSizeOfHeaders;        // PEͷ�Ĵ�С
    DWORD m_dwNumberOfRvaAndSizes;  // ����Ŀ¼�ĸ���

public:
    // ���ܷ���
    static DWORD Rva2Fa(DWORD dwRva, LPVOID lpFileBuff);
    static DWORD GetAlignSize(DWORD dwDataSize, DWORD dwAlign);

    // �����
    static LPVOID AddSection(LPVOID lpOldFileBuff, DWORD dwOldFileSize,
        LPVOID lpDataBuff = NULL, DWORD dwDataSize = NULL); // ����Section

    // ���������
    static void MyGetModuleName(HMODULE hInst, OUT LPSTR lpModuleName);  // ͨ��ģ������ȡģ������
    static void MyGetModulePath(HMODULE hInst, OUT LPSTR lpModulePath);  // ͨ��ģ������ȡģ��·��
    static HMODULE MyGetModuleBase(LPCSTR lpModuleName);               // ͨ��ģ������/·����ȡģ����
    static LPVOID  MyLoadLibrary(LPCSTR lpModulePath);                 // ��ʵ�ֵ�LoadLibrary��ֻ֧�ִ���ģ��·��
    static LPVOID  MyGetProcFunName(LPVOID pfnAddr);                   // ͨ��������ַ��ȡ��������/���
    static LPVOID  MyGetProcAddress(HMODULE hInst, LPCSTR lpProcName); // ��ʵ�ֵ�GetProcAddress

    // ��������
    static LPVOID MyAddImportTableItem(LPVOID lpFileBuff, LPCSTR lpDllName, LPCSTR lpProcName); // ���ӵ����
};

