#pragma once
#include <Windows.h>


/*
模块信息表{
  +0  //前一个表的地址
  +4  //后一个表的地址
  +18 //当前模块的基址 hInstance
  +1C //模块的入口点
  +20 //SizeOfImage
  +24 //Rtl格式的unicode字符串，保存了模块的路径
      {
        +0 //字符串实际长度
        +2 //字符串所占的空间大小
        +4 //unicode字符串的地址
      }
  +2C //Rtl格式的unicode字符串，保存了模块的名称
      {
        +0 //字符串实际长度
        +2 //字符串所占的空间大小
        +4 //unicode字符串的地址
      }
}
*/
struct MY_LIST_ENTRY
{
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

class CMyPe
{
public:
    CMyPe();
    CMyPe(void* pFileBuff);
    CMyPe(const char* strFilePath);
    ~CMyPe();

private:
    HANDLE m_hFile;
    HANDLE m_hFileMap;
    DWORD  m_dwFileSize;
    LPVOID m_lpFileBuff;
    BOOL   m_bIsMemInit; // 如果构造时传入的是内存地址，则不需要取消文件映射

private:
    void Init();
    void InitPeFormat(void* pFileBuff);
    void InitPeFormat(const char* strFilePath);

public:
    // 文件操作相关
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
    // PE头部数据
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

    PIMAGE_EXPORT_DIRECTORY   m_pExportDirectory;   // 导出表位于数据目录第0项
    PIMAGE_IMPORT_DESCRIPTOR  m_pImportDirectory;   // 导入表位于数据目录第1项
    PIMAGE_RESOURCE_DIRECTORY m_pResourceDirectory; // 资源表位于数据目录第2项
    PIMAGE_BASE_RELOCATION    m_pRelocDirectory;    // 重定位表位于数据目录第5项
    PIMAGE_TLS_DIRECTORY      m_pTlsDirectory;      // TLS位于数据目录第9项

    DWORD m_dwExportSize; // 导出表的size是有用的
    DWORD m_dwImportSize; // import使用全0结构结尾
    DWORD m_dwRelocSize;  // 重定位表的size是有用的，遍历时会用上

public:
    // PE结构部分重要字段
    WORD  GetNumberOfSections() const;
    DWORD GetAddressOfEntryPoint() const;
    DWORD GetImageBase() const;
    DWORD GetSectionAlignment() const;
    DWORD GetFileAlignment() const;
    DWORD GetSizeOfImage() const;
    DWORD GetSizeOfHeaders() const;
    DWORD GetNumberOfRvaAndSizes() const;

private:
    WORD  m_wNumberOfSections;      // 节表的个数
    DWORD m_dwAddressOfEntryPoint;  // 程序入口点，RVA
    DWORD m_dwImageBase;            // 程序的建议装载地址
    DWORD m_dwSectionAlignment;     // 在内存中的对齐 
    DWORD m_dwFileAlignment;        // 在文件中的对齐
    DWORD m_dwSizeOfImage;          // 文件载入内存并对齐后的大小
    DWORD m_dwSizeOfHeaders;        // PE头的大小
    DWORD m_dwNumberOfRvaAndSizes;  // 数据目录的个数

public:
    // 功能方法
    static DWORD Rva2Fa(DWORD dwRva, LPVOID lpFileBuff);
    static DWORD GetAlignSize(DWORD dwDataSize, DWORD dwAlign);

    // 节相关
    static LPVOID AddSection(LPVOID lpOldFileBuff, DWORD dwOldFileSize, 
        LPVOID lpDataBuff = NULL, DWORD dwDataSize = NULL); // 新增Section

    // 导出表相关
    static void MyGetModuleName(HMODULE hInst, OUT LPSTR lpModuleName);  // 通过模块句柄获取模块名称
    static void MyGetModulePath(HMODULE hInst, OUT LPSTR lpModulePath);  // 通过模块句柄获取模块路径
    static HMODULE MyGetModuleBase(LPCSTR lpModuleName);               // 通过模块名称/路径获取模块句柄
    static LPVOID  MyLoadLibrary(LPCSTR lpModulePath);                 // 自实现的LoadLibrary，只支持传入模块路径
    static LPVOID  MyGetProcFunName(LPVOID pfnAddr);                   // 通过函数地址获取函数名称/序号
    static LPVOID  MyGetProcAddress(HMODULE hInst, LPCSTR lpProcName); // 自实现的GetProcAddress

    // 导入表相关
    static LPVOID MyAddImportTableItem(LPVOID lpFileBuff, LPCSTR lpDllName, LPCSTR lpProcName); // 增加导入表
};

