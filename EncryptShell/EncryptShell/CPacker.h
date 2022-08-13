#pragma once

#include <windows.h>
#include "CPe.h"
#include "MyLibC.h"


class CPacker {
public:
    CPacker();
    ~CPacker();

public:
    BOOL Pack(const char* pSrcPath, const char* pDstPath);

private:
    // PE���ݽ���
    CPe* m_PE;

private:
    // �������
    PBYTE m_pImportTableBuff;   // �����Զ���ĵ��������
    DWORD m_dwImportTableSize;  // ��������ݵĳ���
    DWORD MoveImportTable(PBYTE pImportTableBuff);    // �����Զ���ĵ����
    void  ClearImportTable();   // ���ԭ�����

private:
    // �ض�λ����
    PBYTE m_pRelocBuff;   // �����Զ�����ض�λ������
    DWORD m_dwRelocTableSize;  // �ض�λ�����ݵĳ���
    DWORD MoveRelocTable(PBYTE pRelocTableBuff);    // �����Զ�����ض�λ��
    void  ClearRelocTable();   // ���ԭ�ض�λ��

private:
    // ѹ���������
    BOOL  DoCompress();
    PBYTE m_pCompressDataBuff;  // ѹ�����ݵ��ڴ��ַ
    DWORD m_dwComDataAlignSize; // ѹ���������ļ�����ֵ������С
    DWORD m_dwComDataSize;      // ѹ�����ݵ���ʵ��С

private:
    // �Ǵ������
    BOOL  GetShellCode();
    PBYTE m_pShellCodeBuff;  // �Ǵ�����ڴ��ַ
    DWORD m_dwShellCodeSize; // �Ǵ������ļ�����ֵ������С

private:
    // �����µĽڱ�
    BOOL RebuildSection();
    enum SecHdrIdx {
        SHI_SPACE,
        SHI_CODE,
        SHI_COM,
        SHI_COUT
    };
    IMAGE_SECTION_HEADER m_NewSecHdrs[SHI_COUT];  // �µĽڱ�

    // �����µ�PEͷ
    BOOL  RebuildPeHeader();
    PBYTE m_pNewPeHeader;      // PE��Header���ڴ��ַ
    DWORD m_dwNewPeHeaderSize; // PE��Header���ļ�����ֵ������С

private:
    // д���µ�PE������
    BOOL WritePackerFile(const char* pDstPath);
};

