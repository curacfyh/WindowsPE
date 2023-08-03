//
// Created by Chou on 2023/7/27.
//

#ifndef PETOOL_PE_STRUCT_H
#define PETOOL_PE_STRUCT_H
typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;

struct _IMAGE_DOS_HEADER {
    WORD e_magic;  //MZ标记
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    DWORD e_lfanew;  //PE文件真正开始的偏移地址
};

//标准PE头
struct _IMAGE_FILE_HEADER {
    WORD Machine;  //文件运行平台
    WORD NumberOfSections;  //节数量
    DWORD TimeDateStamp;  //时间戳
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;  //可选PE头大小
    WORD Characteristics;  //特征值
};

//可选PE头
struct _IMAGE_OPTIONAL_HEADER {
    WORD Magic;  //文件类型
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;   //代码节文件对齐后的大小
    DWORD SizeOfInitializedData;  //初始化数据文件对齐后的大小
    DWORD SizeOfUninitializedData;  //未初始化数据文件对齐后大小
    DWORD AddressOfEntryPoint;  //程序入口点（偏移量）
    DWORD BaseOfCode;  //代码基址
    DWORD BaseOfData;  //数据基址
    DWORD ImageBase;   //内存镜像基址
    DWORD SectionAlignment;  //内存对齐粒度
    DWORD FileAlignment;  //文件对齐粒度
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;  //文件装入虚拟内存后大小
    DWORD SizeOfHeaders;  //DOS、NT头和节表大小
    DWORD CheckSum;  //校验和
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;  //预留堆栈大小
    DWORD SizeOfStackCommit;  //实际分配堆栈大小
    DWORD SizeOfHeapReserve;  //预留堆大小
    DWORD SizeOfHeapCommit;  //实际分配堆大小
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;  //目录项数目
    //_IMAGE_DATA_DIRECTORY DataDirectory[16];  //这个先不管
};

//NT头
struct _IMAGE_NT_HEADERS {
    DWORD Signature;  //PE签名
    struct _IMAGE_FILE_HEADER FileHeader;
    struct _IMAGE_OPTIONAL_HEADER OptionalHeader;
};

//节表
struct _IMAGE_SECTION_HEADER{
    BYTE Name[8];  //节表名
    union{
        DWORD PhysicalAddress;
        DWORD VirtualSize;  //内存中未对齐大小
    }Misc;
    DWORD VirtualAddress;  //该节在内存中偏移地址
    DWORD SizeOfRawData;  //该节在硬盘上文件对齐后大小
    DWORD PointerToRawData;  //该节在硬盘上文件对齐后偏移地址
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;  //该节特征属性
};

#endif //PETOOL_PE_STRUCT_H
