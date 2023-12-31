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

//数据目录
struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
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
    struct _IMAGE_DATA_DIRECTORY DataDirectory[16];
};

//NT头
struct _IMAGE_NT_HEADERS {
    DWORD Signature;  //PE签名
    struct _IMAGE_FILE_HEADER FileHeader;
    struct _IMAGE_OPTIONAL_HEADER OptionalHeader;
};

//节表
struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];  //节表名
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;  //内存中未对齐大小
    } Misc;
    DWORD VirtualAddress;  //该节在内存中偏移地址
    DWORD SizeOfRawData;  //该节在硬盘上文件对齐后大小
    DWORD PointerToRawData;  //该节在硬盘上文件对齐后偏移地址
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;  //该节特征属性
};

//导出表
struct _IMAGE_EXPORT_DIRECTORY {   //40字节
    DWORD Characteristics;  //未使用
    DWORD TimeDateStamp;  //时间戳
    WORD MajorVersion;  //未使用
    WORD MinorVersion;    //未使用
    DWORD Name;  //指向该导出表文件名字符串  *
    DWORD Base;  //导出函数起始序号  *
    DWORD NumberOfFunctions;  //所有导出函数的个数  *
    DWORD NumberOfNames;  //以函数名字导出的函数个数  *
    DWORD AddressOfFunctions;  //导出函数地址表RVA  *
    DWORD AddressOfNames;  //导出函数名称表RVA  *
    DWORD AddressOfNameOrdinals;  //导出函数序号表RVA  *
};

//重定位表
struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
};

//导入表，有很多个这种结构（成员全为0，表示结束）
struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;  //RVA，指向IMAGE_THUNK_DATA结构数组（INT表）
    };
    DWORD TimeDateStamp;  //时间戳	（用于判断是否有绑定导入表/IAT表中是否已经绑定绝对地址）
    DWORD ForwarderChain;
    DWORD Name;  //RVA，指向dll名字字符串存储地址
    DWORD FirstThunk;  //RVA,指向IMAGE_THUNK_DATA结构数组（IAT表）
};

//INT表和运行前IAT表
struct _IMAGE_THUNK_DATA32 {
    union {
        BYTE ForwarderString;
        DWORD Function;
        DWORD Ordinal;  //序号
        struct _IMAGE_IMPORT_BY_NAME *AddressOfData;  //RVA，指向IMAGE_IMPORT_BY_NAME
    };
};

struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;  //可能为空（编译器决定）；如果不为空，表示函数在导出表中的索引
    BYTE Name[1];  //函数名称，以0结尾
};

struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD TimeDateStamp;  //时间戳
    WORD OffsetModuleName;    //DLL的名字RVA（加第一个结构中RVA才是字符串真正RVA，详见下面）
    WORD NumberOfModuleForwarderRefs;  //这个绑定导入表结构后面还有几个_IMAGE_BOUND_FORWARDER_REF这种结构
};  //绑定导入表有很多这种结构或者_IMAGE_BOUND_FORWARDER_REF这种结构，最后如果有sizeof(_IMAGE_BOUND_IMPORT_DESCRIPTOR)个0，表示绑定导入表结束

struct _IMAGE_BOUND_FORWARDER_REF {
    DWORD TimeDateStamp;  //时间戳
    WORD OffsetModuleName;  //对应DLL的名字
    WORD Reserved;  //保留（未使用）
};

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD Characteristics;                        //资源属性  保留 0
    DWORD TimeDateStamp;                        //资源创建的时间
    WORD MajorVersion;                        //资源版本号 未使用 0
    WORD MinorVersion;                        //资源版本号 未使用 0
    WORD NumberOfNamedEntries;                        //以名称命名的资源数量
    WORD NumberOfIdEntries;                        //以ID命名的资源数量
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {                        //目录项的名称、或者ID
        struct {
            DWORD NameOffset: 31;
            DWORD NameIsString: 1;
        };
        DWORD Name;
        WORD Id;
    };
    union {
        DWORD OffsetToData;                        //目录项指针
        struct {
            DWORD OffsetToDirectory: 31;
            DWORD DataIsDirectory: 1;
        };
    };
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
    WORD Length;
    wchar_t NameString[1];
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;

typedef struct _IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#endif //PETOOL_PE_STRUCT_H
