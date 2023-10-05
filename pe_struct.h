//
// Created by Chou on 2023/7/27.
//

#ifndef PETOOL_PE_STRUCT_H
#define PETOOL_PE_STRUCT_H
typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;

struct _IMAGE_DOS_HEADER {
    WORD e_magic;  //MZ���
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
    DWORD e_lfanew;  //PE�ļ�������ʼ��ƫ�Ƶ�ַ
};

//��׼PEͷ
struct _IMAGE_FILE_HEADER {
    WORD Machine;  //�ļ�����ƽ̨
    WORD NumberOfSections;  //������
    DWORD TimeDateStamp;  //ʱ���
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;  //��ѡPEͷ��С
    WORD Characteristics;  //����ֵ
};

//����Ŀ¼
struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
};

//��ѡPEͷ
struct _IMAGE_OPTIONAL_HEADER {
    WORD Magic;  //�ļ�����
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;   //������ļ������Ĵ�С
    DWORD SizeOfInitializedData;  //��ʼ�������ļ������Ĵ�С
    DWORD SizeOfUninitializedData;  //δ��ʼ�������ļ�������С
    DWORD AddressOfEntryPoint;  //������ڵ㣨ƫ������
    DWORD BaseOfCode;  //�����ַ
    DWORD BaseOfData;  //���ݻ�ַ
    DWORD ImageBase;   //�ڴ澵���ַ
    DWORD SectionAlignment;  //�ڴ��������
    DWORD FileAlignment;  //�ļ���������
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;  //�ļ�װ�������ڴ���С
    DWORD SizeOfHeaders;  //DOS��NTͷ�ͽڱ��С
    DWORD CheckSum;  //У���
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;  //Ԥ����ջ��С
    DWORD SizeOfStackCommit;  //ʵ�ʷ����ջ��С
    DWORD SizeOfHeapReserve;  //Ԥ���Ѵ�С
    DWORD SizeOfHeapCommit;  //ʵ�ʷ���Ѵ�С
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;  //Ŀ¼����Ŀ
    struct _IMAGE_DATA_DIRECTORY DataDirectory[16];
};

//NTͷ
struct _IMAGE_NT_HEADERS {
    DWORD Signature;  //PEǩ��
    struct _IMAGE_FILE_HEADER FileHeader;
    struct _IMAGE_OPTIONAL_HEADER OptionalHeader;
};

//�ڱ�
struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];  //�ڱ���
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;  //�ڴ���δ�����С
    } Misc;
    DWORD VirtualAddress;  //�ý����ڴ���ƫ�Ƶ�ַ
    DWORD SizeOfRawData;  //�ý���Ӳ�����ļ�������С
    DWORD PointerToRawData;  //�ý���Ӳ�����ļ������ƫ�Ƶ�ַ
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;  //�ý���������
};

//������
struct _IMAGE_EXPORT_DIRECTORY {   //40�ֽ�
    DWORD Characteristics;  //δʹ��
    DWORD TimeDateStamp;  //ʱ���
    WORD MajorVersion;  //δʹ��
    WORD MinorVersion;    //δʹ��
    DWORD Name;  //ָ��õ������ļ����ַ���  *
    DWORD Base;  //����������ʼ���  *
    DWORD NumberOfFunctions;  //���е��������ĸ���  *
    DWORD NumberOfNames;  //�Ժ������ֵ����ĺ�������  *
    DWORD AddressOfFunctions;  //����������ַ��RVA  *
    DWORD AddressOfNames;  //�����������Ʊ�RVA  *
    DWORD AddressOfNameOrdinals;  //����������ű�RVA  *
};

//�ض�λ��
struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
};

//������кܶ�����ֽṹ����ԱȫΪ0����ʾ������
struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;  //RVA��ָ��IMAGE_THUNK_DATA�ṹ���飨INT��
    };
    DWORD TimeDateStamp;  //ʱ���	�������ж��Ƿ��а󶨵����/IAT�����Ƿ��Ѿ��󶨾��Ե�ַ��
    DWORD ForwarderChain;
    DWORD Name;  //RVA��ָ��dll�����ַ����洢��ַ
    DWORD FirstThunk;  //RVA,ָ��IMAGE_THUNK_DATA�ṹ���飨IAT��
};

//INT�������ǰIAT��
struct _IMAGE_THUNK_DATA32 {
    union {
        BYTE ForwarderString;
        DWORD Function;
        DWORD Ordinal;  //���
        struct _IMAGE_IMPORT_BY_NAME *AddressOfData;  //RVA��ָ��IMAGE_IMPORT_BY_NAME
    };
};

struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;  //����Ϊ�գ��������������������Ϊ�գ���ʾ�����ڵ������е�����
    BYTE Name[1];  //�������ƣ���0��β
};

struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD TimeDateStamp;  //ʱ���
    WORD OffsetModuleName;    //DLL������RVA���ӵ�һ���ṹ��RVA�����ַ�������RVA��������棩
    WORD NumberOfModuleForwarderRefs;  //����󶨵����ṹ���滹�м���_IMAGE_BOUND_FORWARDER_REF���ֽṹ
};  //�󶨵�����кܶ����ֽṹ����_IMAGE_BOUND_FORWARDER_REF���ֽṹ����������sizeof(_IMAGE_BOUND_IMPORT_DESCRIPTOR)��0����ʾ�󶨵�������

struct _IMAGE_BOUND_FORWARDER_REF {
    DWORD TimeDateStamp;  //ʱ���
    WORD OffsetModuleName;  //��ӦDLL������
    WORD Reserved;  //������δʹ�ã�
};

typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD Characteristics;                        //��Դ����  ���� 0
    DWORD TimeDateStamp;                        //��Դ������ʱ��
    WORD MajorVersion;                        //��Դ�汾�� δʹ�� 0
    WORD MinorVersion;                        //��Դ�汾�� δʹ�� 0
    WORD NumberOfNamedEntries;                        //��������������Դ����
    WORD NumberOfIdEntries;                        //��ID��������Դ����
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union {                        //Ŀ¼������ơ�����ID
        struct {
            DWORD NameOffset: 31;
            DWORD NameIsString: 1;
        };
        DWORD Name;
        WORD Id;
    };
    union {
        DWORD OffsetToData;                        //Ŀ¼��ָ��
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
