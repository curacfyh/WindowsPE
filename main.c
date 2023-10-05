#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe_struct.h"
#include "Utils.h"

long fileSize;
BYTE *fileBuffer;
BYTE *imageBuffer;
BYTE *newBuffer;
DWORD newBufferSize;

const DWORD messageboxAddr = 0x76330C10;

const struct _IMAGE_DOS_HEADER *gFileDosHeader;
const struct _IMAGE_NT_HEADERS *gFileNtHeaders;
const struct _IMAGE_FILE_HEADER *gFileFileHeader;
const struct _IMAGE_OPTIONAL_HEADER *gFileOptionalHeader;
const struct _IMAGE_SECTION_HEADER *gFileSectionHeader;
PIMAGE_RESOURCE_DIRECTORY gFileResourceDirectory;

const struct _IMAGE_DOS_HEADER *gImageDosHeader;
const struct _IMAGE_NT_HEADERS *gImageNtHeaders;
const struct _IMAGE_FILE_HEADER *gImageFileHeader;
const struct _IMAGE_OPTIONAL_HEADER *gImageOptionalHeader;
const struct _IMAGE_SECTION_HEADER *gImageSectionHeader;

struct _IMAGE_DOS_HEADER *gNewDosHeader;
struct _IMAGE_NT_HEADERS *gNewNtHeaders;
struct _IMAGE_FILE_HEADER *gNewFileHeader;
struct _IMAGE_OPTIONAL_HEADER *gNewOptionalHeader;
struct _IMAGE_SECTION_HEADER *gNewSectionHeader;

void initialFileHeader() {
    gFileDosHeader = (struct _IMAGE_DOS_HEADER *) fileBuffer;
    gFileNtHeaders = (struct _IMAGE_NT_HEADERS *) (fileBuffer + gFileDosHeader->e_lfanew);
    gFileFileHeader = &(gFileNtHeaders->FileHeader);
    gFileOptionalHeader = &(gFileNtHeaders->OptionalHeader);
    gFileSectionHeader = (struct _IMAGE_SECTION_HEADER *) ((BYTE *) gFileOptionalHeader +
                                                           gFileFileHeader->SizeOfOptionalHeader);
}

void initialImageHeader() {
    gImageDosHeader = (struct _IMAGE_DOS_HEADER *) imageBuffer;
    gImageNtHeaders = (struct _IMAGE_NT_HEADERS *) (imageBuffer + gImageDosHeader->e_lfanew);
    gImageFileHeader = &(gImageNtHeaders->FileHeader);
    gImageOptionalHeader = &(gImageNtHeaders->OptionalHeader);
    gImageSectionHeader = (struct _IMAGE_SECTION_HEADER *) ((BYTE *) gImageOptionalHeader +
                                                            gImageFileHeader->SizeOfOptionalHeader);
}

void initialNewBufferHeader() {
    gNewDosHeader = (struct _IMAGE_DOS_HEADER *) newBuffer;
    gNewNtHeaders = (struct _IMAGE_NT_HEADERS *) (newBuffer + gNewDosHeader->e_lfanew);
    gNewFileHeader = &(gNewNtHeaders->FileHeader);
    gNewOptionalHeader = &(gNewNtHeaders->OptionalHeader);
    gNewSectionHeader = (struct _IMAGE_SECTION_HEADER *) ((BYTE *) gNewOptionalHeader +
                                                          gNewFileHeader->SizeOfOptionalHeader);
}

// ��ȡ�ļ��������ļ���ͷָ��
void readFile(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        printf("Failed to open file: %s\n", filename);
        exit(1);
    }
    // ��ȡ�ļ���С
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);  // ���ļ�ָ���ƻ��ļ���ʼ
    if (fileSize < 0) {
        printf("Failed to get file size.\n");
        fclose(file);
        return;
    }
    // �����ڴ棬��ȡ�ļ�����
    fileBuffer = (BYTE *) malloc(fileSize);
    if (fileBuffer == NULL) {
        printf("Failed to allocate memory.\n");
        fclose(file);
        return;
    }
    size_t numRead = fread(fileBuffer, 1, fileSize, file);
    if (numRead != fileSize) {
        printf("Failed to read file.\n");
        fclose(file);
        return;
    }
    fclose(file);
    initialFileHeader();
}

void printPEHeader() {
    printf("e_magic: %04x\n", gFileDosHeader->e_magic);
    printf("e_lfanew: %08x\n", gFileDosHeader->e_lfanew);
    printf("Signature: %04x\n", gFileNtHeaders->Signature);
    printf("Machine: %04x\n", gFileFileHeader->Machine);
    printf("Magic: %04x\n", gFileOptionalHeader->Magic);
}

void printSectionTable() {
    printf("section name:%s\n", gFileSectionHeader->Name);
    printf("PointerToRawData:%08x\n", gFileSectionHeader->PointerToRawData);
}

void fileBufferToImageBuffer() {
    DWORD sizeOfImage = gFileOptionalHeader->SizeOfImage;
    imageBuffer = (BYTE *) malloc(sizeOfImage);
    if (imageBuffer == NULL) {
        printf("Failed to allocate memory for imageBuffer.\n");
        return;
    }
    memset(imageBuffer, 0x00, sizeOfImage);
    //����ͷ�ͽڱ�
    memcpy(imageBuffer, fileBuffer, gFileOptionalHeader->SizeOfHeaders);
    //��������
    WORD numOfSections = gFileFileHeader->NumberOfSections;
    for (int i = 0; i < numOfSections; ++i) {
        const struct _IMAGE_SECTION_HEADER *curSectionHeader = gFileSectionHeader + i;
        //������ʼλ��
        BYTE *pFileSection = (BYTE *) fileBuffer + curSectionHeader->PointerToRawData;
        BYTE *pImageSection = (BYTE *) imageBuffer + curSectionHeader->VirtualAddress;
        memcpy(pImageSection, pFileSection, curSectionHeader->Misc.VirtualSize);
    }
}

void implantCode() {
    //׼��Ҫֲ��Ĵ��� 6A 00 6A 00 6A 00 6A 00 E8 XX XX XX XX E9 XX XX XX XX����18�ֽڣ�push call jmp
    BYTE codePush[] = {0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00};
    BYTE codeE8 = 0xE8;
    BYTE codeE9 = 0xE9;
    //���ҿհ���������ʹ�õ�һ�����������Ŀհ�����Ȼ�󿴿հ����Ƿ񹻷Ŵ���
    DWORD blankSize = gNewSectionHeader->SizeOfRawData - gNewSectionHeader->VirtualAddress;
    if (blankSize < 18) {
        printf("�հ�������ֲ����롣\n");
        exit(1);
    }
    //�ҳ��հ�����ƫ�Ƶ�ַ
    DWORD blankFileOffset = gNewSectionHeader->PointerToRawData + gNewSectionHeader->Misc.VirtualSize;
    DWORD blankVirtualOffset = gNewSectionHeader->VirtualAddress + gNewSectionHeader->Misc.VirtualSize;
    //����E8�����ƫ����
    //messageBoxA�ĵ�ַ�Ǿ��Ե�ַ�����Բ�������������ַҲ�þ��Ե�ַ��ע�������ַ���ܻ��
    //E8ָ��֮��ĵ�ַ=blankVirtualOffset+8+5+imageBase
    DWORD E8AppendOffset = messageboxAddr - (blankVirtualOffset + 8 + 5 + 0x00400000);
    printf("E8 offset: 0x%08x\n", E8AppendOffset);
    //����E9�����ƫ��������ԭ����EOP 0x000E1D80�����Ǹ��ļ���ַƫ������ע�������ַ���ܻ��
    DWORD E9AppendOffset = 0x000E1D80 - (blankVirtualOffset + 18);
    printf("E9 offset: 0x%08x\n", E9AppendOffset);
    //ֲ�����
    memcpy(newBuffer + blankFileOffset, codePush, 8);
    memcpy(newBuffer + blankFileOffset + 8, &codeE8, 1);
    memcpy(newBuffer + blankFileOffset + 9, &E8AppendOffset, 4);
    memcpy(newBuffer + blankFileOffset + 13, &codeE9, 1);
    memcpy(newBuffer + blankFileOffset + 14, &E9AppendOffset, 4);
    //�޸�OEPΪֲ������λ�á�ע��OEP�Ǹ��ڴ�ƫ�Ƶ�ַ
    memcpy(newBuffer + gNewDosHeader->e_lfanew + 4 + 20 + 16, &blankVirtualOffset, 4);
}

//�κ�ƫ��λ��ֲ����롣sectionIdxΪ������������0��ʼ��offsetInSectionΪ��Խ�����ʼλ�õ�ƫ����
void implantCodeAtPos(const DWORD sectionIdx, const DWORD offsetInSection) {
    //׼��Ҫֲ��Ĵ��� 6A 00 6A 00 6A 00 6A 00 E8 XX XX XX XX E9 XX XX XX XX����18�ֽڣ�push call jmp
    BYTE codePush[] = {0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00};
    BYTE codeE8 = 0xE8;
    BYTE codeE9 = 0xE9;
    //ֲ�����λ�õ��ڴ�ƫ�Ƶ�ַ���ļ�ƫ�Ƶ�ַ
    DWORD virtualOffset = (gNewSectionHeader + sectionIdx)->VirtualAddress + offsetInSection;
    DWORD fileOffSet = (gNewSectionHeader + sectionIdx)->PointerToRawData + offsetInSection;
    //����E8�����ƫ����
    //messageBoxA�ĵ�ַ�Ǿ��Ե�ַ�����Բ�������������ַҲ�þ��Ե�ַ��ע�������ַ���ܻ��
    //E8ָ��֮��ĵ�ַ=blankVirtualOffset+8+5+imageBase
    DWORD E8AppendOffset = messageboxAddr - (virtualOffset + 8 + 5 + 0x00400000);
    printf("E8 offsetInSection: 0x%08x\n", E8AppendOffset);
    //����E9�����ƫ��������ԭ����EOP 0x000E1D80�����Ǹ��ļ���ַƫ������ע�������ַ���ܻ��
    DWORD E9AppendOffset = 0x000E1D80 - (virtualOffset + 18);
    printf("E9 offsetInSection: 0x%08x\n", E9AppendOffset);
    //ֲ�����
    memcpy(newBuffer + fileOffSet, codePush, 8);
    memcpy(newBuffer + fileOffSet + 8, &codeE8, 1);
    memcpy(newBuffer + fileOffSet + 9, &E8AppendOffset, 4);
    memcpy(newBuffer + fileOffSet + 13, &codeE9, 1);
    memcpy(newBuffer + fileOffSet + 14, &E9AppendOffset, 4);
    //�޸�OEPΪֲ������λ�á�ע��OEP�Ǹ��ڴ�ƫ�Ƶ�ַ
    memcpy(newBuffer + gNewDosHeader->e_lfanew + 4 + 20 + 16, &virtualOffset, 4);
}

//�����������������������Ľڱ�
struct _IMAGE_SECTION_HEADER *addNewSection(size_t newSectionSize) {
    struct _IMAGE_SECTION_HEADER *pOldEnd = gNewSectionHeader + gNewFileHeader->NumberOfSections;
    //�ȿ���NTͷ�����һ���ڱ�����ݵ��½�����DOSͷ����λ��
    size_t copySize = 0x4 + 0x14 + 0xe0 + gNewFileHeader->NumberOfSections * 0x28;
    memcpy(gNewDosHeader + 1, gNewNtHeaders, copySize);
    //�޸�lfanew�ֶ�
    gNewDosHeader->e_lfanew = 0x40;
    //���³�ʼ��newBuffer��Ӧ�ĸ�ͷ
    initialNewBufferHeader();
    struct _IMAGE_SECTION_HEADER *pNewEnd = gNewSectionHeader + gNewFileHeader->NumberOfSections;
    //�����ƶ�ͷ�ͽڱ���¿ճ�����λ��Ϊ0x00
    size_t newBlankSize = (BYTE *) pOldEnd - (BYTE *) pNewEnd;
    memset(pNewEnd, 0x00, newBlankSize);
    //�¿հ��Ƿ񹻷�2���ڱ��С����80���ֽ�
    if (newBlankSize < 80) {
        printf("Not enough blank space to insert two section tables.\n");
        exit(1);
    }
    //������һ���ڱ��������ڱ�
    memcpy(pNewEnd, gNewSectionHeader, 40);
    //����һ���ļ�����Ĵ�С������ע����룬����ĩβ��������
    size_t expandSize = newSectionSize == 0 ? gNewOptionalHeader->FileAlignment : newSectionSize;
    newBufferSize += expandSize;
    newBuffer = realloc(newBuffer, newBufferSize);
    memset(newBuffer + (newBufferSize - expandSize), 0, expandSize);
    if (newBuffer == NULL) {
        printf("Memory reallocation failed.\n");
        exit(1);
    }
    initialNewBufferHeader();
    //�޸������Ľڱ�����
    struct _IMAGE_SECTION_HEADER *pLastSectionHeader = gNewSectionHeader + gNewFileHeader->NumberOfSections - 1;
    struct _IMAGE_SECTION_HEADER *pAddedSectionHeader = pLastSectionHeader + 1;
    BYTE name[] = {0x63, 0x68, 0x6f, 0x75, 0x00, 0x00, 0x00, 0x00};
    memcpy(pAddedSectionHeader->Name, name, 8);
    // ��С1��Ϊ��ռλ�������0������������ڴ��в�����
    pAddedSectionHeader->Misc.VirtualSize = 1;
    pAddedSectionHeader->VirtualAddress = gNewOptionalHeader->SizeOfImage;
    pAddedSectionHeader->SizeOfRawData = expandSize;
    pAddedSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
    //�޸�sizeOfImage������ֻ��������һ���ڴ�����С�Ľ����������������һ�������С��Ҫ�ȶ����ټ�
    gNewOptionalHeader->SizeOfImage += gNewOptionalHeader->SectionAlignment;
    //�޸Ľڱ���Ŀ
    gNewFileHeader->NumberOfSections += 1;
    return pAddedSectionHeader;
}

//��������ֲ�����
void implantCodeByNewSection() {
    addNewSection(0);
    //���½���ֲ�����
    implantCodeAtPos(gNewFileHeader->NumberOfSections, 1);
}

//�ϲ����н�Ϊһ���� TODO ����������⣬��֪��Ϊʲô
void mergeAllSectionsToOne() {
    DWORD newVirtualSize = gNewOptionalHeader->SizeOfImage - gNewSectionHeader->Misc.VirtualSize;
    DWORD newVirtualAddress = gNewSectionHeader->VirtualAddress;
    DWORD newCharacteristics = gNewSectionHeader->Characteristics;
    WORD oldSectionNum = gNewFileHeader->NumberOfSections;
    for (int i = 1; i < oldSectionNum; ++i) {
        newCharacteristics |= (gNewSectionHeader + i)->Characteristics;
    }
    newBuffer = imageBuffer;
    initialNewBufferHeader();
    newBufferSize = gNewOptionalHeader->SizeOfImage;
    gNewSectionHeader->VirtualAddress = newVirtualAddress;
    gNewSectionHeader->Misc.VirtualSize = newVirtualSize;
    gNewSectionHeader->PointerToRawData = newVirtualAddress;
    gNewSectionHeader->SizeOfRawData = newVirtualSize;
    gNewSectionHeader->Characteristics = newCharacteristics;
    gNewFileHeader->NumberOfSections = 1;
    //������ýڱ�
    memset(gNewSectionHeader + 1, 0x00, (oldSectionNum - 1) * 40);
}

void writeFile(DWORD bufferSize) {
//    FILE *outFile = fopen("C:\\Users\\Administrator\\Desktop\\sharedDLL_new.dll", "wb");
    FILE *outFile = fopen("D:\\�����ƽ�\\PEѧϰ\\IPMSG2007_new.exe", "wb");
    if (outFile == NULL) {
        printf("Failed to open file.\n");
        exit(1);
    }
    size_t writeCount = fwrite(newBuffer, bufferSize, 1, outFile);
    if (writeCount != 1) {
        printf("Failed to write file.\n");
    }
    fclose(outFile);
}

//newBufferΪ�µ�fileBuffer
void imageBufferToNewBuffer() {
    initialImageHeader();
    newBufferSize = gImageOptionalHeader->SizeOfHeaders;
    for (int i = 0; i < gImageFileHeader->NumberOfSections; ++i) {
        newBufferSize += (gImageSectionHeader + i)->SizeOfRawData;
    }
    newBuffer = (BYTE *) malloc(newBufferSize);
    if (newBuffer == NULL) {
        printf("Failed to allocate memory for newBuffer.\n");
        return;
    }
    memset(newBuffer, 0x00, newBufferSize);
    memcpy(newBuffer, imageBuffer, gImageOptionalHeader->SizeOfHeaders);
    for (int i = 0; i < gImageFileHeader->NumberOfSections; ++i) {
        const struct _IMAGE_SECTION_HEADER *curSectionHeader = gImageSectionHeader + i;
        BYTE *pImageSection = (BYTE *) imageBuffer + curSectionHeader->VirtualAddress;
        BYTE *pNewBufferSection = (BYTE *) newBuffer + curSectionHeader->PointerToRawData;
        memcpy(pNewBufferSection, pImageSection, curSectionHeader->SizeOfRawData);
    }
    initialNewBufferHeader();
//    implantCode();
//    implantCodeByNewSection();
//    mergeAllSectionsToOne();
}

//�����������ڴ�ƫ�Ƶ�ַת�ļ�ƫ�Ƶ�ַ��������VirtualSize��SizeOfRawData������
DWORD RVAToFOA(const DWORD RVA) {
    //�ڼ�������
    int sectionIndex = -1;
    //������ʼλ�õ�ƫ��
    DWORD offset = -1;
    for (int i = 0; i < gImageFileHeader->NumberOfSections; ++i) {
        const struct _IMAGE_SECTION_HEADER *pSectionTable = gImageSectionHeader + i;
        if (RVA >= pSectionTable->VirtualAddress &&
            RVA < pSectionTable->VirtualAddress + pSectionTable->Misc.VirtualSize) {
            sectionIndex = i;
            offset = RVA - pSectionTable->VirtualAddress;
            break;
        }
    }
    if (sectionIndex == -1 || offset == -1) {
        printf("RVA is not legal!\n");
    }
    return (gFileSectionHeader + sectionIndex)->PointerToRawData + offset;
}

//�������ļ�ƫ�Ƶ�ַת�����ڴ�ƫ�Ƶ�ַ��������VirtualSize��SizeOfRawData������
DWORD FOAToRVA(const DWORD FOA) {
    //�ڼ�������
    int sectionIndex = -1;
    //������ʼλ�õ�ƫ��
    DWORD offset = -1;
    for (int i = 0; i < gNewFileHeader->NumberOfSections; ++i) {
        const struct _IMAGE_SECTION_HEADER *pSectionTable = gNewSectionHeader + i;
        if (FOA >= pSectionTable->PointerToRawData &&
            FOA < pSectionTable->PointerToRawData + pSectionTable->SizeOfRawData) {
            sectionIndex = i;
            offset = FOA - pSectionTable->PointerToRawData;
            break;
        }
    }
    if (sectionIndex == -1 || offset == -1) {
        printf("FOA is not legal!\n");
    }
    return (gNewSectionHeader + sectionIndex)->VirtualAddress + offset;
}

DWORD getFunctionByName(const char *name, const struct _IMAGE_EXPORT_DIRECTORY *pExportDirectory) {
    DWORD addressOfNamesFOA = RVAToFOA(pExportDirectory->AddressOfNames);
    DWORD numberOfNames = pExportDirectory->NumberOfNames;
    DWORD AddressOfNameOrdinalsFOA = RVAToFOA(pExportDirectory->AddressOfNameOrdinals);
    DWORD AddressOfFunctionsFOA = RVAToFOA(pExportDirectory->AddressOfFunctions);
    DWORD ordinalOffset = -1;
    DWORD *ppName = (DWORD *) (fileBuffer + addressOfNamesFOA);
    for (int i = 0; i < numberOfNames; ++i) {
        char *pName = (char *) (fileBuffer + RVAToFOA(*(ppName + i)));
        if (strcmp(pName, name) == 0) {
            ordinalOffset = i;
            continue;
        }
    }
    if (ordinalOffset == -1) {
        printf("can't find the name.");
        exit(1);
    }
    WORD *pOrdinal = (WORD *) (fileBuffer + AddressOfNameOrdinalsFOA);
    WORD functionOrdinal = *(pOrdinal + ordinalOffset);
    DWORD *pFunction = (DWORD *) (fileBuffer + AddressOfFunctionsFOA) + functionOrdinal;
    DWORD functionRVA = *pFunction;
    printf("function RVA: %d\n", functionRVA);
    return functionRVA;
}

DWORD getFunctionByOrdinal(const DWORD ordinal, const struct _IMAGE_EXPORT_DIRECTORY *pExportDirectory) {
    DWORD AddressOfFunctionsFOA = RVAToFOA(pExportDirectory->AddressOfFunctions);
    DWORD *pFunction = (DWORD *) (fileBuffer + AddressOfFunctionsFOA) + (ordinal - pExportDirectory->Base);
    return *pFunction;
}

//��ӡ������
void printExportTable() {
    DWORD FOA = RVAToFOA(gFileOptionalHeader->DataDirectory[0].VirtualAddress);
    const struct _IMAGE_EXPORT_DIRECTORY *pExportDirectory = (struct _IMAGE_EXPORT_DIRECTORY *) (fileBuffer + FOA);
    DWORD exportTableRVA = gFileOptionalHeader->DataDirectory[0].VirtualAddress;
    DWORD exportTableSize = gFileOptionalHeader->DataDirectory[0].Size;
    printf("Export table VirtualAddress: 0x%04x\n", exportTableRVA);
    printf("Export table Size: %d\n", exportTableSize);
    DWORD numberOfFunctions = pExportDirectory->NumberOfFunctions;
    DWORD numberOfNames = pExportDirectory->NumberOfNames;
    DWORD addressOfFunctions = pExportDirectory->AddressOfFunctions;
    DWORD addressOfNames = pExportDirectory->AddressOfNames;
    DWORD addressOfOrdinals = pExportDirectory->AddressOfNameOrdinals;
    printf("number of functions: %d\n", numberOfFunctions);
    printf("number of names: %d\n", numberOfNames);
    printf("address of functions: 0x%04x\n", addressOfFunctions);
    printf("address of names: 0x%04x\n", addressOfNames);
    printf("address of ordinals: 0x%04x\n", addressOfOrdinals);
    //ͨ����������Ѱ�Һ���
    DWORD functionFOAByName = RVAToFOA(getFunctionByName("myPlus", pExportDirectory));
    printf("function FOA by name: %d\n", functionFOAByName);
    //ͨ������Һ���
    DWORD functionFOAByOrdinal = RVAToFOA(getFunctionByOrdinal(5, pExportDirectory));
    printf("function FOA by ordinal: %d\n", functionFOAByOrdinal);
}

//��ӡ�ض�λ��
void printBaseRelocTable() {
    DWORD FOA = RVAToFOA(gFileOptionalHeader->DataDirectory[5].VirtualAddress);
    struct _IMAGE_BASE_RELOCATION *pBaseRelocation = (struct _IMAGE_BASE_RELOCATION *) (fileBuffer + FOA);
    int n = 1;
    while (pBaseRelocation->VirtualAddress != 0 && pBaseRelocation->SizeOfBlock != 0) {
        WORD *pEntry = (WORD *) (pBaseRelocation + 1);
        DWORD entryCount = (pBaseRelocation->SizeOfBlock - 8) / 2;
        printf("relocation table %d's RVA:\n", n++);
        for (int i = 0; i < entryCount; ++i) {
            WORD entry = pEntry[i];
            if ((entry & 0xF000) != (3 << 12)) continue;
            int relocEntry = entry & 0x0FFF;
            DWORD relocRVA = pBaseRelocation->VirtualAddress + relocEntry;
            printf("%08x\n", relocRVA);
        }
        pBaseRelocation = (struct _IMAGE_BASE_RELOCATION *) ((BYTE *) pBaseRelocation + pBaseRelocation->SizeOfBlock);
    }
}

//��ӡ�����
void printImportTable() {
    struct _IMAGE_IMPORT_DESCRIPTOR *pImportTable = (struct _IMAGE_IMPORT_DESCRIPTOR *) (fileBuffer + RVAToFOA(
            gNewOptionalHeader->DataDirectory[1].VirtualAddress));
    struct _IMAGE_IMPORT_DESCRIPTOR zeroDesc = {0};
    while (memcmp(pImportTable, &zeroDesc, sizeof(struct _IMAGE_IMPORT_DESCRIPTOR)) != 0) {
        BYTE *pName = fileBuffer + RVAToFOA(pImportTable->Name);
        printf("Import table's DLL name: %s\n", pName);
        struct _IMAGE_THUNK_DATA32 *pOriginalThunk = (struct _IMAGE_THUNK_DATA32 *) (fileBuffer + RVAToFOA(
                pImportTable->OriginalFirstThunk));
        while (pOriginalThunk->Function != 0) {
            printf("Original First Thunk: %04x\n", pOriginalThunk->Function);
            pOriginalThunk++;
        }
        struct _IMAGE_THUNK_DATA32 *pFirstThunk = (struct _IMAGE_THUNK_DATA32 *) (fileBuffer + RVAToFOA(
                pImportTable->FirstThunk));
        while (pFirstThunk->Function != 0) {
            if ((pFirstThunk->Function >> 31) == 0x1) {
                DWORD ordinal = pFirstThunk->Function & 0x7FFFFFFF;
                printf("ordinal: %04x\n", ordinal);
            } else {
                struct _IMAGE_IMPORT_BY_NAME *pImportByName = (struct _IMAGE_IMPORT_BY_NAME *) (fileBuffer + RVAToFOA(
                        pFirstThunk->Function));
                printf("import by name: %s\n", pImportByName->Name);
            }
            pFirstThunk++;
        }
        printf("------------------------------\n");
        pImportTable++;
    }
}

//��ӡ�󶨵����
void printBoundImportTable() {
    //ע�⣬�����VirtualAddressҲ��������ͷ����Ŀ��пռ���ģ��������ڽ����������������תFOA�ķ����ͻ���������ǲ���Ҫת��
    struct _IMAGE_BOUND_IMPORT_DESCRIPTOR *pBoundImportDescriptor = (struct _IMAGE_BOUND_IMPORT_DESCRIPTOR *) (
            fileBuffer + RVAToFOA(gNewOptionalHeader->DataDirectory[11].VirtualAddress));
    struct _IMAGE_BOUND_IMPORT_DESCRIPTOR zeroDesc = {0};
    while (memcmp(pBoundImportDescriptor, &zeroDesc, sizeof(struct _IMAGE_BOUND_IMPORT_DESCRIPTOR)) != 0) {
        printf("BOUND_IMPORT OffsetModuleName: %s\n", fileBuffer + pBoundImportDescriptor->OffsetModuleName);
        printf("BOUND_IMPORT TimeDateStamp: %04x\n", pBoundImportDescriptor->TimeDateStamp);
        struct _IMAGE_BOUND_FORWARDER_REF *pBF = (struct _IMAGE_BOUND_FORWARDER_REF *) (pBoundImportDescriptor + 1);
        for (int i = 0; i < pBoundImportDescriptor->NumberOfModuleForwarderRefs; ++i) {
            printf("BOUND_FORWARDER OffsetModuleName: %s\n", fileBuffer + pBF[i].OffsetModuleName);
            printf("BOUND_FORWARDER TimeDateStamp: %04x\n", pBF[i].TimeDateStamp);
        }
        printf("---------------------");
        pBoundImportDescriptor += 1 + pBoundImportDescriptor->NumberOfModuleForwarderRefs;
    }
}

//�ƶ�������
void moveExportTable() {
    int newSectionSize = 0x1000;
    struct _IMAGE_SECTION_HEADER *pNewSectionHeader = addNewSection(newSectionSize);
    DWORD exportTableFOA = RVAToFOA(gNewOptionalHeader->DataDirectory[0].VirtualAddress);
    struct _IMAGE_EXPORT_DIRECTORY *pExportTable = (struct _IMAGE_EXPORT_DIRECTORY *) (newBuffer + exportTableFOA);
    DWORD numberOfFunctions = pExportTable->NumberOfFunctions;
    DWORD numberOfNames = pExportTable->NumberOfNames;
    DWORD addressOfFunctions = pExportTable->AddressOfFunctions;
    DWORD addressOfNames = pExportTable->AddressOfNames;
    DWORD addressOfOrdinals = pExportTable->AddressOfNameOrdinals;
    size_t sizeOfData = 0;
    //��ʼ���ο�����������š����ֵȱ������µ������3����ַ
    BYTE *newSecStartCopyPos = newBuffer + pNewSectionHeader->PointerToRawData;
    memcpy(newSecStartCopyPos, newBuffer + RVAToFOA(addressOfFunctions), numberOfFunctions * 4);
    sizeOfData += numberOfFunctions * 4;
    pExportTable->AddressOfFunctions = FOAToRVA(newSecStartCopyPos - newBuffer);
    newSecStartCopyPos += numberOfFunctions * 4;
    memcpy(newSecStartCopyPos, newBuffer + RVAToFOA(addressOfOrdinals), numberOfNames * 2);
    sizeOfData += numberOfNames * 2;
    pExportTable->AddressOfNameOrdinals = FOAToRVA(newSecStartCopyPos - newBuffer);
    newSecStartCopyPos += numberOfNames * 2;
    BYTE *ppNamesInByte = newBuffer + RVAToFOA(addressOfNames);
    memcpy(newSecStartCopyPos, ppNamesInByte, numberOfNames * 4);
    sizeOfData += numberOfNames * 4;
    pExportTable->AddressOfNames = FOAToRVA(newSecStartCopyPos - newBuffer);
    newSecStartCopyPos += numberOfNames * 4;
    //��ʼ������������
    DWORD *ppNameInDWord = (DWORD *) ppNamesInByte;
    for (int i = 0; i < numberOfNames; ++i) {
        DWORD *prePpNameInDWord = ppNameInDWord++;
        BYTE *preCopyPos = newSecStartCopyPos;
        strcpy((char *) newSecStartCopyPos, (const char *) ppNameInDWord);
        size_t copiedLen = strlen((const char *) ppNameInDWord) + 1;
        sizeOfData += copiedLen;
        newSecStartCopyPos += copiedLen;
        //�������ֱ��RVA
        *prePpNameInDWord = FOAToRVA((preCopyPos - newBuffer));
    }
    //��ʼ����������
    memcpy(newSecStartCopyPos, pExportTable, 0x28);
    sizeOfData += 0x28;
    //����Ŀ¼���е������RVA
    gNewOptionalHeader->DataDirectory[0].VirtualAddress = FOAToRVA(newSecStartCopyPos - newBuffer);
    //�������һ���ڱ�����
    pNewSectionHeader->SizeOfRawData = align(newSectionSize, gNewOptionalHeader->FileAlignment);
    pNewSectionHeader->Misc.VirtualSize = sizeOfData;
}

//�ƶ��ض�λ��
void moveRelocTable() {
    int newSectionSize = 0x1000;
    struct _IMAGE_SECTION_HEADER *pNewSectionHeader = addNewSection(newSectionSize);
    DWORD FOA = RVAToFOA(gNewOptionalHeader->DataDirectory[5].VirtualAddress);
    struct _IMAGE_BASE_RELOCATION *pBaseRelocation = (struct _IMAGE_BASE_RELOCATION *) (newBuffer + FOA);
    BYTE *newSecStartCopyPos = newBuffer + pNewSectionHeader->PointerToRawData;
    size_t sizeOfData = 0;
    while (pBaseRelocation->VirtualAddress != 0 && pBaseRelocation->SizeOfBlock != 0) {
        memcpy(newSecStartCopyPos, pBaseRelocation, pBaseRelocation->SizeOfBlock);
        newSecStartCopyPos += pBaseRelocation->SizeOfBlock;
        sizeOfData += pBaseRelocation->SizeOfBlock;
        pBaseRelocation = (struct _IMAGE_BASE_RELOCATION *) ((BYTE *) pBaseRelocation + pBaseRelocation->SizeOfBlock);
    }
    //���������ȻΪ0����Ҳ��ռλ��
    sizeOfData += 8;
    //����Ŀ¼�����ض�λ���RVA
    gNewOptionalHeader->DataDirectory[5].VirtualAddress = FOAToRVA(pNewSectionHeader->PointerToRawData);
    //�������һ���ڱ�����
    pNewSectionHeader->SizeOfRawData = align(newSectionSize, gNewOptionalHeader->FileAlignment);
    pNewSectionHeader->Misc.VirtualSize = sizeOfData;
}

//�޸�ImageBase������0x10000000��һ����Ǵ�0x10000000���0x20000000��Ȼ�������к����޸��ض�λ��
void repairRelocation() {
    gNewOptionalHeader->ImageBase += 0x10000000;
    DWORD FOA = RVAToFOA(gNewOptionalHeader->DataDirectory[5].VirtualAddress);
    struct _IMAGE_BASE_RELOCATION *pBaseRelocation = (struct _IMAGE_BASE_RELOCATION *) (newBuffer + FOA);
    while (pBaseRelocation->VirtualAddress != 0 && pBaseRelocation->SizeOfBlock != 0) {
        WORD *ppEntryOffset = (WORD *) (pBaseRelocation + 1);
        for (int i = 0; i < (pBaseRelocation->SizeOfBlock - 8) / 2; ++i) {
            if ((ppEntryOffset[i] & 0xF000) != (3 << 12)) continue;
            DWORD pEntryRVA = pBaseRelocation->VirtualAddress + (ppEntryOffset[i] & 0x0FFF);
            DWORD *pEntry = (DWORD *) (newBuffer + RVAToFOA(pEntryRVA));
            *pEntry += 0x10000000;
        }
        pBaseRelocation = (struct _IMAGE_BASE_RELOCATION *) ((BYTE *) pBaseRelocation + pBaseRelocation->SizeOfBlock);
    }
}

//�����ע�� TODO �д����Ҳ���ԭ���Ժ���˵�ɣ���������
void injectDLLByImportTable() {
    int newSectionSize = 0x1000;
    struct _IMAGE_SECTION_HEADER *pNewSectionHeader = addNewSection(newSectionSize);
    struct _IMAGE_IMPORT_DESCRIPTOR *pImportTable = (struct _IMAGE_IMPORT_DESCRIPTOR *) (newBuffer + RVAToFOA(
            gNewOptionalHeader->DataDirectory[1].VirtualAddress));
    BYTE *newSecStartCopyPos = newBuffer + pNewSectionHeader->PointerToRawData;
    size_t sizeOfData = 0;
    size_t sizeOfOriginalData = 0;
    struct _IMAGE_IMPORT_DESCRIPTOR zeroDesc = {0};
    //�������������
    while (memcmp(pImportTable, &zeroDesc, sizeof(struct _IMAGE_IMPORT_DESCRIPTOR)) != 0) {
        memcpy(newSecStartCopyPos, pImportTable, sizeof(struct _IMAGE_IMPORT_DESCRIPTOR));
        newSecStartCopyPos += sizeof(struct _IMAGE_IMPORT_DESCRIPTOR);
        sizeOfData += sizeof(struct _IMAGE_IMPORT_DESCRIPTOR);
        sizeOfOriginalData += sizeof(struct _IMAGE_IMPORT_DESCRIPTOR);
        pImportTable++;
    }
    sizeOfOriginalData += sizeof(struct _IMAGE_IMPORT_DESCRIPTOR);
    //����ע��ĵ����������һ��ȫ0�ĵ������Ϊ��β
    struct _IMAGE_IMPORT_DESCRIPTOR *injectImportTable = (struct _IMAGE_IMPORT_DESCRIPTOR *) newSecStartCopyPos;
    newSecStartCopyPos += sizeof(struct _IMAGE_IMPORT_DESCRIPTOR) * 2;
    sizeOfData += sizeof(struct _IMAGE_IMPORT_DESCRIPTOR) * 2;
    //����DLL����
    const char *dllName = "injectDLL.dll";
    strcpy((char *) newSecStartCopyPos, dllName);
    (*injectImportTable).Name = FOAToRVA(newSecStartCopyPos - newBuffer);
    size_t dllNameLen = strlen(dllName) + 1;
    newSecStartCopyPos += dllNameLen;
    sizeOfData += dllNameLen;
    //����ע���INT������������INT�ձ�
    struct _IMAGE_THUNK_DATA32 *injectINT = (struct _IMAGE_THUNK_DATA32 *) newSecStartCopyPos;
    (*injectImportTable).OriginalFirstThunk = FOAToRVA(newSecStartCopyPos - newBuffer);
    newSecStartCopyPos += sizeof(struct _IMAGE_THUNK_DATA32) * 2;
    sizeOfData += sizeof(struct _IMAGE_THUNK_DATA32) * 2;
    //����ע���IAT������������INT�ձ�
    struct _IMAGE_THUNK_DATA32 *injectIAT = (struct _IMAGE_THUNK_DATA32 *) newSecStartCopyPos;
    (*injectImportTable).FirstThunk = FOAToRVA(newSecStartCopyPos - newBuffer);
    newSecStartCopyPos += sizeof(struct _IMAGE_THUNK_DATA32) * 2;
    sizeOfData += sizeof(struct _IMAGE_THUNK_DATA32) * 2;
    //�������ֱ��������������ֿձ�
    struct _IMAGE_IMPORT_BY_NAME *pInjectNameTable = (struct _IMAGE_IMPORT_BY_NAME *) newSecStartCopyPos;
    char *pFuncName = "myFunction";
    size_t funcNameLen = strlen(pFuncName) + 1;
    strcpy((char *) (*pInjectNameTable).Name, pFuncName);
    sizeOfData += (2 + funcNameLen) + sizeof(struct _IMAGE_IMPORT_BY_NAME);
    //�޸�ע���INT��IAT��
    //�����ֵ���
    DWORD nameRVA = FOAToRVA((BYTE *) pInjectNameTable - newBuffer);
    (*injectINT).Function = nameRVA;
    (*injectIAT).Function = nameRVA;
    //����ŵ��������ﺯ�����������1
//    int ordinal = 1;
//    (*injectINT).Ordinal = 0x80000000 | ordinal;
//    (*injectIAT).Ordinal = 0x80000000 | ordinal;
    //����Ŀ¼�����ض�λ���RVA
    gNewOptionalHeader->DataDirectory[1].VirtualAddress = FOAToRVA(pNewSectionHeader->PointerToRawData);
    gNewOptionalHeader->DataDirectory[1].Size += sizeOfOriginalData + 20;
    //�������һ���ڱ�����
    pNewSectionHeader->SizeOfRawData = align(newSectionSize, gNewOptionalHeader->FileAlignment);
    pNewSectionHeader->Misc.VirtualSize = sizeOfData;
}

//��ӡ��Դ��
void printResourceTable() {
    DWORD FOA = RVAToFOA(gFileOptionalHeader->DataDirectory[2].VirtualAddress);
    gFileResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY) (fileBuffer + FOA);
    WORD numOfResType = gFileResourceDirectory->NumberOfIdEntries + gFileResourceDirectory->NumberOfNamedEntries;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResType = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (gFileResourceDirectory + 1);
    for (int i = 0; i < numOfResType; ++i) {
        //��Դ����
        if (pResType->NameIsString) {
            PIMAGE_RESOURCE_DIR_STRING_U pResStringU = (PIMAGE_RESOURCE_DIR_STRING_U) (pResType->NameOffset +
                                                                                       (BYTE *) gFileResourceDirectory);
            wprintf(L"--���� NameString: %.*ls\n", pResStringU->Length, pResStringU->NameString);
        } else {
            printf("--���� id: %d\n", pResType->Id);
        }
        //��Դ���
        if (pResType->DataIsDirectory) {
            PIMAGE_RESOURCE_DIRECTORY pResName = (PIMAGE_RESOURCE_DIRECTORY) (pResType->OffsetToDirectory +
                                                                              (BYTE *) gFileResourceDirectory);
            WORD numOfResName = pResName->NumberOfIdEntries + pResName->NumberOfNamedEntries;
            PIMAGE_RESOURCE_DIRECTORY_ENTRY pResNameEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (pResName + 1);
            for (int j = 0; j < numOfResName; ++j) {
                if (pResNameEntry->NameIsString) {
                    PIMAGE_RESOURCE_DIR_STRING_U pResStringU = (PIMAGE_RESOURCE_DIR_STRING_U) (
                            pResNameEntry->NameOffset +
                            (BYTE *) gFileResourceDirectory);
                    wprintf(L"----���� NameString: %.*ls\n", pResStringU->Length, pResStringU->NameString);
                } else {
                    printf("----���� id: %d\n", pResNameEntry->Id);
                }
                //��Դ����
                if (pResNameEntry->DataIsDirectory) {
                    PIMAGE_RESOURCE_DIRECTORY pResLang = (PIMAGE_RESOURCE_DIRECTORY) (pResNameEntry->OffsetToDirectory +
                                                                                      (BYTE *) gFileResourceDirectory);
                    WORD numOfResLang = pResLang->NumberOfIdEntries + pResLang->NumberOfNamedEntries;
                    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResLangEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY) (pResLang + 1);
                    for (int k = 0; k < numOfResLang; ++k) {
                        printf("------���� id: %d\n", pResLangEntry->Id);
                        //��Դ����
                        PIMAGE_DATA_DIRECTORY pResDataEntry = (PIMAGE_DATA_DIRECTORY) (pResLangEntry->OffsetToData +
                                                                                       (BYTE *) gFileResourceDirectory);
                        printf("------��Դ���� RVA: %08x\n", pResDataEntry->VirtualAddress);
                        printf("------��Դ���� Size: %08x\n", pResDataEntry->Size);
                        pResLangEntry++;
                    }
                }
                pResNameEntry++;
            }
        }
        pResType++;
    }
}

int main() {
    readFile("D:\\�����ƽ�\\PEѧϰ\\IPMSG2007.exe");
//    readFile("C:\\Users\\Administrator\\Desktop\\sharedDLL.dll");
    if (fileBuffer == NULL) {
        exit(1); // �ļ���ȡʧ�ܣ��˳�����
    }
//    printPEHeader();
//    printSectionTable();
    fileBufferToImageBuffer();
    imageBufferToNewBuffer();
//    printBaseRelocTable();
//    DWORD FOA = RVAToFOA(0x0001F000);
//    printf("FOA:%08x\n", FOA);
//    printExportTable();
//    moveExportTable();
//    moveRelocTable();
//    repairRelocation();
//    printImportTable();
//    printBoundImportTable();
//    injectDLLByImportTable();
//    writeFile(newBufferSize);
    printResourceTable();
    free(fileBuffer);
    free(imageBuffer);
    free(newBuffer);
    return 0;
}
