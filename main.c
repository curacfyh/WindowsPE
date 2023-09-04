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

// 读取文件，返回文件开头指针
void readFile(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        printf("Failed to open file: %s\n", filename);
        exit(1);
    }
    // 获取文件大小
    fseek(file, 0, SEEK_END);
    fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);  // 将文件指针移回文件开始
    if (fileSize < 0) {
        printf("Failed to get file size.\n");
        fclose(file);
        return;
    }
    // 分配内存，读取文件数据
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
    //拷贝头和节表
    memcpy(imageBuffer, fileBuffer, gFileOptionalHeader->SizeOfHeaders);
    //拷贝节区
    WORD numOfSections = gFileFileHeader->NumberOfSections;
    for (int i = 0; i < numOfSections; ++i) {
        const struct _IMAGE_SECTION_HEADER *curSectionHeader = gFileSectionHeader + i;
        //节区起始位置
        BYTE *pFileSection = (BYTE *) fileBuffer + curSectionHeader->PointerToRawData;
        BYTE *pImageSection = (BYTE *) imageBuffer + curSectionHeader->VirtualAddress;
        memcpy(pImageSection, pFileSection, curSectionHeader->Misc.VirtualSize);
    }
}

void implantCode() {
    //准备要植入的代码 6A 00 6A 00 6A 00 6A 00 E8 XX XX XX XX E9 XX XX XX XX，共18字节，push call jmp
    BYTE codePush[] = {0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00};
    BYTE codeE8 = 0xE8;
    BYTE codeE9 = 0xE9;
    //先找空白区，这里使用第一个节区对齐后的空白区，然后看空白区是否够放代码
    DWORD blankSize = gNewSectionHeader->SizeOfRawData - gNewSectionHeader->VirtualAddress;
    if (blankSize < 18) {
        printf("空白区不够植入代码。\n");
        exit(1);
    }
    //找出空白区首偏移地址
    DWORD blankFileOffset = gNewSectionHeader->PointerToRawData + gNewSectionHeader->Misc.VirtualSize;
    DWORD blankVirtualOffset = gNewSectionHeader->VirtualAddress + gNewSectionHeader->Misc.VirtualSize;
    //计算E8代码的偏移量
    //messageBoxA的地址是绝对地址，所以参与计算的其它地址也用绝对地址，注意这个地址可能会变
    //E8指令之后的地址=blankVirtualOffset+8+5+imageBase
    DWORD E8AppendOffset = messageboxAddr - (blankVirtualOffset + 8 + 5 + 0x00400000);
    printf("E8 offset: 0x%08x\n", E8AppendOffset);
    //计算E9代码的偏移量，即原来的EOP 0x000E1D80，这是个文件地址偏移量，注意这个地址可能会变
    DWORD E9AppendOffset = 0x000E1D80 - (blankVirtualOffset + 18);
    printf("E9 offset: 0x%08x\n", E9AppendOffset);
    //植入代码
    memcpy(newBuffer + blankFileOffset, codePush, 8);
    memcpy(newBuffer + blankFileOffset + 8, &codeE8, 1);
    memcpy(newBuffer + blankFileOffset + 9, &E8AppendOffset, 4);
    memcpy(newBuffer + blankFileOffset + 13, &codeE9, 1);
    memcpy(newBuffer + blankFileOffset + 14, &E9AppendOffset, 4);
    //修改OEP为植入代码的位置。注意OEP是个内存偏移地址
    memcpy(newBuffer + gNewDosHeader->e_lfanew + 4 + 20 + 16, &blankVirtualOffset, 4);
}

//任何偏移位置植入代码。sectionIdx为节区索引，从0开始；offsetInSection为相对节区起始位置的偏移量
void implantCodeAtPos(const DWORD sectionIdx, const DWORD offsetInSection) {
    //准备要植入的代码 6A 00 6A 00 6A 00 6A 00 E8 XX XX XX XX E9 XX XX XX XX，共18字节，push call jmp
    BYTE codePush[] = {0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00};
    BYTE codeE8 = 0xE8;
    BYTE codeE9 = 0xE9;
    //植入代码位置的内存偏移地址和文件偏移地址
    DWORD virtualOffset = (gNewSectionHeader + sectionIdx)->VirtualAddress + offsetInSection;
    DWORD fileOffSet = (gNewSectionHeader + sectionIdx)->PointerToRawData + offsetInSection;
    //计算E8代码的偏移量
    //messageBoxA的地址是绝对地址，所以参与计算的其它地址也用绝对地址，注意这个地址可能会变
    //E8指令之后的地址=blankVirtualOffset+8+5+imageBase
    DWORD E8AppendOffset = messageboxAddr - (virtualOffset + 8 + 5 + 0x00400000);
    printf("E8 offsetInSection: 0x%08x\n", E8AppendOffset);
    //计算E9代码的偏移量，即原来的EOP 0x000E1D80，这是个文件地址偏移量，注意这个地址可能会变
    DWORD E9AppendOffset = 0x000E1D80 - (virtualOffset + 18);
    printf("E9 offsetInSection: 0x%08x\n", E9AppendOffset);
    //植入代码
    memcpy(newBuffer + fileOffSet, codePush, 8);
    memcpy(newBuffer + fileOffSet + 8, &codeE8, 1);
    memcpy(newBuffer + fileOffSet + 9, &E8AppendOffset, 4);
    memcpy(newBuffer + fileOffSet + 13, &codeE9, 1);
    memcpy(newBuffer + fileOffSet + 14, &E9AppendOffset, 4);
    //修改OEP为植入代码的位置。注意OEP是个内存偏移地址
    memcpy(newBuffer + gNewDosHeader->e_lfanew + 4 + 20 + 16, &virtualOffset, 4);
}

//新增节区，返回新增节区的节表
struct _IMAGE_SECTION_HEADER *addNewSection(size_t newSectionSize) {
    struct _IMAGE_SECTION_HEADER *pOldEnd = gNewSectionHeader + gNewFileHeader->NumberOfSections;
    //先拷贝NT头到最后一个节表的内容到新紧挨着DOS头的新位置
    size_t copySize = 0x4 + 0x14 + 0xe0 + gNewFileHeader->NumberOfSections * 0x28;
    memcpy(gNewDosHeader + 1, gNewNtHeaders, copySize);
    //修改lfanew字段
    gNewDosHeader->e_lfanew = 0x40;
    //重新初始化newBuffer对应的各头
    initialNewBufferHeader();
    struct _IMAGE_SECTION_HEADER *pNewEnd = gNewSectionHeader + gNewFileHeader->NumberOfSections;
    //设置移动头和节表后新空出来的位置为0x00
    size_t newBlankSize = (BYTE *) pOldEnd - (BYTE *) pNewEnd;
    memset(pNewEnd, 0x00, newBlankSize);
    //新空白是否够放2个节表大小，即80个字节
    if (newBlankSize < 80) {
        printf("Not enough blank space to insert two section tables.\n");
        exit(1);
    }
    //拷贝第一个节表来新增节表
    memcpy(pNewEnd, gNewSectionHeader, 40);
    //扩大一个文件对齐的大小，用作注入代码，即在末尾新增节区
    size_t expandSize = newSectionSize == 0 ? gNewOptionalHeader->FileAlignment : newSectionSize;
    newBufferSize += expandSize;
    newBuffer = realloc(newBuffer, newBufferSize);
    memset(newBuffer + (newBufferSize - expandSize), 0, expandSize);
    if (newBuffer == NULL) {
        printf("Memory reallocation failed.\n");
        exit(1);
    }
    initialNewBufferHeader();
    //修改新增的节表属性
    struct _IMAGE_SECTION_HEADER *pLastSectionHeader = gNewSectionHeader + gNewFileHeader->NumberOfSections - 1;
    struct _IMAGE_SECTION_HEADER *pAddedSectionHeader = pLastSectionHeader + 1;
    BYTE name[] = {0x63, 0x68, 0x6f, 0x75, 0x00, 0x00, 0x00, 0x00};
    memcpy(pAddedSectionHeader->Name, name, 8);
    // 大小1是为了占位，如果是0，这个节区在内存中不存在
    pAddedSectionHeader->Misc.VirtualSize = 1;
    pAddedSectionHeader->VirtualAddress = gNewOptionalHeader->SizeOfImage;
    pAddedSectionHeader->SizeOfRawData = expandSize;
    pAddedSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
    //修改sizeOfImage。这里只是增加了一个内存对齐大小的节区，如果节区超过一个对齐大小，要先对齐再加
    gNewOptionalHeader->SizeOfImage += gNewOptionalHeader->SectionAlignment;
    //修改节表数目
    gNewFileHeader->NumberOfSections += 1;
    return pAddedSectionHeader;
}

//新增节来植入代码
void implantCodeByNewSection() {
    addNewSection(0);
    //在新节区植入代码
    implantCodeAtPos(gNewFileHeader->NumberOfSections, 1);
}

//合并所有节为一个节 TODO 导入表有问题，不知道为什么
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
    //清空无用节表
    memset(gNewSectionHeader + 1, 0x00, (oldSectionNum - 1) * 40);
}

void writeFile(DWORD bufferSize) {
    FILE *outFile = fopen("C:\\Users\\Administrator\\Desktop\\sharedDLL_new.dll", "wb");
//    FILE *outFile = fopen("C:\\Users\\Administrator\\Desktop\\Windows On Top_new.exe", "wb");
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

//newBuffer为新的fileBuffer
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

//节区中虚拟内存偏移地址转文件偏移地址，不考虑VirtualSize比SizeOfRawData大的情况
DWORD RVAToFOA(const DWORD RVA) {
    //第几个节区
    int sectionIndex = -1;
    //节区起始位置的偏移
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

//节区中文件偏移地址转虚拟内存偏移地址，不考虑VirtualSize比SizeOfRawData大的情况
DWORD FOAToRVA(const DWORD FOA) {
    //第几个节区
    int sectionIndex = -1;
    //节区起始位置的偏移
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

//打印导出表
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
    //通过函数名称寻找函数
    DWORD functionFOAByName = RVAToFOA(getFunctionByName("myPlus", pExportDirectory));
    printf("function FOA by name: %d\n", functionFOAByName);
    //通过序号找函数
    DWORD functionFOAByOrdinal = RVAToFOA(getFunctionByOrdinal(5, pExportDirectory));
    printf("function FOA by ordinal: %d\n", functionFOAByOrdinal);
}

//打印重定位表
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

//移动导出表
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
    //开始依次拷贝函数、序号、名字等表，并更新导出表的3个地址
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
    //开始遍历拷贝名字
    DWORD *ppNameInDWord = (DWORD *) ppNamesInByte;
    for (int i = 0; i < numberOfNames; ++i) {
        DWORD *prePpNameInDWord = ppNameInDWord++;
        BYTE *preCopyPos = newSecStartCopyPos;
        strcpy((char *) newSecStartCopyPos, (const char *) ppNameInDWord);
        size_t copiedLen = strlen((const char *) ppNameInDWord) + 1;
        sizeOfData += copiedLen;
        newSecStartCopyPos += copiedLen;
        //更新名字表的RVA
        *prePpNameInDWord = FOAToRVA((preCopyPos - newBuffer));
    }
    //开始拷贝导出表
    memcpy(newSecStartCopyPos, pExportTable, 0x28);
    sizeOfData += 0x28;
    //更新目录表中导出表的RVA
    gNewOptionalHeader->DataDirectory[0].VirtualAddress = FOAToRVA(newSecStartCopyPos - newBuffer);
    //更新最后一个节表内容
    pNewSectionHeader->SizeOfRawData = align(newSectionSize, gNewOptionalHeader->FileAlignment);
    pNewSectionHeader->Misc.VirtualSize = sizeOfData;
}

//移动重定位表
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
    //结束标记虽然为0，但也是占位的
    sizeOfData += 8;
    //更新目录表中重定位表的RVA
    gNewOptionalHeader->DataDirectory[5].VirtualAddress = FOAToRVA(pNewSectionHeader->PointerToRawData);
    //更新最后一个节表内容
    pNewSectionHeader->SizeOfRawData = align(newSectionSize, gNewOptionalHeader->FileAlignment);
    pNewSectionHeader->Misc.VirtualSize = sizeOfData;
}

//修改ImageBase，增加0x10000000，一般就是从0x10000000变成0x20000000，然后用下列函数修复重定位表
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

int main() {
//    readFile("C:\\Users\\Administrator\\Desktop\\Windows On Top.exe");
    readFile("C:\\Users\\Administrator\\Desktop\\sharedDLL.dll");
    if (fileBuffer == NULL) {
        exit(1); // 文件读取失败，退出程序
    }
//    printPEHeader();
//    printSectionTable();
    fileBufferToImageBuffer();
    imageBufferToNewBuffer();
    printBaseRelocTable();
//    DWORD FOA = RVAToFOA(0x0001F000);
//    printf("FOA:%08x\n", FOA);
    printExportTable();
//    moveExportTable();
//    moveRelocTable();
    repairRelocation();
    writeFile(newBufferSize);
    free(fileBuffer);
    free(imageBuffer);
    free(newBuffer);
    return 0;
}
