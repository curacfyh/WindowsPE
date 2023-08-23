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
    //拷贝头和节表 TODO 参考下别人的代码
    memcpy(imageBuffer, fileBuffer, gFileOptionalHeader->SizeOfHeaders);
    //拷贝节区
    WORD numOfSections = gFileFileHeader->NumberOfSections;
    for (int i = 0; i < numOfSections; ++i) {
        const struct _IMAGE_SECTION_HEADER *curSectionHeader = gFileSectionHeader + i;
        //节区起始位置
        BYTE *pFileSection = (BYTE *) fileBuffer + curSectionHeader->PointerToRawData;
        BYTE *pImageSection = (BYTE *) imageBuffer + curSectionHeader->VirtualAddress;
        DWORD minSize = min(curSectionHeader->Misc.VirtualSize, curSectionHeader->SizeOfRawData);
        memcpy(pImageSection, pFileSection, minSize);
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

//新增节来植入代码
void implantCodeByNewSection() {
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
    newBufferSize += gNewOptionalHeader->FileAlignment;
    newBuffer = realloc(newBuffer, newBufferSize);
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
    pAddedSectionHeader->SizeOfRawData = gNewOptionalHeader->FileAlignment;
    pAddedSectionHeader->PointerToRawData = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;
    //修改sizeOfImage。这里只是增加了一个内存对齐大小的节区，如果节区超过一个对齐大小，要先对齐再加
    gNewOptionalHeader->SizeOfImage += gNewOptionalHeader->SectionAlignment;
    //在新节区植入代码
    implantCodeAtPos(gNewFileHeader->NumberOfSections, 1);
    //修改节表数目
    gNewFileHeader->NumberOfSections += 1;
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
    FILE *outFile = fopen("C:\\Users\\Chou\\Desktop\\libsharedDLL.dll", "wb");
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
    //计算newBuffer大小，公式为SizeOfHeaders按fileAlignment对齐+各节区的SizeOfRawData
    //还有更简便的，最后一个节区的PointerToRawData + SizeOfRawData就是整个PE文件的大小。这种暂时不做
    //将SizeOfHeaders按fileAlignment对齐
    DWORD sizeOfHeaders = gImageOptionalHeader->SizeOfHeaders;
    DWORD fileAlignment = gImageOptionalHeader->FileAlignment;
    newBufferSize = (sizeOfHeaders + fileAlignment - 1) & ~(fileAlignment - 1);
    for (int i = 0; i < gImageFileHeader->NumberOfSections; ++i) {
        newBufferSize += (gImageSectionHeader + i)->SizeOfRawData;
    }
    newBuffer = (BYTE *) malloc(newBufferSize);
    if (newBuffer == NULL) {
        printf("Failed to allocate memory for newBuffer.\n");
        return;
    }
    memset(newBuffer, 0x00, newBufferSize);
    memcpy(newBuffer, imageBuffer, sizeOfHeaders);
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
//    writeFile(newBufferSize);
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
            RVA <= pSectionTable->VirtualAddress + pSectionTable->Misc.VirtualSize) {
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

DWORD getFunctionByName(const char *name, const struct _IMAGE_EXPORT_DIRECTORY *pExportDirectory) {
    DWORD addressOfNamesFOA = RVAToFOA(pExportDirectory->AddressOfNames);
    DWORD numberOfNames = pExportDirectory->NumberOfNames;
    DWORD AddressOfNameOrdinalsFOA = RVAToFOA(pExportDirectory->AddressOfNameOrdinals);
    DWORD AddressOfFunctionsFOA = RVAToFOA(pExportDirectory->AddressOfFunctions);
    DWORD ordinalOffset = -1;
    for (int i = 0; i < numberOfNames; ++i) {
        DWORD *ppName = (DWORD *) (fileBuffer + addressOfNamesFOA);
        char *pName = (char *) *ppName;
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
    printf("function: ", *pFunction);
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
    //getFunctionByName("plus", pExportDirectory);
}

int main() {
//    readFile("C:\\Users\\Chou\\Desktop\\Windows On Top.exe");
    readFile("C:\\Users\\Chou\\Desktop\\libsharedDLL.dll");
    if (fileBuffer == NULL) {
        exit(1); // 文件读取失败，退出程序
    }
//    printPEHeader();
//    printSectionTable();
    fileBufferToImageBuffer();
    imageBufferToNewBuffer();
//    DWORD FOA = RVAToFOA(0x0001F000);
//    printf("FOA:%08x\n", FOA);
//    printExportTable();
    free(fileBuffer);
    free(imageBuffer);
    free(newBuffer);
    return 0;
}
