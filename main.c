#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe_struct.h"

long fileSize;
BYTE *fileBuffer;
BYTE *imageBuffer;
BYTE *newBuffer;
const struct _IMAGE_DOS_HEADER *gFileImageDosHeader;
const struct _IMAGE_NT_HEADERS *gFileImageNtHeaders;
const struct _IMAGE_FILE_HEADER *gFileImageFileHeader;
const struct _IMAGE_OPTIONAL_HEADER *gFileImageOptionalHeader;
const struct _IMAGE_SECTION_HEADER *gFileImageSectionHeader;

const struct _IMAGE_DOS_HEADER *gVirtualImageDosHeader;
const struct _IMAGE_NT_HEADERS *gVirtualImageNtHeaders;
const struct _IMAGE_FILE_HEADER *gVirtualImageFileHeader;
const struct _IMAGE_OPTIONAL_HEADER *gVirtualImageOptionalHeader;
const struct _IMAGE_SECTION_HEADER *gVirtualImageSectionHeader;

struct _IMAGE_DOS_HEADER *gNewDosHeader;
struct _IMAGE_NT_HEADERS *gNewNtHeaders;
struct _IMAGE_FILE_HEADER *gNewFileHeader;
struct _IMAGE_OPTIONAL_HEADER *gNewOptionalHeader;
struct _IMAGE_SECTION_HEADER *gNewSectionHeader;

void initialFileHeader() {
    gFileImageDosHeader = (struct _IMAGE_DOS_HEADER *) fileBuffer;
    gFileImageNtHeaders = (struct _IMAGE_NT_HEADERS *) (fileBuffer + gFileImageDosHeader->e_lfanew);
    gFileImageFileHeader = &(gFileImageNtHeaders->FileHeader);
    gFileImageOptionalHeader = &(gFileImageNtHeaders->OptionalHeader);
    gFileImageSectionHeader = (struct _IMAGE_SECTION_HEADER *) ((BYTE *) gFileImageOptionalHeader +
                                                                gFileImageFileHeader->SizeOfOptionalHeader);
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
    printf("e_magic: %04x\n", gFileImageDosHeader->e_magic);
    printf("e_lfanew: %08x\n", gFileImageDosHeader->e_lfanew);
    printf("Signature: %04x\n", gFileImageNtHeaders->Signature);
    printf("Machine: %04x\n", gFileImageFileHeader->Machine);
    printf("Magic: %04x\n", gFileImageOptionalHeader->Magic);
}

void printSectionTable() {
    printf("section name:%s\n", gFileImageSectionHeader->Name);
    printf("PointerToRawData:%08x\n", gFileImageSectionHeader->PointerToRawData);
}

void fileBufferToImageBuffer() {
    DWORD sizeOfImage = gFileImageOptionalHeader->SizeOfImage;
    imageBuffer = (BYTE *) malloc(sizeOfImage);
    if (imageBuffer == NULL) {
        printf("Failed to allocate memory for imageBuffer.\n");
        return;
    }
    memset(imageBuffer, 0x00, sizeOfImage);
    //拷贝头和节表
    memcpy(imageBuffer, fileBuffer, gFileImageOptionalHeader->SizeOfHeaders);
    //拷贝节区
    WORD numOfSections = gFileImageFileHeader->NumberOfSections;
    for (int i = 0; i < numOfSections; ++i) {
        const struct _IMAGE_SECTION_HEADER *curSectionHeader = gFileImageSectionHeader + i;
        //节区起始位置
        BYTE *pFileSection = (BYTE *) fileBuffer + curSectionHeader->PointerToRawData;
        BYTE *pImageSection = (BYTE *) imageBuffer + curSectionHeader->VirtualAddress;
        memcpy(pImageSection, pFileSection, curSectionHeader->SizeOfRawData);
    }
}

void initialVirtualHeader() {
    gVirtualImageDosHeader = (struct _IMAGE_DOS_HEADER *) imageBuffer;
    gVirtualImageNtHeaders = (struct _IMAGE_NT_HEADERS *) (imageBuffer + gVirtualImageDosHeader->e_lfanew);
    gVirtualImageFileHeader = &(gVirtualImageNtHeaders->FileHeader);
    gVirtualImageOptionalHeader = &(gVirtualImageNtHeaders->OptionalHeader);
    gVirtualImageSectionHeader = (struct _IMAGE_SECTION_HEADER *) ((BYTE *) gVirtualImageOptionalHeader +
                                                                   gVirtualImageFileHeader->SizeOfOptionalHeader);
}

void initialNewBufferHeader() {
    gNewDosHeader = (struct _IMAGE_DOS_HEADER *) newBuffer;
    gNewNtHeaders = (struct _IMAGE_NT_HEADERS *) (newBuffer + gNewDosHeader->e_lfanew);
    gNewFileHeader = &(gNewNtHeaders->FileHeader);
    gNewOptionalHeader = &(gNewNtHeaders->OptionalHeader);
    gNewSectionHeader = (struct _IMAGE_SECTION_HEADER *) ((BYTE *) gNewOptionalHeader +
                                                          gNewFileHeader->SizeOfOptionalHeader);
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
    //messageBoxA的地址 0x77530C10，这是绝对地址，所以参与计算的其它地址也用绝对地址，注意这个地址可能会变
    //E8指令之后的地址=blankVirtualOffset+8+5+imageBase
    DWORD E8AppendOffset = 0x77530C10 - (blankVirtualOffset + 8 + 5 + 0x00400000);
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
    //修改OEP为植入代码的位置，在文件偏移地址0x128位置
    memcpy(newBuffer + 0x128, &blankVirtualOffset, 4);
}

void writeFile(DWORD newBufferSize) {
    FILE *outFile = fopen("C:\\Users\\Chou\\Desktop\\Windows On Top_new.exe", "wb");
    if (outFile == NULL) {
        printf("Failed to open file: %s\n", outFile);
        exit(1);
    }
    size_t writeCount = fwrite(newBuffer, newBufferSize, 1, outFile);
    if (writeCount != 1) {
        printf("Failed to write file.\n");
    }
    fclose(outFile);
}

//newBuffer为新的fileBuffer
void imageBufferToNewBuffer() {
    initialVirtualHeader();
    //计算newBuffer大小，公式为SizeOfHeaders按fileAlignment对齐+各节区的SizeOfRawData
    //还有更简便的，最后一个节区的PointerToRawData + SizeOfRawData就是整个PE文件的大小。这种暂时不做
    //将SizeOfHeaders按fileAlignment对齐
    DWORD sizeOfHeaders = gVirtualImageOptionalHeader->SizeOfHeaders;
    DWORD fileAlignment = gVirtualImageOptionalHeader->FileAlignment;
    DWORD newBufferSize = (sizeOfHeaders + fileAlignment - 1) & ~(fileAlignment - 1);
    for (int i = 0; i < gVirtualImageFileHeader->NumberOfSections; ++i) {
        newBufferSize += (gVirtualImageSectionHeader + i)->SizeOfRawData;
    }
    newBuffer = (BYTE *) malloc(newBufferSize);
    if (newBuffer == NULL) {
        printf("Failed to allocate memory for newBuffer.\n");
        return;
    }
    memset(newBuffer, 0x00, newBufferSize);
    memcpy(newBuffer, imageBuffer, sizeOfHeaders);
    for (int i = 0; i < gVirtualImageFileHeader->NumberOfSections; ++i) {
        const struct _IMAGE_SECTION_HEADER *curSectionHeader = gVirtualImageSectionHeader + i;
        BYTE *pImageSection = (BYTE *) imageBuffer + curSectionHeader->VirtualAddress;
        BYTE *pNewBufferSection = (BYTE *) newBuffer + curSectionHeader->PointerToRawData;
        memcpy(pNewBufferSection, pImageSection, curSectionHeader->SizeOfRawData);
    }
    initialNewBufferHeader();
    implantCode();
    writeFile(newBufferSize);
}

//节区中虚拟内存偏移地址转文件偏移地址，不考虑VirtualSize比SizeOfRawData大的情况
DWORD RVAToFOA(const BYTE *pVirtualAddress) {
    //传入的是绝对地址，需要计算偏移地址
    DWORD RVA = pVirtualAddress - imageBuffer;
    //第几个节区
    int sectionIndex = -1;
    //节区起始位置的偏移
    DWORD offset = -1;
    for (int i = 0; i < gVirtualImageFileHeader->NumberOfSections; ++i) {
        const struct _IMAGE_SECTION_HEADER *pSectionTable = gVirtualImageSectionHeader + i;
        if (RVA >= pSectionTable->VirtualAddress &&
            RVA <= pSectionTable->VirtualAddress + pSectionTable->Misc.VirtualSize) {
            sectionIndex = i;
            offset = RVA - pSectionTable->VirtualAddress;
            break;
        }
    }
    if (sectionIndex == -1 || offset == -1) {
        printf("RVA地址或偏移值非法！\n");
    }
    return (gFileImageSectionHeader + sectionIndex)->PointerToRawData + offset;
}

int main() {
    readFile("C:\\Users\\Chou\\Desktop\\Windows On Top.exe");
    if (fileBuffer == NULL) {
        exit(1); // 文件读取失败，退出程序
    }
    printPEHeader();
    printSectionTable();
    fileBufferToImageBuffer();
    imageBufferToNewBuffer();
    DWORD FOA = RVAToFOA(imageBuffer + 0x0001F000);
    printf("FOA:%08x\n", FOA);
    free(fileBuffer);
    free(imageBuffer);
    free(newBuffer);
    return 0;
}
