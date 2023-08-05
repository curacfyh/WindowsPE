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
    FILE *outFile = fopen("C:\\Users\\Chou\\Desktop\\IPMSG2007_new.exe", "wb");
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
    readFile("C:\\Users\\Chou\\Desktop\\IPMSG2007.exe");
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
