#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe_struct.h"

long fileSize;
BYTE *fileBuffer;
BYTE *imageBuffer;
BYTE *newBuffer;
const struct _IMAGE_DOS_HEADER *gImageDosHeader;
const struct _IMAGE_NT_HEADERS *gImageNtHeaders;
const struct _IMAGE_FILE_HEADER *gImageFileHeader;
const struct _IMAGE_OPTIONAL_HEADER *gImageOptionalHeader;
const struct _IMAGE_SECTION_HEADER *gImageSectionHeader;

// 读取文件，返回文件开头指针
void readFile(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        printf("Failed to open file: %s\n", filename);
        return;
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
    size_t numRead = fread(fileBuffer, 1, fileSize, file); // 修正 fread 参数顺序
    if (numRead != fileSize) {
        printf("Failed to read file.\n");
        free(fileBuffer);
        fclose(file);
        return;
    }
    fclose(file);
    gImageDosHeader = (struct _IMAGE_DOS_HEADER *) fileBuffer;
    gImageNtHeaders = (struct _IMAGE_NT_HEADERS *) (fileBuffer + gImageDosHeader->e_lfanew);
    gImageFileHeader = &(gImageNtHeaders->FileHeader);
    gImageOptionalHeader = &(gImageNtHeaders->OptionalHeader);
    gImageSectionHeader = (struct _IMAGE_SECTION_HEADER *) ((BYTE *) gImageOptionalHeader +
                                                            gImageFileHeader->SizeOfOptionalHeader);
}

void printPEHeader() {
    printf("e_magic: %04x\n", gImageDosHeader->e_magic);
    printf("e_lfanew: %08x\n", gImageDosHeader->e_lfanew);
    printf("Signature: %04x\n", gImageNtHeaders->Signature);
    printf("Machine: %04x\n", gImageFileHeader->Machine);
    printf("Magic: %04x\n", gImageOptionalHeader->Magic);
}

void printSectionTable() {
    printf("section name:%s\n", gImageSectionHeader->Name);
    printf("PointerToRawData:%08x\n", gImageSectionHeader->PointerToRawData);
}

void fileBufferToImageBuffer() {
    DWORD sizeOfImage = gImageOptionalHeader->SizeOfImage;
    imageBuffer = (BYTE *) malloc(sizeOfImage);
    memset(imageBuffer, 0x00, sizeOfImage);
    //拷贝头和节表
    strncpy(imageBuffer, fileBuffer, gImageOptionalHeader->SizeOfHeaders);
    //拷贝节区
    WORD numOfSections = gImageFileHeader->NumberOfSections;
    for (int i = 0; i < numOfSections; ++i) {
        const struct _IMAGE_SECTION_HEADER *curSectionHeader = gImageSectionHeader + i;
        //节区起始位置
        BYTE *pFileSection = (BYTE *) fileBuffer + curSectionHeader->PointerToRawData;
        BYTE *pImageSection = (BYTE *) imageBuffer + curSectionHeader->VirtualAddress;
        memcpy(pImageSection, pFileSection, curSectionHeader->SizeOfRawData);
    }
}

//newBuffer为新的fileBuffer
void imageBufferToNewBuffer() {
    struct _IMAGE_DOS_HEADER *pImageDosHeader = (struct _IMAGE_DOS_HEADER *) imageBuffer;
    struct _IMAGE_NT_HEADERS *pImageNtHeaders = (struct _IMAGE_NT_HEADERS *) (imageBuffer + pImageDosHeader->e_lfanew);
    struct _IMAGE_FILE_HEADER *pImageFileHeader = &(pImageNtHeaders->FileHeader);
    struct _IMAGE_OPTIONAL_HEADER *pImageOptionalHeader = &(pImageNtHeaders->OptionalHeader);
    struct _IMAGE_SECTION_HEADER *pImageSectionHeader = (struct _IMAGE_SECTION_HEADER *) (
            (BYTE *) pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
    //计算newBuffer大小，公式为fileAlignment+对齐后的各节区大小，对齐使用fileAlignment
    pImageSectionHeader.
    //newBuffer = (BYTE *) malloc(newBufferSize);
}

int main() {
    readFile("C:\\Users\\Chou\\Desktop\\IPMSG2007.exe");
    if (fileBuffer == NULL) {
        return 1; // 文件读取失败，退出程序
    }
    printPEHeader();
    printSectionTable();
    fileBufferToImageBuffer();
    imageBufferToNewBuffer();
    free(fileBuffer); // 释放内存
    return 0;
}
