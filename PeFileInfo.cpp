#include "windows.h"
#include "stdio.h"
#include <iostream>
#include <string>

#define TO_PSTRUCT(TYPE, offset) (TYPE)(pImageBase+(offset)) //RVA
#define VAR_OF_PSTRUCT(var, TYPE, offset) TYPE var = TO_PSTRUCT(TYPE, offset)


using namespace std;

class ExceptionInfoPeFIle {

public:
	ExceptionInfoPeFIle(string message) : message{ message } {}
	string getMessage() const { return message; }

private:
	string message;
};

class InfoPeFile {

private:

	PUCHAR pImageBase;

	struct PeStruct {
		PIMAGE_DOS_HEADER pDosHeader;
		PUCHAR p;
		WORD nSections;
		PIMAGE_SECTION_HEADER pSectionHeader;
		CHAR nmSection[9];
		PIMAGE_NT_HEADERS pTempPeHeader;
	};
	PeStruct pestruct;

public:

	InfoPeFile(LPCWSTR FilePath) {

		// preparation section
		HANDLE hFile = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == hFile) {
			printf("ERROR: LoadPeFile: CreateFile fails with %d error \n", GetLastError());
			throw ExceptionInfoPeFIle("ERROR: LoadPeFile: CreateFile fails with error\n");
		}

		HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);
		if (NULL == hFileMapping) {
			printf("ERROR: LoadPeFile: CreateFileMapping fails with %d error \n", GetLastError());
			throw ExceptionInfoPeFIle("ERROR: LoadPeFile: CreateFileMapping fails with error \n");
		}

		LPVOID p = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
		if (NULL == p) {
			printf("ERROR: LoadPeFile: MapViewOfFile fails with %d error \n", GetLastError());
			throw ExceptionInfoPeFIle("ERROR: LoadPeFile: CreateFile fails with error\n");
		}


		// init section
		this->pImageBase = (PUCHAR)p;

		this->pestruct.pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;

		VAR_OF_PSTRUCT(pTempPeHeader, PIMAGE_NT_HEADERS, this->pestruct.pDosHeader->e_lfanew);
		this->pestruct.pTempPeHeader = pTempPeHeader;

		this->pestruct.p = (PUCHAR)(&(this->pestruct.pTempPeHeader)->Signature);

		this->pestruct.nSections = this->pestruct.pTempPeHeader->FileHeader.NumberOfSections;

		this->pestruct.pSectionHeader = nullptr;
	}

	void PrintSignaturePeFile() {
		printf("MS-DOS Signature: %c%c \n", this->pImageBase[0], this->pImageBase[1]);
	}
	void PrintArchitecturePeFile() {
		switch (this->pestruct.pTempPeHeader->FileHeader.Machine) {
		case IMAGE_FILE_MACHINE_I386:
			printf("PE Architecture: x86 \n");
			this->pestruct.pSectionHeader = (PIMAGE_SECTION_HEADER)(((PUCHAR)this->pestruct.pTempPeHeader) + sizeof(IMAGE_NT_HEADERS32));
			break;
		case IMAGE_FILE_MACHINE_AMD64:
			printf("PE Architecture: x64 \n");
			this->pestruct.pSectionHeader = (PIMAGE_SECTION_HEADER)(((PUCHAR)this->pestruct.pTempPeHeader) + sizeof(IMAGE_NT_HEADERS64));
			break;
		default:
			printf("PE Architecture: unknown \n");
			throw ExceptionInfoPeFIle("PE Architecture: unknown \n");
			break;
		}
	}
	void PrintPeSection() {
		memset(this->pestruct.nmSection, 0, sizeof(this->pestruct.nmSection));
		for (int i = 0; i < this->pestruct.nSections; i++) {
			memcpy(this->pestruct.nmSection, this->pestruct.pSectionHeader->Name, 8);
			printf("section #%i %s \n", i, this->pestruct.nmSection);
			this->pestruct.pSectionHeader++;
		}
	}

};


int wmain(int argc, wchar_t* argv[])
{
	if (argc != 2) {
		printf("Usage: SeconLab PeFilePath \n");
		return -1;
	}

	LPCWSTR g_FilePath = argv[1];
	InfoPeFile* example = NULL;


	// исключение
	try {
		example = new InfoPeFile(g_FilePath);
	}
	catch (ExceptionInfoPeFIle e) {
		exit(-1);
	}

	example->PrintSignaturePeFile();
	example->PrintArchitecturePeFile();
	example->PrintPeSection();


}
