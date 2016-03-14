#include "stdio.h"
#include "stdlib.h"
#include "string.h"

char* input;
char* output;

#define LOADADDR    0x08048000
#define PHDRL	32
#define EHDRL	52

unsigned int address=0;
unsigned int length=0;
//unsigned int* backpatch;
int bpl = 0;

struct patchaddr{
	unsigned int f_offset;
	unsigned int m_offset;
};
typedef struct patchaddr patchaddr;
patchaddr* backpatch;

int bfc();
int wef(char* filename);

int main(int argc, char** argv){
	if(argc != 3){
		printf("not enough args\n");
		return 1;
	}

	FILE* tmp = fopen(argv[1], "rb");
	fseek(tmp, 0, SEEK_END);
	int sz = ftell(tmp);
	rewind(tmp);
	input=(char*)malloc(sizeof(char)*sz);
	char* tempsave=input;
	fread(input, 1, sz, tmp);
	input[sz]='\0';
	backpatch=(void*)malloc(sizeof(patchaddr)*1);
	printf("%s\n", input);
	bfc();
	wef(argv[2]);
	fclose(tmp);
	free(output);
	free(tempsave);
	free(backpatch);
	return 0;
}

int bfc(){
	output=(char*)malloc(sizeof(char)*strlen("\x55\x89\xE5\x44"));
	strcpy(output, "\x55\x89\xE5\x44");
	address+=4;
	length+=4;
	void* addr_calc;
	while(*input)
	{
		switch(*input){
			case '+':
				output=(char*)realloc(output, sizeof(char)*strlen("\xFE\x04\x24")+length+1);
				strcpy(&output[length], "\xFE\x04\x24");
				address+=3;
				length+=3;
				break;
			case '-':
				output=(char*)realloc(output, sizeof(char)*strlen("\xFE\x0C\x24")+length+1);
				strcpy(&output[length], "\xFE\x0C\x24");
				address+=3;
				length+=3;
				break;
			case '>':
				output=(char*)realloc(output, sizeof(char)*length+2);
				output[length++]='\x44'; //inc
				address++;
				break;
			case '<':
				output=(char*)realloc(output, sizeof(char)*length+2);
				output[length++]='\x4C'; //dec
				address++;
				break;
			case '[':
				output=(char*)realloc(output, sizeof(char)*11+length);
				memcpy(&output[length], "\x80\x3C\x24\x00\x0F\x84\x00\x00\x00\x00", 10);
				address+=10;
				length+=10;
				backpatch=(void*)realloc(backpatch, sizeof(patchaddr)*(bpl+1));
				backpatch[bpl++].m_offset=address-6;
				backpatch[bpl-1].f_offset=length-6;
				break;
			case ']':
				addr_calc = &output[backpatch[--bpl].f_offset]+2;
				*(int*)addr_calc = address+5-(backpatch[bpl].m_offset+6);//patch up previous
				output=(char*)realloc(output, sizeof(char)*3+length);
				memcpy(&output[length], "\xE9", 1);
				address+=1;
				length+=1;
				addr_calc = &output[length];
				*(int*)addr_calc = -1*(address-1 - (backpatch[bpl].m_offset-4)+5);
				address+=4;
				length+=4;
				break;
		}
		input++;
	}
	output=(char*)realloc(output, sizeof(char)*17+length); //exit on linux
	memcpy(&output[length], "\x31\xDB\x8A\x1C\x24\x89\xEC\x5D\xB8\x01\x00\x00\x00\xCD\x80", 15);
	address+=15;
	length+=15;
	FILE *tmp;
	if(tmp = fopen("out.elf", "wb")){
		fwrite(output, 1, length, tmp);
		fclose(tmp);
	}
	else
		printf("file can't be opened");
	return 0;
}

int wef(char* filename){
	char* elffile=(char*)malloc(sizeof(char)*52+32+length);//enough for ehdr+phdr
	int elfoffset=0;
	memcpy(elffile, "\x7F\x45\x4C\x46\x01\x01\x01\0", 8);//magic
	elfoffset+=8;
	memset(&elffile[elfoffset], 0, 8);
	elfoffset+=8;
	memcpy(&elffile[elfoffset], "\x02\x00\x03\x00\x01\x00\x00\x00", 8);//type
	elfoffset+=8;
	memcpy(&elffile[elfoffset], "\x54\x80\x04\x08\x34\0\0\0", 8);
	elfoffset+=8;
	memcpy(&elffile[elfoffset], "\0\0\0\0\0\0\0\0", 8);
	elfoffset+=8;
	memcpy(&elffile[elfoffset], "\x34\0\x20\0\x01\0", 6);
	elfoffset+=6;
	memcpy(&elffile[elfoffset], "\0\0\0\0\0\0", 6);
	elfoffset+=6;
	//now we enter the phdr
	memcpy(&elffile[elfoffset], "\x1\0\0\0\0\0\0\0", 8);
	elfoffset+=8;
	memcpy(&elffile[elfoffset], "\0\x80\x04\x08\0\x80\x04\x08", 8);
	elfoffset+=8;
	int filesz = 52 + 32 + length;
	memcpy(&elffile[elfoffset], &filesz, 4);
	elfoffset+=4;
	memcpy(&elffile[elfoffset], &filesz, 4);
	elfoffset+=4;
	memcpy(&elffile[elfoffset], "\x05\0\0\0\0\x10\0\0", 8);
	elfoffset+=8;
	//phdr over
	memcpy(&elffile[elfoffset], output, length);
	elfoffset+=length;
	FILE* tmp = fopen(filename, "wb");
	fwrite(elffile, 1, elfoffset, tmp);
	fclose(tmp);
	free(elffile);
	return 0;
}