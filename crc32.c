#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "crc32.h"

extern uint32_t crc_tableil8_o32[256];
extern uint32_t crc_tableil8_o40[256];
extern uint32_t crc_tableil8_o48[256];
extern uint32_t crc_tableil8_o56[256];
extern uint32_t crc_tableil8_o64[256];
extern uint32_t crc_tableil8_o72[256];
extern uint32_t crc_tableil8_o80[256];
extern uint32_t crc_tableil8_o88[256];

uint32_t crc32(
	uint32_t*		p_running_crc,
	const uint8_t*	p_buf,
	const uint32_t	length,
	uint8_t			mode)
{
	uint32_t li;
	uint32_t crc, term1, term2;
	uint32_t running_length;
	uint32_t end_bytes;
	crc = *p_running_crc;
	running_length = ((length) / 8) * 8;
	end_bytes = length - running_length;

	for(li = 0; li < running_length / 8; li++) {
		crc ^= *(uint32_t *)p_buf;
		p_buf += 4;
		term1 = crc_tableil8_o88[crc & 0x000000FF] ^
				crc_tableil8_o80[(crc >> 8) & 0x000000FF];
		term2 = crc >> 16;
		crc = term1 ^
			  crc_tableil8_o72[term2 & 0x000000FF] ^ 
			  crc_tableil8_o64[(term2 >> 8) & 0x000000FF];
		term1 = crc_tableil8_o56[(*(uint32_t *)p_buf) & 0x000000FF] ^
				crc_tableil8_o48[((*(uint32_t *)p_buf) >> 8) & 0x000000FF];
		
		term2 = (*(uint32_t *)p_buf) >> 16;
		crc =	crc ^ 
				term1 ^		
				crc_tableil8_o40[term2  & 0x000000FF] ^	
				crc_tableil8_o32[(term2 >> 8) & 0x000000FF];	
		p_buf += 4;
	}
	for(li = 0; li < end_bytes; li++) 
		crc = crc_tableil8_o32[(crc ^ *p_buf++) & 0x000000FF] ^ (crc >> 8);

	return crc;		
}

#ifdef TEST_CRC32

int main (int argc, char *argv[]) {
	FILE *fptr;
	size_t result;
	unsigned char *buffer;
	buffer = (unsigned char *)malloc(BYTES_READ);
	if(argc < 2) {
		fprintf(stderr, "%s: No input file specified.\n", argv[0]);
		return EXIT_FAILURE;
	}
	int fcnt;
	for (fcnt = 1; fcnt < argc; fcnt++) {
		struct stat file_info;
		stat(argv[fcnt], &file_info);
		if (S_ISDIR(file_info.st_mode)) {
			fprintf(stderr, "%s: %s: Is a directory\n", argv[0], argv[fcnt]);
			continue;	
		}
		fptr = fopen(argv[fcnt], "rb");
		if (fptr == NULL) {
			if (access(argv[fcnt], F_OK) == -1)
				fprintf(stderr, "%s: No such file or directory\n", argv[0]);
			else if (access(argv[fcnt], R_OK) == -1)
				fprintf(stderr, "%s: Permission denied\n", argv[0]);
			continue;
		}

		unsigned int crc = 0xFFFFFFFF;
		while(!feof(fptr)) {
			result = fread(buffer, 1, BYTES_READ, fptr);
			crc = crc32(&crc, buffer, result, 1);
			if (result < BYTES_READ)
				crc ^= 0xFFFFFFFF;
		}

		printf("%08x", crc);
		if (argc > 2)
			printf("\t%s\n", argv[fcnt]);
		else
			printf("\n");

		fclose(fptr);
	}

	free(buffer);
	return EXIT_SUCCESS;
}

#endif /* TEST_CRC32 */
