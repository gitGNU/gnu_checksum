#include <stdio.h>

#include "types.h"
#include "crc32.h"
#include "md5.h"

unsigned char buffer[BYTES_READ];

Boolean_T crc32file(char *fname, uint32_t *crc, uint32_t *charcnt){

  FILE *fptr;
  size_t result;

  fptr = fopen(fname, "rb");
  if (fptr == NULL) {
    if (access(fname, F_OK) == -1)
      fprintf(stderr, "%s: No such file or directory\n", fname);
    else if (access(fname, R_OK) == -1)
      fprintf(stderr, "%s: Permission denied\n", fname);
    return Error_;
  }

  *crc = 0xFFFFFFFF;
  while(!feof(fptr)) {
    result = fread(buffer, 1, BYTES_READ, fptr);
    *crc = crc32(crc, buffer, result, 1);
    if (result < BYTES_READ)
      *crc ^= 0xFFFFFFFF;
  }

  return Success_;
}



int md5file(const unsigned char *fname, unsigned char *signature, char *result){
    FILE *fin = stdin;
    int nn;
    struct MD5Context md5c;

    if (strcmp(fname, "-") != 0) {
	if ((fin = fopen(fname, "rb")) == NULL) {
	    fprintf(stderr, "Cannot open input file %s\n", fname);
	    return 2;
	    }
	}

#ifdef _WIN32
    /** Warning!  On systems which distinguish text mode and
	    binary I/O (MS-DOS, Macintosh, etc.) the modes in the open
            statement for "fin" should have forced the input file into
            binary mode.  But what if we're reading from standard
	    input?  Well, then we need to do a system-specific tweak
            to make sure it's in binary mode.  While we're at it,
            let's set the mode to binary regardless of however fopen
	    set it.

	    The following code, conditional on _WIN32, sets binary
	    mode using the method prescribed by Microsoft Visual C 5.0
            ("Monkey C"); this may require modification if you're
	    using a different compiler or release of Monkey C.	If
            you're porting this code to a different system which
            distinguishes text and binary files, you'll need to add
	    the equivalent call for that system. */

    _setmode(_fileno(fin), _O_BINARY);
#endif

    MD5Init(&md5c);
    while ((nn = fread(buffer, 1, sizeof buffer, fin)) > 0) {
	MD5Update(&md5c, buffer, (unsigned) nn);
	}
    MD5Final(signature, &md5c);

    if (strcmp(fname, "-") != 0) fclose(fin);

    for (nn = 0; nn < MD5_SIG_SIZE; nn++) {
	sprintf(result, "%s%02X", result, signature[nn]);
	}
    return(0);
}

int md5checksig(unsigned char *signature, unsigned char *csig){
    int nn, docheck = 0;

    for (nn = 0; nn < MD5_SIG_SIZE; nn++) {
	if (signature[nn] != csig[nn]) {
	    docheck = 1;
	    break;
	    }
	}
    return(docheck);
}

