/*

 Calculate or Check CRC32/MD5 Signature

 Copyright (c) 2000-2003 Tong Sun
 @Version: $Date: 2003/01/08 17:09:24 $ $Revision: 2.1 $
 @Home URL: http://xpt.sourceforge.net/
 
 Distribute freely, as long as the author's info & copyright are retained.
 Please refer to LICENSE for details.
 
 Original md5 algorithm is by John Walker
 http://www.fourmilab.ch/

*/


#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifdef _WIN32
 #include <fcntl.h>
 #include <io.h>
#endif

#include "md5.h"
#include "types.h"

#define FALSE	0
#define TRUE	1

#define EOS     '\0'

#define FN_SIZE 1024

#define LINE_WIDTH 80

enum MC {M_CRC = 1, M_MD5};
enum RET_CODE {RET_OK, CHECKSUM_FAILED, INTERNAL_ERROR };

void show_progress(int verbose, int *fcount);
void show_status(int verbose, int fcount);
void usage(void);

int checksumfile(unsigned char *finfo, unsigned char *result, 
		 unsigned char *signature, int method, int bare) {
    #define FNAME_EOS "\t\r\n"
    DWORD crc;
    long charcnt;
    int errors = RET_OK;
    char checksum_new[2*MD5_SIG_SIZE+1];
	
    unsigned char *sp, *fname, *checksum_org;
    unsigned long fsize;
    int checksum_format;

    enum CHECKSUM_FORMAT {FNAME_ONLY, INC_FSIZE, INC_CHECKSUM };

    sp = strtok(finfo, FNAME_EOS);
    if(sp) {
	checksum_format = FNAME_ONLY;
	fname = sp;
	}
    else {
	fprintf(stderr,	"[checksum] Internal error - null file name\n");
	return INTERNAL_ERROR;
	}
	
    checksum_new[0] = 0;
    if (bare) result[0] = 0;
    else sprintf(result, "%s\t", fname);

    sp = strtok(NULL, FNAME_EOS);
    if(sp) {
	checksum_format = INC_FSIZE;
	fsize = atol(sp);
	sprintf(result, "%s%lu\t", result, fsize);
	}

    sp = strtok(NULL, FNAME_EOS);
    if(sp) {
	struct stat fstat;
	checksum_format = INC_CHECKSUM;
	checksum_org = sp;
	/* Doing checksum, check file size first */
	if(stat(fname, &fstat)){
	    perror("\n[checksum]");
	    return CHECKSUM_FAILED;
	    }
	if(fstat.st_size != fsize) {
	    unsigned char result0[FN_SIZE+128];
	    strcpy(result0, result);
	    sprintf(result, "\n%sSize=%d\tFailed!\n",
		    result0, fstat.st_size);
	    return CHECKSUM_FAILED;
	    }
	}

    switch (method) {

    case M_CRC:             /* checksum method CRC */
	errors |= crc32file(fname, &crc, &charcnt);
	sprintf(checksum_new, "%08lX", crc);
	break;

    case M_MD5: {            /* checksum method MD5 */
	errors |= md5file(fname, signature, checksum_new);
	break;
	}
    default:
	fprintf(stderr,
		"[checksum] Internal error - unknown checksum method\n");
	return INTERNAL_ERROR;
	}

    sprintf(result, "%s%s", result, checksum_new);
    if(checksum_format == INC_CHECKSUM){
	sprintf(result, "%s\t%s", result,
		strcmp(checksum_new, checksum_org) ? "Failed!" : "Passed");
	}
    strcat(result, "\n");
    return errors;
}

/*  Main program  */

int main(int argc, char *argv[]){

    int i, j, cmdln_data = FALSE, docheck = FALSE, arg_file_tag = 0;
    int method = 0, bare = FALSE, fnstart = 0, pipein = FALSE, verbose = FALSE;
    unsigned int bp;
    char *cp, *clabel, opt;
    FILE *fin = stdin, *fout = stdout;
    unsigned char buffer[16384];
    unsigned char signature[MD5_SIG_SIZE], csig[MD5_SIG_SIZE];
    unsigned char fname[FN_SIZE], result[FN_SIZE+128];
    struct MD5Context md5c;

    DWORD crc;
    long charcnt;
    int errors = 0;

    int fcount=0;

    if (argc <= 1) usage();
    fname[0] = 0;

    for (i = 1; i < argc; i++) {
	cp = argv[i];
        if (*cp == '-') {
	    opt = *(++cp);

	    switch (opt) {

	    case 'M':		/* Method choosing */
		method = M_CRC;	/* Default method */
		if (strcmp(cp + 1, "md5") == 0) method = M_MD5;
		break;

	    case 'f':		/* rest of commandline are file names */
		fnstart = i+1;
		break;

	    case 'p':		/* file names provides from pipe */
		pipein = TRUE;
		arg_file_tag++;	/* Mark no infile argument needed */
		break;

	    case 'v':		/* verbose output */
		verbose = TRUE;
		break;

	    case 'b':		/* bare output */
		bare = TRUE;
		break;

	    case 'c':		/* -cSignature, Check signature, set ret code */
		docheck = TRUE;
		if (strlen(cp + 1) != 32) {
		    docheck = FALSE;
		    }
		memset(csig, 0, MD5_SIG_SIZE);
		clabel = cp + 1;
		for (j = 0; j < MD5_SIG_SIZE; j++) {
		    if (isxdigit(clabel[0]) && isxdigit(clabel[1]) &&
			sscanf((cp + 1 + (j * 2)), "%02X", &bp) == 1) {
			csig[j] = (unsigned char) bp;
			} else {
			    docheck = FALSE;
			    break;
			    }
		    clabel += 2;
		    }
		if (!docheck) {
		    fprintf(stderr, "[checksum] Error - "
			    "Signature specification must be 32 hex digits.\n");
		    return CHECKSUM_FAILED;
		    }
		break;

	    case 'd':		/* -dText  --  Compute signature of given text */
		strcpy(buffer, cp + 1);
		cmdln_data = TRUE;
		arg_file_tag++;	/* Mark no infile argument needed */
		break;

	    case '?':		/* -? -h -H  --  Print usage */
	    case 'h':
	    case 'H':
		usage();
		}
	    } /* -TAG */
	else {
	    if (fnstart) break;

	    /*  stay in the loop to process fin & fout */
	    switch (arg_file_tag) {
	    case 0:
		strcpy(fname, cp);
		arg_file_tag++;
		break;

	    case 1:
		if (strcmp(cp, "-") != 0) {
		    if ((fout = fopen(cp, "w")) == NULL) {
			fprintf(stderr, "Cannot open output file %s\n", cp);
			return CHECKSUM_FAILED;
			}
		    }
		arg_file_tag++;
		break;

	    default:
		fprintf(stderr, "Too many file names specified.\n");
		return CHECKSUM_FAILED;
		}
	    }
	}

    if (!method) {
	fprintf(stderr, "[checksum] Error - No checksum method chosen.\n");
	usage();
	}

    /*  == Multiple files */
    setlinebuf(stdout);
    
    if (fnstart) {		/* file names provides on commandline */
	for (i =fnstart; i < argc; i++) {
	    show_progress(verbose, &fcount);
	    errors |= checksumfile(argv[i], result, signature, method, bare);
	    fprintf(fout, "%s", result);
	    }
	show_status(verbose, fcount);
	return(errors);
	}

    if (pipein) {		/* file names provides from pipe */
	while (fgets(fname, FN_SIZE, stdin), !feof(stdin)) {
	    show_progress(verbose, &fcount);
	    errors |= checksumfile(fname, result, signature, method, bare);
	    fprintf(fout, "%s", result);
	    }
	show_status(verbose, fcount);
	return(errors);
	}

    /*  == One file only */
    if (!bare) sprintf(result, "%s\t", fname);
    if (cmdln_data) {
	MD5Init(&md5c);
	MD5Update(&md5c, buffer, strlen(buffer));
	MD5Final(signature, &md5c);
	}
    else {
	if (method == M_CRC) {
	    errors |= crc32file(fname, &crc, &charcnt);
	    sprintf(result, "%s%08lX\n", result, crc);
	    }
	else {
	    errors |= md5file(fname, signature, result);
	    strcat(result, "\n");
	    }
	fprintf(fout, "%s", result);
	}

    if (docheck) {
	docheck = md5checksig(signature, csig);
	return docheck;
	} 
    return(errors);
}

void show_progress(int verbose, int *fcount){
    if(verbose){
	if(++*fcount % LINE_WIDTH == 0) fputc('\r', stderr);
	fputc('.', stderr);
	}
}

void show_status(int verbose, int fcount){
    if(verbose){
	fprintf(stderr,"\n%d files processed.\n", fcount);
	}
}

/* Print how to call information. */
void usage(void){

    fprintf(stderr,"checksum  --  Calculate MD5/CRC signature of file.\n");
    exit(RET_OK);
}


