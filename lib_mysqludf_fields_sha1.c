/* 
	lib_mysqludf_sha1 - a library of mysql udfs to generate sha1 hashes
	Copyright (C) 2014 Bernhard Kraft <kraftb@think-open.at>
	
	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.
	
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
	
	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
	
*/
#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
#define DLLEXP __declspec(dllexport) 
#else
#define DLLEXP
#endif

#ifdef STANDARD
#include <string.h>
#include <stdlib.h>
#ifdef __WIN__
typedef unsigned __int64 ulonglong;
typedef __int64 longlong;
#else
typedef unsigned long long ulonglong;
typedef long long longlong;
#endif /*__WIN__*/
#else
#include <my_global.h>
#include <my_sys.h>
#endif
#include <mysql.h>
#include <m_ctype.h>
#include <m_string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#ifdef DEBUG
#include <stdio.h>
#endif

/* For Windows, define PACKAGE_STRING in the VS project */
#ifndef __WIN__
#include "config.h"
#endif

#include <ctype.h>

#ifdef HAVE_DLOPEN

#define LIBVERSION "lib_mysqludf_fields_sha1 version 0.0.1"

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * FIELDS_SHA1 Exports
 */


DLLEXP my_bool lib_mysqludf_fields_sha1_info_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
DLLEXP void lib_mysqludf_fields_sha1_info_deinit(UDF_INIT *initid);
DLLEXP char *lib_mysqludf_fields_sha1_info(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);

DLLEXP my_bool fields_sha1_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
DLLEXP void fields_sha1_deinit(UDF_INIT *initid);
DLLEXP char* fields_sha1( UDF_INIT *initid, UDF_ARGS *args, char* result, unsigned long* length, char *is_null, char *error);

#ifdef	__cplusplus
}
#endif


/*
 * Output the library version.
 * lib_mysqludf_fields_sha1_info()
 */
my_bool lib_mysqludf_fields_sha1_info_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
	return 0;
}

void lib_mysqludf_fields_sha1_info_deinit(UDF_INIT *initid) {
}

char* lib_mysqludf_fields_sha1_info(UDF_INIT *initid, UDF_ARGS *args, char* result, unsigned long* length,	char *is_null, char *error) {
	strcpy(result, PACKAGE_STRING);
	*length = strlen(PACKAGE_STRING);
	return result;
}

/*
 * FIELDS_SHA1
 */
my_bool fields_sha1_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
	SHA_CTX *ctx = NULL;
	if (args->arg_count > 1) {
		ctx = (SHA_CTX*)malloc(sizeof(SHA_CTX));
		if (!ctx) {
			strcpy(message, "Could not allocate memory (udf: fields_sha1_init)");
			return 1;
		}
	}
	initid->ptr = (char*)ctx;
	initid->maybe_null = 0;
	initid->const_item = 0;
	return 0;
}

void fields_sha1_deinit(UDF_INIT *initid) {
	if (initid->ptr) {
		free(initid->ptr);
	}
}

void _fields_sha1_hashValue(SHA_CTX *ctx, char *data, unsigned long length) {
	char *pipe = NULL;
	char *backslash = NULL;
	char *lower = NULL;
	int hashPipe = 0;

	#ifdef DEBUG
	FILE *debug = NULL;
	debug = fopen("/tmp/debug.log", "ab");
	fprintf(debug, "Data: \"%s\" (%lu)\n", data, length);
	fflush(debug);
	#endif
	
	while (length > 0) {
		pipe = memchr(data, '|', length);
		backslash = memchr(data, '\\', length);

		#ifdef DEBUG
		fprintf(debug, "%p: %li\n%p: %li\n\n", pipe, pipe-data, backslash, backslash-data);
		fflush(debug);
		#endif

		if (pipe == NULL && backslash == NULL) {
			SHA1_Update(ctx, data, length);
			return;
		} else {
			// Determine what was encountered first: pipe or backslash
			if (pipe != NULL) {
				if (backslash != NULL) {
					if (pipe < backslash) {
						lower = pipe;
						hashPipe = 1;
					} else {
						lower = backslash;
						hashPipe = 0;
					}
				} else {
					lower = pipe;
					hashPipe = 1;
				}
			} else {
				lower = backslash;
				hashPipe = 0;
			}
		}

		#ifdef DEBUG
		fprintf(debug, "%p: %li (%d)", lower, lower-data, hashPipe);
		fflush(debug);
		#endif

		SHA1_Update(ctx, data, lower-data);
		if (hashPipe) {
			SHA1_Update(ctx, "\\|", 2);
		} else {
			SHA1_Update(ctx, "\\\\", 2);
		}
		lower++;
		length -= (lower-data);
		data = lower;

		#ifdef DEBUG
		fprintf(debug, "Data: \"%s\" (%lu)\n", data, length);
		fflush(debug);
		#endif

	}

	#ifdef DEBUG
	fprintf(debug, "--------------------------\n");
	fflush(debug);
	fclose(debug);
	#endif

}

char* fields_sha1(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error) {
	int i = 0;
	char separator = '|';
	char *tmp = NULL;
	unsigned long len = 0;
	long long int_val;
	double real_val;
	if (args->arg_count == 0) {
		SHA1(NULL, 0, result);
	} else if (args->arg_count == 1) {
		SHA1(args->args[0], args->lengths[0], result);
	} else {
		SHA1_Init((SHA_CTX*)initid->ptr);
		for (i = 0; i < args->arg_count; i++) {
			switch (args->arg_type[i]) {

				case INT_RESULT:
					int_val = *((long long*) args->args[i]);
					_fields_sha1_hashValue((SHA_CTX*)initid->ptr, (char*)&int_val, sizeof(long long));
				break;

				case REAL_RESULT:
					real_val = *((double*) args->args[i]);
					_fields_sha1_hashValue((SHA_CTX*)initid->ptr, (char*)&real_val, sizeof(double));
				break;

				default:
					if (args->args[i]) {
						_fields_sha1_hashValue((SHA_CTX*)initid->ptr, args->args[i], args->lengths[i]);
					}
				break;

			}
			if (i+1 < args->arg_count) {
				SHA1_Update((SHA_CTX*)initid->ptr, &separator, 1);
			}
		}
		SHA1_Final(result, (SHA_CTX*)initid->ptr);
	}
	*length = 20;
	return result;
}

#endif /* HAVE_DLOPEN */

#ifdef TESTING
void main(int argc, char **argv) {
	/* ----------- Test Results ------------- begin ------------ */
	// The SHA1 sum for ""
	unsigned char sha1_empty[20] = {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09};

	// The SHA1 sum for "test123"
	unsigned char sha1_test123[20] = {0x72, 0x88, 0xed, 0xd0, 0xfc, 0x3f, 0xfc, 0xbe, 0x93, 0xa0, 0xcf, 0x06, 0xe3, 0x56, 0x8e, 0x28, 0x52, 0x16, 0x87, 0xbc};

	// The SHA1 sum for "test|123"
	unsigned char sha1_testPipe123[20] = {0xd2, 0x3c, 0xb4, 0x9c, 0xb4, 0x09, 0x9e, 0x11, 0x1a, 0xc1, 0x62, 0xe3, 0x99, 0x32, 0xb7, 0x67, 0x07, 0xfb, 0x67, 0x30};

	// The SHA1 sum for "test\123"
	unsigned char sha1_testBackslash123[20] = {0x15, 0xca, 0xf8, 0x24, 0xa5, 0xa4, 0x73, 0xcc, 0x1d, 0x86, 0x6a, 0x45, 0xef, 0xd4, 0x6b, 0x54, 0xa7, 0x4f, 0xb6, 0x7f};
	/* ----------- Test Results ------------- end -------------- */

	SHA_CTX ctx;
	unsigned char buffer[20] = "";

	// Test: ""
	SHA1(NULL, 0, buffer);
	if (memcmp(buffer, sha1_empty, 20)) {
		fprintf(stderr, "Error in SHA1! (1)\n");
	}
	fprintf(stdout, "Test 1 OK\n\n");

	// Test: "test123"
	SHA1_Init(&ctx);
	_fields_sha1_hashValue(&ctx, "test123", 7);
	SHA1_Final(buffer, &ctx);
	if (memcmp(buffer, sha1_test123, 20)) {
		fprintf(stderr, "Error in SHA1! (2)\n");
	}
	fprintf(stdout, "Test 2 OK\n\n");
	
	// Test: "test|123"
	SHA1_Init(&ctx);
	_fields_sha1_hashValue(&ctx, "test|123", 8);
	SHA1_Final(buffer, &ctx);
	if (memcmp(buffer, sha1_testPipe123, 20)) {
		fprintf(stderr, "Error in SHA1! (3)\n");
	}
	fprintf(stdout, "Test 3 OK\n\n");

	// Test: "test\123"
	SHA1_Init(&ctx);
	_fields_sha1_hashValue(&ctx, "test\\123", 8);
	SHA1_Final(buffer, &ctx);
	if (memcmp(buffer, sha1_testBackslash123, 20)) {
		fprintf(stderr, "Error in SHA1! (4)\n");
	}
	fprintf(stdout, "Test 4 OK\n\n");

}
#endif

