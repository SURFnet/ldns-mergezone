/*
 * Copyright (c) 2017 SURFnet bv
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * - Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * - Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include "merge.h"
#include "verbose.h"

void usage(void)
{
	printf("ldns-mergezone\n");
	printf("Copyright (C) 2017 SURFnet bv\n");
	printf("All rights reserved (see LICENSE for more information)\n\n");
	printf("Usage:\n");
	printf("\tldns-mergezone -f <from-zone> -t <to-zone> [-1] [-2] [-3] -o <out-zone> [-v]\n");
	printf("\tldns-mergezone -h\n");
	printf("\n");
	printf("\t-f <from-zone> Zone signed with the \"from\" algorithm\n");
	printf("\t-t <to-zone>   Zone signed with the \"to\" algorithm\n");
	printf("\t-1             Produce first output zone type (see README.md)\n");
	printf("\t-2             Produce second output zone type (see README.md)\n");
	printf("\t-3             Produce third output zone type (see README.md)\n");
	printf("\t               (note: you must specify one of -1, -2, -3)\n");
	printf("\t-o <out-zone>  Write output to <out-zone>\n");
	printf("\t-v             Be verbose\n");
	printf("\n");
	printf("\t-h                 Print this help message\n");
}

void cleanup_openssl(void)
{
	FIPS_mode_set(0);
	ENGINE_cleanup();
	CONF_modules_unload(1);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
}

int main(int argc, char* argv[])
{
	char*	from_zone	= NULL;
	char*	to_zone		= NULL;
	char*	out_zone	= NULL;
	int	out_type	= 0;
	int	c		= 0;
	int	rv		= 0;
	
	while ((c = getopt(argc, argv, "f:t:o:123vh")) != -1)
	{
		switch(c)
		{
		case 'f':
			from_zone = strdup(optarg);
			break;
		case 't':
			to_zone = strdup(optarg);
			break;
		case 'o':
			out_zone = strdup(optarg);
			break;
		case '1':
			out_type = 1;
			break;
		case '2':
			out_type = 2;
			break;
		case '3':
			out_type = 3;
			break;
		case 'v':
			set_verbose(1);
			break;
		case 'h':
		default:
			usage();
			return 0;
		}
	}

	/* Check arguments */
	if (from_zone == NULL)
	{
		fprintf(stderr, "You must specify a \"from\" zone with -f!\n");

		return EINVAL;
	}

	if (to_zone == NULL)
	{
		fprintf(stderr, "You must specify a \"to\" zone with -t!\n");

		return EINVAL;
	}

	if (out_zone == NULL)
	{
		fprintf(stderr, "You must specify an output zone file with -o!\n");

		return EINVAL;
	}

	if (out_type == 0)
	{
		fprintf(stderr, "You must specify an output zone type with -1, -2 or -3!\n");

		return EINVAL;
	}

	/* Run merge */
	if ((rv = ldns_mergezone_merge(from_zone, to_zone, out_zone, out_type)) != 0)
	{
		fprintf(stderr, "Zone merge failed, exiting with error state\n");
	}

	cleanup_openssl();

	free(from_zone);
	free(to_zone);
	free(out_zone);
	
	return rv;
}
 
