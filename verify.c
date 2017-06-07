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
#include <stdint.h>
#include <string.h>
#include <ldns/ldns.h>
#include <assert.h>
#include "verify.h"
#include "verbose.h"

/* Verify that the SOA serial and origin for the zones match */
int ldns_mergezone_verify_soa_and_origin(ldns_zone* left, ldns_zone* right)
{
	assert(left != NULL);
	assert(right != NULL);

	ldns_rr*	left_soa		= NULL;
	uint32_t	left_soa_serial		= 0;
	ldns_rr*	right_soa		= NULL;
	uint32_t	right_soa_serial	= 0;
	char*		left_soa_owner		= NULL;
	char*		right_soa_owner		= NULL;

	if ((left == NULL) || (right == NULL))
	{
		return 1;
	}

	left_soa = ldns_zone_soa(left);

	if (left_soa == NULL)
	{
		fprintf(stderr, "Left-hand zone is missing an SOA record\n");

		return 1;
	}

	assert(ldns_rr_rd_count(left_soa) == 7);
	left_soa_serial = ldns_rdf2native_int32(ldns_rr_rdf(left_soa, 2));

	VERBOSE("Left-hand zone has SOA serial %u\n", left_soa_serial);

	right_soa = ldns_zone_soa(right);

	if (right_soa == NULL)
	{
		fprintf(stderr, "Right-hand zone is missing an SOA record\n");

		return 1;
	}

	assert(ldns_rr_rd_count(right_soa) == 7);
	right_soa_serial = ldns_rdf2native_int32(ldns_rr_rdf(right_soa, 2));

	VERBOSE("Right-hand zone has SOA serial %u\n", right_soa_serial);

	if (left_soa_serial != right_soa_serial)
	{
		fprintf(stderr, "SOA mismatch between left- and right-hand zone (%u != %u)\n", left_soa_serial, right_soa_serial);

		return 1;
	}

	left_soa_owner = ldns_rdf2str(ldns_rr_owner(left_soa));
	right_soa_owner = ldns_rdf2str(ldns_rr_owner(right_soa));

	if (strcasecmp(left_soa_owner, right_soa_owner) != 0)
	{
		fprintf(stderr, "Owner name of left- and right-hand SOA record differs (%s != %s)\n", left_soa_owner, right_soa_owner);

		return 1;
	}

	VERBOSE("Left-hand zone has owner name '%s'\n", left_soa_owner);
	VERBOSE("Right-hand zone has owner name '%s'\n", right_soa_owner);

	free(left_soa_owner);
	free(right_soa_owner);

	return 0;
}

/* Verify and retrieve the single signing algorithm in the zone */
int ldns_mergezone_verify_and_fetch_single_algo(ldns_zone* zone_to_verify, int* algo_id)
{
	assert(algo_id != NULL);
	assert(zone_to_verify != NULL);

	ldns_rr_list*	zone_rrs	= ldns_zone_rrs(zone_to_verify);
	size_t		i		= 0;
	int		single_algo	= -1;

	for (i = 0; i < ldns_rr_list_rr_count(zone_rrs); i++)
	{
		ldns_rr*	rr	= ldns_rr_list_rr(zone_rrs, i);

		switch(ldns_rr_get_type(rr))
		{
		case LDNS_RR_TYPE_RRSIG:
			{
				assert(ldns_rr_rd_count(rr) == 9);

				int rr_algo = ldns_rdf2native_int8(ldns_rr_rdf(rr, 1));

				if ((single_algo != -1) && (rr_algo != single_algo))
				{
					fprintf(stderr, "Found RRSIGs for more than one algorithm in the input zone\n");

					return 1;
				}

				single_algo = rr_algo;
			}
			break;
		default:
			/* Skip */
			break;
		}
	}

	VERBOSE("Input zone has %zd resource records\n", ldns_rr_list_rr_count(zone_rrs));

	*algo_id = single_algo;

	return 0;
}

