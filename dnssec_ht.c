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
#include "dnssec_ht.h"
#include "verbose.h"
#include "uthash.h"

/* Populate hash table with DNSSEC data from this zone */
int ldns_mergezone_populate_dnssec_ht(ldns_zone* zone, dnssec_ht* ht)
{
	assert(zone != NULL);
	assert(ht != NULL);

	size_t		i		= 0;
	ldns_rr_list*	zone_rrs	= ldns_zone_rrs(zone);

	/* Initialise hash table */
	ht->rrsig_ht = NULL;
	ht->dnskeys = ldns_rr_list_new();
	ht->dnskey_rrsigs = ldns_rr_list_new();

	for (i = 0; i < ldns_rr_list_rr_count(zone_rrs); i++)
	{
		ldns_rr*	rr	= ldns_rr_list_rr(zone_rrs, i);

		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY)
		{
			ldns_rr_list_push_rr(ht->dnskeys, rr);
		}
		else if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG)
		{
			assert(ldns_rr_rd_count(rr) == 9);

			uint16_t	type_covered	= ldns_rdf2native_int16(ldns_rr_rdf(rr, 0));

			if (type_covered == LDNS_RR_TYPE_DNSKEY)
			{
				ldns_rr_list_push_rr(ht->dnskey_rrsigs, rr);
			}
			else
			{
				char		type_and_owner[1024]	= { 0 };
				char*		owner_name		= ldns_rdf2str(ldns_rr_owner(rr));
				rrsig_ht_ent*	htent			= NULL;

				snprintf(type_and_owner, 1024, "%u_%s", type_covered, owner_name);

				free(owner_name);

				HASH_FIND_STR(ht->rrsig_ht, type_and_owner, htent);

				if (htent != NULL)
				{
					fprintf(stderr, "Found second RRSIG for %s\n", type_and_owner);

					return 1;
				}

				htent = (rrsig_ht_ent*) malloc(sizeof(rrsig_ht_ent));

				memset(htent, 0, sizeof(rrsig_ht_ent));

				strcpy(htent->type_and_owner, type_and_owner);

				htent->rr = rr;

				HASH_ADD_STR(ht->rrsig_ht, type_and_owner, htent);
			}
		}
	}

	VERBOSE("Zone has %zd DNSKEY records\n", ldns_rr_list_rr_count(ht->dnskeys));
	VERBOSE("Zone has %zd DNSKEY RRSIG records\n", ldns_rr_list_rr_count(ht->dnskey_rrsigs));
	VERBOSE("Zone has %d other RRSIG records\n", HASH_COUNT(ht->rrsig_ht));

	return 0;
}

/* Find matching RRSIG */
int ldns_mergezone_find_rrsig_match(dnssec_ht* ht, ldns_rr* find, ldns_rr** found)
{
	return 0;
}

/* Get DNSKEYs */
ldns_rr_list* ldns_mergezone_get_dnskeys(dnssec_ht* ht)
{
	return 0;
}

/* Clean up */
void ldns_mergezone_dnssec_ht_free(dnssec_ht* ht)
{
	assert(ht != NULL);
	assert(ht->dnskeys != NULL);
	assert(ht->dnskey_rrsigs != NULL);

	rrsig_ht_ent*	ht_it	= NULL;
	rrsig_ht_ent*	ht_tmp	= NULL;

	ldns_rr_list_free(ht->dnskeys);
	ldns_rr_list_free(ht->dnskey_rrsigs);

	HASH_ITER(hh, ht->rrsig_ht, ht_it, ht_tmp)
	{
		HASH_DEL(ht->rrsig_ht, ht_it);

		free(ht_it);
	}

	ht->dnskeys = NULL;
	ht->dnskey_rrsigs = NULL;
	ht->rrsig_ht = NULL;
}

