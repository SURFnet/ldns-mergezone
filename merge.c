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
#include <ldns/ldns.h>
#include <errno.h>
#include "merge.h"
#include "verify.h"
#include "verbose.h"
#include "dnssec_ht.h"

int ldns_mergezone_merge(const char* from_zone, const char* to_zone, const char* out_zone, const int out_type)
{
	ldns_zone*	from			= NULL;
	ldns_zone*	to			= NULL;
	FILE*		from_fp			= fopen(from_zone, "r");
	FILE*		to_fp			= fopen(to_zone, "r");
	FILE*		out_fp			= NULL;
	int		from_algo		= 0;
	int		to_algo			= 0;
	ldns_rr_list*	output_dnskeys		= NULL;
	int		wrote_dnskeys_and_sigs	= 0;
	size_t		i			= 0;
	size_t		out_recs		= 0;
	ldns_rr_list*	zone_rrs		= NULL;
	dnssec_ht	from_ht;
	dnssec_ht	to_ht;

	if (from_fp == NULL)
	{
		fprintf(stderr, "Failed to open %s for reading\n", from_zone);

		return 1;
	}

	if (to_fp == NULL)
	{
		fprintf(stderr, "Failed to open %s for reading\n", to_zone);

		return 1;
	}

	/* Read zones */
	if (ldns_zone_new_frm_fp(&from, from_fp, NULL, 3600, LDNS_RR_CLASS_IN) != LDNS_STATUS_OK)
	{
		fprintf(stderr, "Failed to read zone data from %s\n", from_zone);

		return 1;
	}

	VERBOSE("Read input zone from %s\n", from_zone);

	if (ldns_zone_new_frm_fp(&to, to_fp, NULL, 3600, LDNS_RR_CLASS_IN) != LDNS_STATUS_OK)
	{
		fprintf(stderr, "Failed to read zone data from %s\n", to_zone);

		return 1;
	}

	VERBOSE("Read input zone from %s\n", to_zone);

	fclose(from_fp);
	fclose(to_fp);

	/* Sort zones */
	/*ldns_zone_sort(from);
	ldns_zone_sort(to);*/

	/* Perform pre-merge verification of input zones */
	if (ldns_mergezone_verify_soa_and_origin(from, to) != 0)
	{
		fprintf(stderr, "SOA or origin verification failed\n");

		return 1;
	}

	VERBOSE("Checking algorithm in zone %s\n", from_zone);

	if (ldns_mergezone_verify_and_fetch_single_algo(from, &from_algo) != 0)
	{
		fprintf(stderr, "\"From\" input zone has records with more than one DNSSEC algorithm\n");

		return 1;
	}

	VERBOSE("\"From\" zone is signed using algorithm %d\n", from_algo);

	VERBOSE("Checking algorithm in zone %s\n", to_zone);

	if (ldns_mergezone_verify_and_fetch_single_algo(to, &to_algo) != 0)
	{
		fprintf(stderr, "\"To\" input zone has records with more than one DNSSEC algorithm\n");

		return 1;
	}

	VERBOSE("\"To\" zone is signed using algorithm %d\n", to_algo);

	/* Populate hash tables for both zones */
	VERBOSE("Populating DNSSEC hash table for %s\n", from_zone);

	if (ldns_mergezone_populate_dnssec_ht(from, &from_ht) != 0)
	{
		fprintf(stderr, "Failed to populate DNSSEC hash table for %s\n", from_zone);

		return 1;
	}

	VERBOSE("Populating DNSSEC hash table for %s\n", to_zone);

	if (ldns_mergezone_populate_dnssec_ht(to, &to_ht) != 0)
	{
		fprintf(stderr, "Failed to populate DNSSEC hash table for %s\n", to_zone);

		return 1;
	}

	/* Validate DNSKEY RRsets in input zones */
	VERBOSE("Validating DNSKEY RRset signatures in \"From\" zone\n");

	if (ldns_mergezone_verify_validate_dnskey_sig(ldns_mergezone_get_dnskeys(&from_ht), ldns_mergezone_get_dnskey_rrsigs(&from_ht)) != 0)
	{
		fprintf(stderr, "DNSKEY RRset in \"From\" zone cannot be validated\n");

		return 1;
	}

	VERBOSE("Validating DNSKEY RRset signatures in \"To\" zone\n");

	if (ldns_mergezone_verify_validate_dnskey_sig(ldns_mergezone_get_dnskeys(&to_ht), ldns_mergezone_get_dnskey_rrsigs(&to_ht)) != 0)
	{
		fprintf(stderr, "DNSKEY RRset in \"To\" zone cannot be validated\n");

		return 1;
	}

	/* Validate correct content of DNSKEY RRsets based on the desired output zone */
	switch(out_type)
	{
	case 1:
		/* 
		 * From zone must contain DNSKEYs with the 'from' algorithm,
		 * but not with the 'to' algorithm.
		 *
		 * To zone must contain DNSKEYs with the 'from' algorithm,
		 * and with the 'to' algorithm.
		 */
		{
			VERBOSE("Verifying the \"From\" zone only contains DNSKEYs with the \"from\" algorithm\n");

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&from_ht), from_algo) != 0)
			{
				fprintf(stderr, "\"From\" zone does not contain DNSKEYs with the \"from\" algorithm\n");

				return 1;
			}

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&from_ht), to_algo) == 0)
			{
				fprintf(stderr, "\"From\" zone contains DNSKEYs with the \"to\" algorithm\n");

				return 1;
			}

			VERBOSE("Verification of \"From\" DNSKEY RRset successful\n");

			VERBOSE("Verifying the \"To\" zone contains DNSKEYs for both the \"from\" and the \"to\" algorithm\n");

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&to_ht), from_algo) != 0)
			{
				fprintf(stderr, "\"To\" zone does not contain DNSKEYs with the \"from\" algorithm\n");

				return 1;
			}

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&to_ht), to_algo) != 0)
			{
				fprintf(stderr, "\"To\" zone does not contain DNSKEYs with the \"to\" algorithm\n");

				return 1;
			}

			VERBOSE("Verification of \"To\" DNSKEY RRset successful\n");

			output_dnskeys = ldns_mergezone_get_dnskeys(&from_ht);

			VERBOSE("Verifying that the output DNSKEY RRset validates against the RRSIG(s) from the \"From\" zone\n");

			if (ldns_mergezone_verify_validate_dnskey_sig(output_dnskeys, ldns_mergezone_get_dnskey_rrsigs(&from_ht)) != 0)
			{
				fprintf(stderr, "Output DNSKEY RRset RRSIG(s) validation failed\n");

				return 1;
			}
		}
		break;
	case 2:
		/* 
		 * From zone must contain DNSKEYs with the 'from' algorithm,
		 * and with the 'to' algorithm.
		 *
		 * To zone must contain DNSKEYs with the 'from' algorithm,
		 * and with the 'to' algorithm.
		 */
		{
			VERBOSE("Verifying the \"From\" zone contains DNSKEYs with both the \"from\" and the \"to\" algorithm\n");

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&from_ht), from_algo) != 0)
			{
				fprintf(stderr, "\"From\" zone does not contain DNSKEYs with the \"from\" algorithm\n");

				return 1;
			}

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&from_ht), to_algo) != 0)
			{
				fprintf(stderr, "\"From\" zone does not contain DNSKEYs with the \"to\" algorithm\n");

				return 1;
			}

			VERBOSE("Verification of \"From\" DNSKEY RRset successful\n");

			VERBOSE("Verifying the \"To\" zone contains DNSKEYs for both the \"from\" and the \"to\" algorithm\n");

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&to_ht), from_algo) != 0)
			{
				fprintf(stderr, "\"To\" zone does not contain DNSKEYs with the \"from\" algorithm\n");

				return 1;
			}

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&to_ht), to_algo) != 0)
			{
				fprintf(stderr, "\"To\" zone does not contain DNSKEYs with the \"to\" algorithm\n");

				return 1;
			}

			VERBOSE("Verification of \"To\" DNSKEY RRset successful\n");

			output_dnskeys = ldns_mergezone_get_dnskeys(&to_ht);

			VERBOSE("Verifying that the output DNSKEY RRset validates against the RRSIG(s) from the \"From\" and the \"To\" zone\n");

			if (ldns_mergezone_verify_validate_dnskey_sig(output_dnskeys, ldns_mergezone_get_dnskey_rrsigs(&from_ht)) != 0)
			{
				fprintf(stderr, "Output DNSKEY RRset RRSIG(s) validation failed\n");

				return 1;
			}

			if (ldns_mergezone_verify_validate_dnskey_sig(output_dnskeys, ldns_mergezone_get_dnskey_rrsigs(&to_ht)) != 0)
			{
				fprintf(stderr, "Output DNSKEY RRset RRSIG(s) validation failed\n");

				return 1;
			}
		}
		break;
	case 3:
		/* 
		 * From zone must contain DNSKEYs with the 'from' algorithm,
		 * and with the 'to' algorithm.
		 *
		 * To zone must not contain DNSKEYs with the 'from' algorithm,
		 * but only with the 'to' algorithm.
		 */
		{
			VERBOSE("Verifying the \"From\" zone contains DNSKEYs with both the \"from\" and the \"to\" algorithm\n");

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&from_ht), from_algo) != 0)
			{
				fprintf(stderr, "\"From\" zone does not contain DNSKEYs with the \"from\" algorithm\n");

				return 1;
			}

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&from_ht), to_algo) != 0)
			{
				fprintf(stderr, "\"From\" zone does not contain DNSKEYs with the \"to\" algorithm\n");

				return 1;
			}

			VERBOSE("Verification of \"From\" DNSKEY RRset successful\n");

			VERBOSE("Verifying the \"To\" zone only contains DNSKEYs for the \"to\" algorithm\n");

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&to_ht), from_algo) == 0)
			{
				fprintf(stderr, "\"To\" zone contains DNSKEYs with the \"from\" algorithm\n");

				return 1;
			}

			if (ldns_mergezone_verify_dnskey_set_contains_algo(ldns_mergezone_get_dnskeys(&to_ht), to_algo) != 0)
			{
				fprintf(stderr, "\"To\" zone does not contain DNSKEYs with the \"to\" algorithm\n");

				return 1;
			}

			VERBOSE("Verification of \"To\" DNSKEY RRset successful\n");
			
			output_dnskeys = ldns_mergezone_get_dnskeys(&to_ht);

			VERBOSE("Verifying that the output DNSKEY RRset validates against the RRSIG(s) from the \"To\" zone\n");

			if (ldns_mergezone_verify_validate_dnskey_sig(output_dnskeys, ldns_mergezone_get_dnskey_rrsigs(&to_ht)) != 0)
			{
				fprintf(stderr, "Output DNSKEY RRset RRSIG(s) validation failed\n");

				return 1;
			}
		}
		break;
	default:
		assert(0 == 1);	/* We should never get here, but hey... */
		break;
	}

	/* Write the output zone */
	out_fp = fopen(out_zone, "w");

	if (out_fp == NULL)
	{
		fprintf(stderr, "Failed to open %s for writing\n", out_zone);

		return EPERM;
	}

	/* Output the SOA first */
	ldns_rr_print(out_fp, ldns_zone_soa(from));
	out_recs++;

	zone_rrs = ldns_zone_rrs(from);

	for (i = 0; i < ldns_rr_list_rr_count(zone_rrs); i++)
	{
		ldns_rr*	rr		= ldns_rr_list_rr(zone_rrs, i);
		ldns_rr*	merged_rrsig	= NULL;
		int		is_dnskey_rec	= 0;

		if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG)
		{
			assert(ldns_rr_rd_count(rr) == 9);

			/* Check if the type covered by the RRSIG is DNSKEY */
			uint16_t type_covered = ldns_rdf2native_int16(ldns_rr_rdf(rr, 0));

			if (type_covered == LDNS_RR_TYPE_DNSKEY)
			{
				/* Do not output this signature directly */
				is_dnskey_rec = 1;
			}
			else
			{
				/* Find the accompanying signature in the other zone */
				if (ldns_mergezone_find_rrsig_match(&to_ht, rr, &merged_rrsig) != 0)
				{
					fprintf(stderr, "Failed to find matching signature, giving up!\n");

					fclose(out_fp);

					unlink(out_zone);

					return 1;
				}

				/* Output both signatures */
				ldns_rr_print(out_fp, rr);
				ldns_rr_print(out_fp, merged_rrsig);

				out_recs += 2;
			}
		}
		else if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY)
		{
			/* Do not output this record directly */
		}
		else
		{
			/* Output unmodified resource record */
			ldns_rr_print(out_fp, rr);

			out_recs++;
		}

		if (is_dnskey_rec && !wrote_dnskeys_and_sigs)
		{
			/* Write DNSKEY RRset and accompanying signatures */
			size_t	j	= 0;

			/* Output DNSKEYs first */
			for (j = 0; j < ldns_rr_list_rr_count(output_dnskeys); j++)
			{
				ldns_rr_print(out_fp, ldns_rr_list_rr(output_dnskeys, j));

				out_recs++;
			}

			/* Output DNSKEY RRSIG records */
			for (j = 0; j < ldns_rr_list_rr_count(ldns_mergezone_get_dnskey_rrsigs(&from_ht)); j++)
			{
				ldns_rr_print(out_fp, ldns_rr_list_rr(ldns_mergezone_get_dnskey_rrsigs(&from_ht), j));

				out_recs++;
			}

			for (j = 0; j < ldns_rr_list_rr_count(ldns_mergezone_get_dnskey_rrsigs(&to_ht)); j++)
			{
				ldns_rr_print(out_fp, ldns_rr_list_rr(ldns_mergezone_get_dnskey_rrsigs(&to_ht), j));

				out_recs++;
			}

			wrote_dnskeys_and_sigs = 1;
		}
	}

	if (!wrote_dnskeys_and_sigs)
	{
		fprintf(stderr, "An error occurred while outputting the merged zone\n");

		fclose(out_fp);

		unlink(out_zone);

		return 1;
	}

	VERBOSE("Merge finished, wrote %zd records to %s\n", out_recs, out_zone);

	fclose(out_fp);

	/* Clean up */
	ldns_mergezone_dnssec_ht_free(&from_ht);
	ldns_mergezone_dnssec_ht_free(&to_ht);

	ldns_zone_deep_free(from);
	ldns_zone_deep_free(to);

	return 0;
}
 
