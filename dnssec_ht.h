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

#ifndef _LDNS_MERGEZONE_DNSSEC_HT_H
#define _LDNS_MERGEZONE_DNSSEC_HT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ldns/ldns.h>
#include "uthash.h"

/* Hash table entry type */
typedef struct
{
	char		type_and_owner[1024];
	ldns_rr*	rr;
	UT_hash_handle	hh;
}
rrsig_ht_ent;

typedef struct
{
	rrsig_ht_ent*	rrsig_ht;
	ldns_rr_list*	dnskeys;
	ldns_rr_list*	dnskey_rrsigs;
}
dnssec_ht;

/* Populate hash table with DNSSEC data from this zone */
int ldns_mergezone_populate_dnssec_ht(ldns_zone* zone, dnssec_ht* ht);

/* Find matching RRSIG */
int ldns_mergezone_find_rrsig_match(dnssec_ht* ht, ldns_rr* find, ldns_rr** found);

/* Get DNSKEYs */
ldns_rr_list* ldns_mergezone_get_dnskeys(dnssec_ht* ht);

/* Clean up */
void ldns_mergezone_dnssec_ht_free(dnssec_ht* ht);

#endif /* !_LDNS_MERGEZONE_DNSSEC_HT_H */

