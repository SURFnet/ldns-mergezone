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

#ifndef _LDNS_MERGEZONE_VERIFY_H
#define _LDNS_MERGEZONE_VERIFY_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ldns/ldns.h>

/* Verify that the SOA serial and origin for the zones match */
int ldns_mergezone_verify_soa_and_origin(ldns_zone* left, ldns_zone* right);

/* Verify and retrieve the single signing algorithm in the zone */
int ldns_mergezone_verify_and_fetch_single_algo(ldns_zone* zone_to_verify, int* algo_id);

/* Validate signature over the specified DNSKEY set with the specified RRSIG(s) */
int ldns_mergezone_verify_validate_dnskey_sig(ldns_rr_list* dnskey_set, ldns_rr_list* dnskey_rrsigs);

/* Verify if the specified DNSKEY set contains keys with the specified algorithm */
int ldns_mergezone_verify_dnskey_set_contains_algo(ldns_rr_list* dnskey_set, int algo);

#endif /* !_LDNS_MERGEZONE_VERIFY_H */

