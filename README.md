# ldns-mergezone

Copyright (c) 2017 SURFnet bv
http://www.surf.nl/en/about-surf/subsidiaries/surfnet

All rights reserved. This tool is distributed under a BSD-style license. For more information, see LICENSE

## 1. INTRODUCTION

This tool provides functionality to merge two DNSSEC-signed zones during a DNSSEC algorithm rollover. As part of this process, three zone states are required, `ldns-mergezone` can create these three zone states based on two signed input zones, one that is signed using the "from" algorithm, and one that is signed using the "to" algorithm. The three zone states that `ldns-mergezone` can create are:

1. Zone with `DNSKEY` set with only the "from" algorithm, with signatures made with the "to" algorithm merged in. This zone is the first zone to be published during an algorithm rollover. It introduces signatures with the new algorithm.

2. Zone with `DNSKEY` set with both the "from" and the "to" algorithm, with signatures made with both algorithms. This zone is the second zone to be published during an algorithm rollover. It introduces the `DNSKEY` for the new algorithm.

3. Zone with `DNSKEY` set with only the "to" algorithm, with signatures made with both algorithms. This zone is the final zone to be published before a zone signed with only the new algorithm can be published.

We deliberately do not include a full description of the DNSSEC algorithm rollover process, please refer to [RFC 6781](https://tools.ietf.org/html/rfc6781) for a discussion of this process.

## 2. PREREQUISITES

Building `ldns-mergezone`, requires the following dependencies to be installed:

 - POSIX-compliant build system
 - make
 - libldns >= 1.6.17

## 3. BUILDING

To build `ldns-mergezone` fresh from the repository, execute the following commands:

    make

## 4. USING THE TOOL

The sections below describe how the three different zone states discussed above can be generated using `ldns-mergezone`. It assumes that there are two input zones, `myzone-fromalgo.zone`, the input zone signed with the "from" algorithm and `myzone-toalgo.zone`, the input zone signed with the "to" algorithm. Note that the content of the two zones is different during different stages of the process, due to the composition of the `DNSKEY` resource record set. The steps discussed below also describe the requirements for the `DNSKEY` resource record set in the input zones. 

If an input zone has to contain keys with both the "from" and the "to" algorithm, and you are using an automated DNSSEC-signing tool, you can achieve this situation by adding the `DNSKEY` records for the missing algorithm to the input zone that is processed by the signing tool.

The tool will check at all stages whether the input zones meet the criteria discussed in the sections below, and will output an error if this is not the case.

### 4.1 FIRST ZONE TO PUBLISH

#### REQUIREMENTS FOR INPUT ZONES

The input zone signed with the *old algorithm* (`myzone-fromalgo.zone`) **MUST** contain a `DNSKEY` resource record set that **only contains the keys for the "from" algorithm**. Consequently, the `RRSIG` over the `DNSKEY` resource record set in this zone only covers keys with the "from" algorithm, and has been created with the "from" algorithm. Note that this zone state is the production state of the zone before the algorithm rollover commences.

The input zone signed with the *new algorithm* (`myzone-toalgo.zone`) **MUST** contain a `DNSKEY` resource record set that **contains the keys for both the "from" and the "to" algorithm**. Consequently, the `RRSIG` over the `DNSKEY` resource record set in this zone covers keys with both the "from" and the "to" algorithm, and has been created with the "to" algorithm.

#### INVOKING THE TOOL

To create the first output zone to publish, based on input zones meeting the requirements as discussed above, invoke the tool as specified below:

    ldns-mergezone -f myzone-fromalgo.zone -t myzone-toalgo.zone -1 -o myzone-first.zone

If the merge succeeds, an output zone called `myzone-first.zone` will have been created.

### 4.2 SECOND ZONE TO PUBLISH

#### REQUIREMENTS FOR INPUT ZONES

The input zone signed with the *old algorithm* (`myzone-fromalgo.zone`) **MUST** contain a `DNSKEY` resource record set that **contains the keys for both the "from" and the "to" algorithm**. Consequently, the `RRSIG` over the `DNSKEY` resource record set in this zone covers keys with both the "from" and the "to" algorithm, and has been created with the "from" algorithm.

The input zone signed with the *new algorithm* (`myzone-toalgo.zone`) **MUST** contain a `DNSKEY` resource record set that **contains the keys for both the "from" and the "to" algorithm**. Consequently, the `RRSIG` over the `DNSKEY` resource record set in this zone covers keys with both the "from" and the "to" algorithm, and has been created with the "to" algorithm. Note that -- under the condition that no resource record sets have changed in the zone -- this zone can be the same zone as used in the previous step.

#### INVOKING THE TOOL

To create the second output zone to publish, based on input zones meeting the requirements as discussed above, invoke the tool as specified below:

    ldns-mergezone -f myzone-fromalgo.zone -t myzone-toalgo.zone -2 -o myzone-second.zone

If the merge succeeds, an output zone called `myzone-second.zone` will have been created.

### 4.3 THIRD ZONE TO PUBLISH

#### REQUIREMENTS FOR INPUT ZONES

The input zone signed with the *old algorithm* (`myzone-fromalgo.zone`) **MUST** contain a `DNSKEY` resource record set that **contains the keys for both the "from" and the "to" algorithm**. Consequently, the `RRSIG` over the `DNSKEY` resource record set in this zone covers keys with both the "from" and the "to" algorithm, and has been created with the "from" algorithm. Note that -- under the condition that no resource record sets have changed in the zone -- this zone can be the same zone as used in the previous step.

The input zone signed with the *new algorithm* (`myzone-toalgo.zone`) **MUST** contain a `DNSKEY` resource record set that **only contains the keys for the "to" algorithm**. Consequently, the `RRSIG` over the `DNSKEY` resource record set in this zone only covers keys with for the "to" algorithm, and has been created with the "to" algorithm. Note that this zone state is equal to the production state of the zone after the algorithm rollover completes.

#### INVOKING THE TOOL

To create the third output zone to publish, based on input zones meeting the requirements as discussed above, invoke the tool as specified below:

    ldns-mergezone -f myzone-fromalgo.zone -t myzone-toalgo.zone -3 -o myzone-third.zone

If the merge succeeds, an output zone called `myzone-third.zone` will have been created.

### 4.4 COMMAND-LINE OPTIONS

More information on the command-line options of `ldns-mergezone` can be obtained by running:

    ldns-mergezone -h

# 5. CONTACT

Questions/remarks/suggestions/praise on this tool can be sent to:

Roland van Rijswijk-Deij <roland.vanrijswijk@surfnet.nl>
