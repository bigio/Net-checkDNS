#!/usr/bin/perl

# BSD 2-Clause License
#
# Copyright (c) 2021, Giovanni Bechis
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;

package Net::checkDNS;

use Net::DNS;

# Resolve an host, returns an arrays of corresponding ip
sub resolve_host($$) {
  my $host = shift;
  my $pub_res = shift;

  my @result;
  my $rr;
  my $count = 0;
  my $query = $pub_res->search($host);

  if ($query) {
    foreach my $rr ($query->answer) {
      next unless $rr->type eq "A";
        $result[$count] = $rr->address;
        $count++;
    }
  } else {
    return undef;
    # warn "query failed: ", $pub_res->errorstring, "\n";
  }
  return @result;
}

# Check if an host resolves as a CNAME
sub check_cname($$) {
  my $host = shift;
  my $auth_res = shift;

  my $rr;
  my $query = $auth_res->search($host);

  if ($query) {
    foreach my $rr ($query->answer) {
      next unless $rr->type eq "CNAME";
      return 1;
    }
  } else {
    # warn "query failed: ", $auth_res->errorstring, "\n";
  }
  return 0;
}

# Find authoritative name servers
sub find_ns($$$) {
  my $domain = shift;
  my $auth_res = shift;
  my $pub_res = shift;

  my @result;
  my @resolved;
  my $count = 0;

  my $query = $auth_res->query($domain, "NS");

  if ($query) {
    foreach my $rr (grep { $_->type eq 'NS' } $query->answer) {
      $result[$count]{'NS'} = $rr->nsdname;
      @resolved = &resolve_host( $rr->nsdname, $pub_res);
      for my $i ( 0 .. (@resolved - 1) ) {
        $result[$count]{'NS_RESOLVED'} = $resolved[$i];
      }
      $count++;
    }
   } else {
     # warn "query failed: ", $auth_res->errorstring, "\n";
   }
  return @result;
}

# Find mail exchange servers
sub find_mx($$$) {
  my $domain = shift;
  my $auth_res = shift;
  my $pub_res = shift;

  my @mx;
  my @result;
  my $count = 0;

  @mx = mx($auth_res, $domain);
  if ( @mx ) {
    foreach my $rr ( @mx ) {
      $result[$count]{'MX'} = $rr->exchange;
      $count++;
    }
  } else {
    # warn "Can't find MX records for $domain: ", $auth_res->errorstring, "\n";
  }
  return @result;
}

# Find soa record
sub find_soa($$) {
  my $domain = shift;
  my $auth_res = shift;

  my $rr;

  my $query = $auth_res->query($domain, "SOA");

  if ($query) {
    return ($query->answer)[0]->string;
  } else {
    # warn "query failed: ", $auth_res->errorstring, "\n";
    return undef;
  }
}

sub parse_soa($) {
  my $soa_record = shift;
  my %soa_info;

  # Create an hash with some infos of the SOA record
  if($soa_record =~ /(.*)\.\s+(.*)\s+IN\s+SOA\s+\(\s(.*)\.\s+(.*)\.\s+(\d+)\s+\;\w+\s+(\d+)\s+\;\w+\s+(\d+)\s+\;\w+\s+(\d+)\s+\;\w+\s+(\d+)\s+\;\w+/ms) {
    $soa_info{DOMAIN} = $1;
    $soa_info{NS} = $3;
    $soa_info{EMAIL} = $4;
    $soa_info{EMAIL} =~ s/\./\@/;
  }
  return %soa_info;
}
1;
