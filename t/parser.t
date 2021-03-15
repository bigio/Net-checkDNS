#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

plan tests => 3;

use Net::checkDNS;

my $soa = 'github.com.     380     IN      SOA     ( ns-1707.awsdns-21.co.uk. awsdns-hostmaster.amazon.com.
                                1               ;serial
                                7200            ;refresh
                                900             ;retry
                                1209600         ;expire
                                86400           ;minimum
        )';
my %h_soa = Net::checkDNS::parse_soa($soa);

is($h_soa{DOMAIN}, 'github.com', "Domain");
is($h_soa{NS}, 'ns-1707.awsdns-21.co.uk', "Nameserver");
is($h_soa{EMAIL}, 'awsdns-hostmaster@amazon.com', "Email");
