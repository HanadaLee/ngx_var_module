#!/usr/bin/perl

# Tests for var time conversion and CIDR functions.

###############################################################################

use warnings;
use strict;

use Test::More;

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

$ENV{TZ} = 'UTC';

my @cases = (
    [ 'gmt_time emits HTTP date syntax', 'Fri, 01 Jan 2021 00:00:00 GMT' ],
    [ 'gmt_time emits cookie date syntax', 'Fri, 01-Jan-21 00:00:00 GMT' ],
    [ 'gmt_time accepts a strftime format', '2021-01-01T00:00:00Z' ],
    [ 'gmt_time supports the epoch format shortcut', '1609459200' ],
    [ 'gmt_time rejects an invalid timestamp', '' ],
    [ 'local_time accepts a strftime format', '2021-01-01 00:00:00' ],
    [ 'local_time supports the epoch format shortcut', '1609459200' ],
    [ 'local_time rejects an invalid timestamp', '' ],
    [ 'unix_time parses an HTTP date', '1609459200' ],
    [ 'unix_time parses a formatted GMT date', '1609459200' ],
    [ 'unix_time applies an explicit timezone offset', '1609459200' ],
    [ 'unix_time without arguments returns the current epoch', qr/^\d+$/ ],
    [ 'unix_time rejects a single argument', '' ],
    [ 'unix_time rejects an invalid HTTP date', '' ],
    [ 'cidr masks an IPv4 address', '192.168.12.0' ],
    [ 'cidr preserves an IPv4 host with 32 bits', '192.168.12.34' ],
    [ 'cidr applies an explicit IPv6 prefix', '2001:db8:1234:5678::' ],
    [ 'cidr defaults the IPv6 prefix to the IPv4 argument', '2001:db8::' ],
    [ 'cidr recognizes an IPv4 mapped IPv6 address', '192.168.12.0' ],
    [ 'cidr rejects an invalid prefix length', '' ],
    [ 'cidr rejects an invalid address', '' ],
);

my $t = Test::Nginx->new()
    ->has(qw/http stream stream_return ngx_var_module/)
    ->plan(2 * (@cases + 1));

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
env TZ;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        var $time_gmt_http gmt_time 1609459200 http_time;
        var $time_gmt_cookie gmt_time 1609459200 cookie_time;
        var $time_gmt_format gmt_time 1609459200 "%Y-%m-%dT%H:%M:%SZ";
        var $time_gmt_epoch gmt_time 1609459200 "%s";
        var $time_gmt_invalid gmt_time invalid "%Y";
        var $time_local_format local_time 1609459200 "%Y-%m-%d %H:%M:%S";
        var $time_local_epoch local_time 1609459200 "%s";
        var $time_local_invalid local_time invalid "%Y";
        var $time_unix_http unix_time "Fri, 01 Jan 2021 00:00:00 GMT" http_time;
        var $time_unix_format unix_time "2021-01-01 00:00:00" "%Y-%m-%d %H:%M:%S";
        var $time_unix_zone unix_time "2021-01-01 08:00:00" "%Y-%m-%d %H:%M:%S" GMT+0800;
        var $time_unix_now unix_time;
        var $time_unix_one unix_time value;
        var $time_unix_invalid unix_time invalid http_time;
        var $cidr_ipv4 cidr 192.168.12.34 24;
        var $cidr_ipv4_host cidr 192.168.12.34 32;
        var $cidr_ipv6 cidr 2001:db8:1234:5678::1 24 64;
        var $cidr_ipv6_default cidr 2001:db8:1234::1 32;
        var $cidr_mapped cidr ::ffff:192.168.12.34 24;
        var $cidr_bits_invalid cidr 192.168.12.34 0;
        var $cidr_ip_invalid cidr invalid 24;

        location / {
            return 200 '$time_gmt_http|$time_gmt_cookie|$time_gmt_format|$time_gmt_epoch|$time_gmt_invalid|$time_local_format|$time_local_epoch|$time_local_invalid|$time_unix_http|$time_unix_format|$time_unix_zone|$time_unix_now|$time_unix_one|$time_unix_invalid|$cidr_ipv4|$cidr_ipv4_host|$cidr_ipv6|$cidr_ipv6_default|$cidr_mapped|$cidr_bits_invalid|$cidr_ip_invalid';
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;

        var $time_gmt_http gmt_time 1609459200 http_time;
        var $time_gmt_cookie gmt_time 1609459200 cookie_time;
        var $time_gmt_format gmt_time 1609459200 "%Y-%m-%dT%H:%M:%SZ";
        var $time_gmt_epoch gmt_time 1609459200 "%s";
        var $time_gmt_invalid gmt_time invalid "%Y";
        var $time_local_format local_time 1609459200 "%Y-%m-%d %H:%M:%S";
        var $time_local_epoch local_time 1609459200 "%s";
        var $time_local_invalid local_time invalid "%Y";
        var $time_unix_http unix_time "Fri, 01 Jan 2021 00:00:00 GMT" http_time;
        var $time_unix_format unix_time "2021-01-01 00:00:00" "%Y-%m-%d %H:%M:%S";
        var $time_unix_zone unix_time "2021-01-01 08:00:00" "%Y-%m-%d %H:%M:%S" GMT+0800;
        var $time_unix_now unix_time;
        var $time_unix_one unix_time value;
        var $time_unix_invalid unix_time invalid http_time;
        var $cidr_ipv4 cidr 192.168.12.34 24;
        var $cidr_ipv4_host cidr 192.168.12.34 32;
        var $cidr_ipv6 cidr 2001:db8:1234:5678::1 24 64;
        var $cidr_ipv6_default cidr 2001:db8:1234::1 32;
        var $cidr_mapped cidr ::ffff:192.168.12.34 24;
        var $cidr_bits_invalid cidr 192.168.12.34 0;
        var $cidr_ip_invalid cidr invalid 24;

        return '$time_gmt_http|$time_gmt_cookie|$time_gmt_format|$time_gmt_epoch|$time_gmt_invalid|$time_local_format|$time_local_epoch|$time_local_invalid|$time_unix_http|$time_unix_format|$time_unix_zone|$time_unix_now|$time_unix_one|$time_unix_invalid|$cidr_ipv4|$cidr_ipv4_host|$cidr_ipv6|$cidr_ipv6_default|$cidr_mapped|$cidr_bits_invalid|$cidr_ip_invalid';
    }
}

EOF

$t->run();

###############################################################################

check_values(http_content(http_get('/')), 'HTTP', \@cases);
check_values(stream('127.0.0.1:' . port(8081))->read(), 'Stream', \@cases);

###############################################################################

sub check_values {
    my ($payload, $protocol, $tests) = @_;
    my @values = split /\|/, $payload, -1;

    is(scalar @values, scalar @$tests, "$protocol returns every time/CIDR field");

    for my $i (0 .. $#$tests) {
        my ($name, $expected) = @{$tests->[$i]};

        if (ref $expected eq 'Regexp') {
            like($values[$i], $expected, "$protocol $name");

        } else {
            is($values[$i], $expected, "$protocol $name");
        }
    }
}

###############################################################################
