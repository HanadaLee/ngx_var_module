#!/usr/bin/perl

# Tests for var mathematical and random functions.

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

my @cases = (
    [ 'abs removes only the negative sign', '0012.50' ],
    [ 'abs rejects a nonnumeric value', '' ],
    [ 'max compares fixed point values', '10.0' ],
    [ 'min compares fixed point values', '-2.5' ],
    [ 'max preserves the selected operand format', '2.00' ],
    [ 'add handles signed integers', '4' ],
    [ 'sub handles signed integers', '-7' ],
    [ 'mul handles two negative integers', '42' ],
    [ 'div truncates toward zero', '-2' ],
    [ 'div rejects a zero divisor', '' ],
    [ 'mod preserves the dividend sign', '-1' ],
    [ 'mod rejects a zero divisor', '' ],
    [ 'bitwise_and combines set bits', '2' ],
    [ 'bitwise_not inverts every bit', '-11' ],
    [ 'bitwise_or combines either bit', '14' ],
    [ 'bitwise_xor combines different bits', '12' ],
    [ 'lshift shifts bits left', '48' ],
    [ 'rshift preserves the sign bit', '-4' ],
    [ 'urshift fills with zero bits', qr/^(?:1073741822|4611686018427387902)$/ ],
    [ 'round rounds to the requested precision', '12.35' ],
    [ 'round propagates a carry', '10.0' ],
    [ 'round pads a missing fraction', '12.00' ],
    [ 'trunc removes a negative fraction', '-12' ],
    [ 'floor leaves a positive integer part', '12' ],
    [ 'floor decreases a negative value', '-13' ],
    [ 'ceil increases a positive value', '13' ],
    [ 'ceil leaves a negative integer part', '-12' ],
    [ 'rand without bounds returns a positive integer', qr/^\d+$/ ],
    [ 'rand with one bound stays in range', qr/^[0-3]$/ ],
    [ 'rand with equal bounds is deterministic', '7' ],
    [ 'rand rejects a reversed range', '' ],
    [ 'hexrand defaults to 32 hexadecimal characters', qr/^[0-9a-f]{32}$/ ],
    [ 'hexrand accepts an explicit length', qr/^[0-9a-f]{7}$/ ],
    [ 'hexrand rejects a length above 32', '' ],
);

my $t = Test::Nginx->new()
    ->has(qw/http stream stream_return ngx_var_module/)
    ->plan(2 * (@cases + 1));

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        var $math_abs abs -0012.50;
        var $math_abs_invalid abs value;
        var $math_max max 2.50 10.0;
        var $math_min min -2.5 -1.25;
        var $math_max_format max 2.00 2;
        var $math_add add 7 -3;
        var $math_sub sub -2 5;
        var $math_mul mul -6 -7;
        var $math_div div -7 3;
        var $math_div_zero div 7 0;
        var $math_mod mod -7 3;
        var $math_mod_zero mod 7 0;
        var $math_and bitwise_and 10 6;
        var $math_not bitwise_not 10;
        var $math_or bitwise_or 10 6;
        var $math_xor bitwise_xor 10 6;
        var $math_lshift lshift 3 4;
        var $math_rshift rshift -16 2;
        var $math_urshift urshift -8 2;
        var $math_round round 12.345 2;
        var $math_round_carry round 9.99 1;
        var $math_round_pad round 12 2;
        var $math_trunc trunc -12.9;
        var $math_floor floor 12.9;
        var $math_floor_negative floor -12.1;
        var $math_ceil ceil 12.1;
        var $math_ceil_negative ceil -12.9;
        var $math_rand rand;
        var $math_rand_bound rand 3;
        var $math_rand_fixed rand 7 7;
        var $math_rand_invalid rand 8 7;
        var $math_hexrand hexrand;
        var $math_hexrand_length hexrand 7;
        var $math_hexrand_invalid hexrand 33;

        location / {
            return 200 '$math_abs|$math_abs_invalid|$math_max|$math_min|$math_max_format|$math_add|$math_sub|$math_mul|$math_div|$math_div_zero|$math_mod|$math_mod_zero|$math_and|$math_not|$math_or|$math_xor|$math_lshift|$math_rshift|$math_urshift|$math_round|$math_round_carry|$math_round_pad|$math_trunc|$math_floor|$math_floor_negative|$math_ceil|$math_ceil_negative|$math_rand|$math_rand_bound|$math_rand_fixed|$math_rand_invalid|$math_hexrand|$math_hexrand_length|$math_hexrand_invalid';
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;

        var $math_abs abs -0012.50;
        var $math_abs_invalid abs value;
        var $math_max max 2.50 10.0;
        var $math_min min -2.5 -1.25;
        var $math_max_format max 2.00 2;
        var $math_add add 7 -3;
        var $math_sub sub -2 5;
        var $math_mul mul -6 -7;
        var $math_div div -7 3;
        var $math_div_zero div 7 0;
        var $math_mod mod -7 3;
        var $math_mod_zero mod 7 0;
        var $math_and bitwise_and 10 6;
        var $math_not bitwise_not 10;
        var $math_or bitwise_or 10 6;
        var $math_xor bitwise_xor 10 6;
        var $math_lshift lshift 3 4;
        var $math_rshift rshift -16 2;
        var $math_urshift urshift -8 2;
        var $math_round round 12.345 2;
        var $math_round_carry round 9.99 1;
        var $math_round_pad round 12 2;
        var $math_trunc trunc -12.9;
        var $math_floor floor 12.9;
        var $math_floor_negative floor -12.1;
        var $math_ceil ceil 12.1;
        var $math_ceil_negative ceil -12.9;
        var $math_rand rand;
        var $math_rand_bound rand 3;
        var $math_rand_fixed rand 7 7;
        var $math_rand_invalid rand 8 7;
        var $math_hexrand hexrand;
        var $math_hexrand_length hexrand 7;
        var $math_hexrand_invalid hexrand 33;

        return '$math_abs|$math_abs_invalid|$math_max|$math_min|$math_max_format|$math_add|$math_sub|$math_mul|$math_div|$math_div_zero|$math_mod|$math_mod_zero|$math_and|$math_not|$math_or|$math_xor|$math_lshift|$math_rshift|$math_urshift|$math_round|$math_round_carry|$math_round_pad|$math_trunc|$math_floor|$math_floor_negative|$math_ceil|$math_ceil_negative|$math_rand|$math_rand_bound|$math_rand_fixed|$math_rand_invalid|$math_hexrand|$math_hexrand_length|$math_hexrand_invalid';
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

    is(scalar @values, scalar @$tests, "$protocol returns every math field");

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
