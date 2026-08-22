#!/usr/bin/perl

# Tests for var OpenSSL digest and HMAC functions.

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
    [ 'sha224 returns the expected digest',
      '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7' ],
    [ 'sha256 returns the expected digest',
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' ],
    [ 'sha384 returns the expected digest',
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7' ],
    [ 'sha512 returns the expected digest',
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f' ],
    [ 'hmac_md5 returns the expected raw digest',
      'd2fe98063f876b03193afb49b4979591' ],
    [ 'hmac_sha1 returns the expected raw digest',
      '4fd0b215276ef12f2b3e4c8ecac2811498b656fc' ],
    [ 'hmac_sha224 returns the expected raw digest',
      'f524670b7e34f31467de0aa96593861cf65117d414fb2d86158d760e' ],
    [ 'hmac_sha256 returns the expected raw digest',
      '9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab' ],
    [ 'hmac_sha384 returns the expected raw digest',
      '30ddb9c8f347cffbfb44e519d814f074cf4047a55d6f563324f1c6a33920e5edfb2a34bac60bdc96cd33a95623d7d638' ],
    [ 'hmac_sha512 returns the expected raw digest',
      '3926a207c8c42b0c41792cbd3e1a1aaaf5f7a25704f62dfc939c4987dd7ce060009c5bb1c2447355b3216f10b537e9afa7b64a4e5391b0d631172d07939e087a' ],
);

my $t = Test::Nginx->new()
    ->has(qw/http stream stream_return http_ssl ngx_var_module/)
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

        var $crypto_source set abc;
        var $crypto_secret set key;
        var $crypto_sha224 sha224 $crypto_source;
        var $crypto_sha256 sha256 $crypto_source;
        var $crypto_sha384 sha384 $crypto_source;
        var $crypto_sha512 sha512 $crypto_source;
        var $crypto_hmac_md5_raw hmac_md5 $crypto_source $crypto_secret;
        var $crypto_hmac_sha1_raw hmac_sha1 $crypto_source $crypto_secret;
        var $crypto_hmac_sha224_raw hmac_sha224 $crypto_source $crypto_secret;
        var $crypto_hmac_sha256_raw hmac_sha256 $crypto_source $crypto_secret;
        var $crypto_hmac_sha384_raw hmac_sha384 $crypto_source $crypto_secret;
        var $crypto_hmac_sha512_raw hmac_sha512 $crypto_source $crypto_secret;
        var $crypto_hmac_md5 hex_encode $crypto_hmac_md5_raw;
        var $crypto_hmac_sha1 hex_encode $crypto_hmac_sha1_raw;
        var $crypto_hmac_sha224 hex_encode $crypto_hmac_sha224_raw;
        var $crypto_hmac_sha256 hex_encode $crypto_hmac_sha256_raw;
        var $crypto_hmac_sha384 hex_encode $crypto_hmac_sha384_raw;
        var $crypto_hmac_sha512 hex_encode $crypto_hmac_sha512_raw;

        location / {
            return 200 '$crypto_sha224|$crypto_sha256|$crypto_sha384|$crypto_sha512|$crypto_hmac_md5|$crypto_hmac_sha1|$crypto_hmac_sha224|$crypto_hmac_sha256|$crypto_hmac_sha384|$crypto_hmac_sha512';
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;

        var $crypto_source set abc;
        var $crypto_secret set key;
        var $crypto_sha224 sha224 $crypto_source;
        var $crypto_sha256 sha256 $crypto_source;
        var $crypto_sha384 sha384 $crypto_source;
        var $crypto_sha512 sha512 $crypto_source;
        var $crypto_hmac_md5_raw hmac_md5 $crypto_source $crypto_secret;
        var $crypto_hmac_sha1_raw hmac_sha1 $crypto_source $crypto_secret;
        var $crypto_hmac_sha224_raw hmac_sha224 $crypto_source $crypto_secret;
        var $crypto_hmac_sha256_raw hmac_sha256 $crypto_source $crypto_secret;
        var $crypto_hmac_sha384_raw hmac_sha384 $crypto_source $crypto_secret;
        var $crypto_hmac_sha512_raw hmac_sha512 $crypto_source $crypto_secret;
        var $crypto_hmac_md5 hex_encode $crypto_hmac_md5_raw;
        var $crypto_hmac_sha1 hex_encode $crypto_hmac_sha1_raw;
        var $crypto_hmac_sha224 hex_encode $crypto_hmac_sha224_raw;
        var $crypto_hmac_sha256 hex_encode $crypto_hmac_sha256_raw;
        var $crypto_hmac_sha384 hex_encode $crypto_hmac_sha384_raw;
        var $crypto_hmac_sha512 hex_encode $crypto_hmac_sha512_raw;

        return '$crypto_sha224|$crypto_sha256|$crypto_sha384|$crypto_sha512|$crypto_hmac_md5|$crypto_hmac_sha1|$crypto_hmac_sha224|$crypto_hmac_sha256|$crypto_hmac_sha384|$crypto_hmac_sha512';
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

    is(scalar @values, scalar @$tests, "$protocol returns every OpenSSL field");

    for my $i (0 .. $#$tests) {
        is($values[$i], $tests->[$i][1], "$protocol $tests->[$i][0]");
    }
}

###############################################################################
