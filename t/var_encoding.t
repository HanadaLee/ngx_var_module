#!/usr/bin/perl

# Tests for var encoding, decoding, and built-in digest functions.

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
    [ 'hex_encode converts bytes to lowercase hex', '417a' ],
    [ 'hex_decode converts mixed case hex to bytes', 'Az' ],
    [ 'hex_decode rejects an odd input length', '' ],
    [ 'itohex converts a positive decimal integer', 'ff' ],
    [ 'itohex preserves a negative sign', '-ff' ],
    [ 'hextoi accepts uppercase hexadecimal input', '255' ],
    [ 'hextoi preserves a negative sign', '-255' ],
    [ 'hextoi rejects invalid hexadecimal input', '' ],
    [ 'escape_uri preserves URI delimiters', 'a&b/c%3Fd' ],
    [ 'escape_args escapes argument delimiters', 'a%26b/c%3Fd' ],
    [ 'escape_uri_component escapes every delimiter', 'a%26b%2Fc%3Fd' ],
    [ 'escape_html escapes unsafe HTML characters', 'a%27b' ],
    [ 'unescape_uri decodes percent encoded bytes', 'a b/c' ],
    [ 'base64_encode uses the standard alphabet', 'aGVsbG8/' ],
    [ 'base64url_encode uses the URL safe alphabet', 'aGVsbG8_' ],
    [ 'base64_decode restores standard base64', 'hello?' ],
    [ 'base64url_decode restores URL safe base64', 'hello?' ],
    [ 'base64_decode rejects malformed input', '' ],
    [ 'crc32 returns an eight digit checksum', 'cbf43926' ],
    [ 'md5 returns a lowercase hexadecimal digest',
      '900150983cd24fb0d6963f7d28e17f72' ],
    [ 'sha1 returns a lowercase hexadecimal digest',
      'a9993e364706816aba3e25717850c26c9cd0d89d' ],
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

        var $enc_hex hex_encode Az;
        var $enc_unhex hex_decode 417A;
        var $enc_unhex_invalid hex_decode abc;
        var $enc_itohex itohex 255;
        var $enc_itohex_negative itohex -255;
        var $enc_hextoi hextoi FF;
        var $enc_hextoi_negative hextoi -ff;
        var $enc_hextoi_invalid hextoi gg;
        var $enc_uri escape_uri "a&b/c?d";
        var $enc_args escape_args "a&b/c?d";
        var $enc_component escape_uri_component "a&b/c?d";
        var $enc_html escape_html "a'b";
        var $enc_unescape unescape_uri "a%20b%2Fc";
        var $enc_base64 base64_encode "hello?";
        var $enc_base64url base64url_encode "hello?";
        var $enc_unbase64 base64_decode aGVsbG8/;
        var $enc_unbase64url base64url_decode aGVsbG8_;
        var $enc_unbase64_invalid base64_decode "%%%";
        var $enc_crc32 crc32 123456789;
        var $enc_md5 md5 abc;
        var $enc_sha1 sha1 abc;

        location / {
            return 200 '$enc_hex|$enc_unhex|$enc_unhex_invalid|$enc_itohex|$enc_itohex_negative|$enc_hextoi|$enc_hextoi_negative|$enc_hextoi_invalid|$enc_uri|$enc_args|$enc_component|$enc_html|$enc_unescape|$enc_base64|$enc_base64url|$enc_unbase64|$enc_unbase64url|$enc_unbase64_invalid|$enc_crc32|$enc_md5|$enc_sha1';
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;

        var $enc_hex hex_encode Az;
        var $enc_unhex hex_decode 417A;
        var $enc_unhex_invalid hex_decode abc;
        var $enc_itohex itohex 255;
        var $enc_itohex_negative itohex -255;
        var $enc_hextoi hextoi FF;
        var $enc_hextoi_negative hextoi -ff;
        var $enc_hextoi_invalid hextoi gg;
        var $enc_uri escape_uri "a&b/c?d";
        var $enc_args escape_args "a&b/c?d";
        var $enc_component escape_uri_component "a&b/c?d";
        var $enc_html escape_html "a'b";
        var $enc_unescape unescape_uri "a%20b%2Fc";
        var $enc_base64 base64_encode "hello?";
        var $enc_base64url base64url_encode "hello?";
        var $enc_unbase64 base64_decode aGVsbG8/;
        var $enc_unbase64url base64url_decode aGVsbG8_;
        var $enc_unbase64_invalid base64_decode "%%%";
        var $enc_crc32 crc32 123456789;
        var $enc_md5 md5 abc;
        var $enc_sha1 sha1 abc;

        return '$enc_hex|$enc_unhex|$enc_unhex_invalid|$enc_itohex|$enc_itohex_negative|$enc_hextoi|$enc_hextoi_negative|$enc_hextoi_invalid|$enc_uri|$enc_args|$enc_component|$enc_html|$enc_unescape|$enc_base64|$enc_base64url|$enc_unbase64|$enc_unbase64url|$enc_unbase64_invalid|$enc_crc32|$enc_md5|$enc_sha1';
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

    is(scalar @values, scalar @$tests, "$protocol returns every encoding field");

    for my $i (0 .. $#$tests) {
        is($values[$i], $tests->[$i][1], "$protocol $tests->[$i][0]");
    }
}

###############################################################################
