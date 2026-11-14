#!/usr/bin/perl

# Tests for common symmetric ciphers, authenticated decryption and IV caching.

###############################################################################

use warnings;
use strict;
use FindBin;
use JSON::PP qw/decode_json/;
use Test::More;
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite stream stream_return
    ngx_var_module/);
system('python3', "$FindBin::Bin/generate_crypto.py", $t->testdir()) == 0
    or BAIL_OUT('could not generate cipher vectors');
my $data = decode_json($t->read_file('cipher-cases.json'));
my $cases = $data->{cases};
my $automatic = $data->{automatic};
my $directives = $t->read_file('cipher-directives.conf');
my $variables = join '|', map { $_->{variable} } @$cases;
my $auto = join '|', map { my $i = $_->{index};
    "\$crypto_auto_hex_$i:\$crypto_auto_hex_$i:\$crypto_open_hex_$i" } @$automatic;
$t->plan(2 * scalar(@$cases) + 8 * scalar(@$automatic) + 1);

$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    variables_hash_max_size 8192;
    variables_hash_bucket_size 128;
    server {
        listen 127.0.0.1:8080;
        $directives
        location / { return 200 "$variables"; }
        location /auto { return 200 "$auto"; }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    variables_hash_max_size 8192;
    variables_hash_bucket_size 128;
    $directives
    server { listen 127.0.0.1:8081; return "$variables"; }
    server { listen 127.0.0.1:8082; return "$auto"; }
}
EOF
$t->run();

my @http = split /\|/, http_content(http_get('/')), -1;
my @stream = split /\|/, stream('127.0.0.1:' . port(8081))->io(''), -1;
for my $i (0 .. $#$cases) {
    is($http[$i], $cases->[$i]{expected}, 'http ' . $cases->[$i]{name});
    is($stream[$i], $cases->[$i]{expected}, 'stream ' . $cases->[$i]{name});
}

my @ha = split /\|/, http_content(http_get('/auto')), -1;
my @hb = split /\|/, http_content(http_get('/auto')), -1;
my @sa = split /\|/, stream('127.0.0.1:' . port(8082))->io(''), -1;
my @sb = split /\|/, stream('127.0.0.1:' . port(8082))->io(''), -1;
for my $i (0 .. $#$automatic) {
    my $case = $automatic->[$i];
    for my $pair (['http', $ha[$i], $hb[$i]], ['stream', $sa[$i], $sb[$i]]) {
        my ($context, $first, $next) = @$pair;
        my ($a, $b, $plain) = split /:/, $first // '', -1;
        is($a, $b, "$context $case->{name} reuses the complete result");
        is($plain, $case->{plaintext}, "$context $case->{name} packed round trip");
        is(length($a // ''), 2 * $case->{encrypted_len}, "$context $case->{name} packet length");
        isnt(substr($first // '', 0, 2 * $case->{iv_len}),
              substr($next // '', 0, 2 * $case->{iv_len}),
              "$context $case->{name} uses a fresh IV in the next context");
    }
}
unlike($t->read_file('error.log'), qr/var: evaluated variable .*value:/,
    'var debug messages do not print variable values');

###############################################################################
