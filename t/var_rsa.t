#!/usr/bin/perl

# Tests for RSA operations against independent cryptography implementations.

###############################################################################

use warnings;
use strict;
use FindBin;
use JSON::PP qw/decode_json encode_json/;
use Test::More;
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite stream stream_return
    ngx_var_module/);
system('python3', "$FindBin::Bin/generate_rsa.py", $t->testdir()) == 0
    or BAIL_OUT('could not generate RSA fixtures');
my $cases = decode_json($t->read_file('rsa-cases.json'));
my $directives = $t->read_file('rsa-directives.conf');
my $variables = join '|', map { $_->{variable} } @$cases;
$t->plan(2 * scalar @$cases);

$t->write_file_expand('nginx.conf', <<EOF)->run();
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    variables_hash_max_size 4096;
    variables_hash_bucket_size 128;
    $directives
    server { listen 127.0.0.1:8080; return 200 "$variables"; }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    variables_hash_max_size 4096;
    variables_hash_bucket_size 128;
    $directives
    server { listen 127.0.0.1:8081; return "$variables"; }
}
EOF

for my $context ('http', 'stream') {
    my $response = $context eq 'http' ? http_content(http_get('/'))
        : stream('127.0.0.1:' . port(8081))->io('');
    my @results = split /\|/, $response, -1;
    $t->write_file('rsa-results.json', encode_json(\@results));
    system('python3', "$FindBin::Bin/generate_rsa.py", $t->testdir(),
        $t->testdir() . '/rsa-results.json', $t->testdir() . '/rsa-checks.json') == 0
        or BAIL_OUT('could not check RSA results');
    my $checks = decode_json($t->read_file('rsa-checks.json'));
    for my $i (0 .. $#$cases) {
        ok($checks->[$i]{ok}, "$context $cases->[$i]{name}")
            or diag($checks->[$i]{error});
    }
}

###############################################################################
