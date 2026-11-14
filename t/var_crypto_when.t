#!/usr/bin/perl

# Tests for encryption rules selected by changing conditions.

###############################################################################

use warnings;
use strict;
use Test::More;
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite stream stream_return
    stream_set ngx_expr_module ngx_var_module/)->plan(6);

my $definitions = <<'EOF';
    expr selected str_eq $state one;
    when selected {
        var $encrypted aes_encrypt message 0123456789abcdef0123456789abcdef;
    }
    var $encrypted aes_encrypt message 0123456789abcdef0123456789abcdef;
    var $encoded hex_encode $encrypted;
EOF
my $assignments = <<'EOF';
    set $state one;
    set $first $encoded;
    set $state two;
    set $second $encoded;
    set $state one;
EOF

$t->write_file_expand('nginx.conf', <<EOF)->run();
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    $definitions
    server {
        listen 127.0.0.1:8080;
        location / {
            $assignments
            return 200 '\$first|\$second|\$encoded';
        }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    $definitions
    server {
        listen 127.0.0.1:8081;
        $assignments
        return '\$first|\$second|\$encoded';
    }
}
EOF

for my $context ('http', 'stream') {
    my $response = $context eq 'http' ? http_content(http_get('/'))
        : stream('127.0.0.1:' . port(8081))->io('');
    my ($first, $second, $last) = split /\|/, $response;
    like($first, qr/^[0-9a-f]+$/, "$context conditional rule encrypts");
    isnt($second, $first, "$context condition is reevaluated before cache lookup");
    is($last, $first, "$context each selected rule retains its own result");
}

###############################################################################
