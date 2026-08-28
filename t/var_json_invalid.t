#!/usr/bin/perl

# Tests for invalid optional var cJSON function configuration.

###############################################################################

use warnings;
use strict;

use Test::More;

use lib 'lib';
use Test::Nginx qw/ :DEFAULT /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http ngx_var_module/);

plan(skip_all => 'no cJSON support in ngx_var_module')
    unless binary_contains($Test::Nginx::NGINX, "extract_json\0");

$t->plan(2);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:8080;

        var $json extract_json '{"a":{"b":1}}' a b;
    }
}

EOF

my $rc = system($Test::Nginx::NGINX, '-t', '-p', $t->testdir() . '/',
                '-c', 'nginx.conf', '-e', 'error.log');

isnt($rc, 0, 'extract_json rejects space-separated path segments');
like($t->read_file('error.log'),
     qr/invalid number of arguments for function "extract_json"/,
     'extract_json reports the invalid argument count');

###############################################################################

sub binary_contains {
    my ($path, $needle) = @_;

    open my $binary, '<', $path or return 0;
    binmode $binary;
    local $/;

    my $contents = <$binary>;

    close $binary;

    return index($contents, $needle) >= 0;
}

###############################################################################
