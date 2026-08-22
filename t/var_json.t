#!/usr/bin/perl

# Tests for the optional var cJSON function.

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
    [ 'extract_json traverses nested objects', '3' ],
    [ 'extract_json traverses array indices', 'Bob' ],
    [ 'extract_json returns strings without quotes', 'hello' ],
    [ 'extract_json serializes arrays compactly', '[1,2,3]' ],
    [ 'extract_json serializes objects compactly', '{"name":"Bob","age":30}' ],
    [ 'extract_json serializes booleans', 'true' ],
    [ 'extract_json serializes null', 'null' ],
    [ 'extract_json returns empty for a missing path', '' ],
    [ 'extract_json rejects malformed JSON', '' ],
);

my $t = Test::Nginx->new()
    ->has(qw/http stream stream_return ngx_var_module/);

plan(skip_all => 'no cJSON support in ngx_var_module')
    unless binary_contains($Test::Nginx::NGINX, "extract_json\0");

$t->plan(2 * (@cases + 1));

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

        var $json_nested extract_json '{"a":{"b":{"c":3}}}' a b c;
        var $json_array_item extract_json '{"users":[{"name":"Alice"},{"name":"Bob"}]}' users [1] name;
        var $json_string extract_json '{"value":"hello"}' value;
        var $json_array extract_json '{"data":[1,2,3]}' data;
        var $json_object extract_json '{"user":{"name":"Bob","age":30}}' user;
        var $json_bool extract_json '{"value":true}' value;
        var $json_null extract_json '{"value":null}' value;
        var $json_missing extract_json '{"a":1}' missing;
        var $json_invalid extract_json '{invalid}' value;

        location / {
            return 200 '$json_nested|$json_array_item|$json_string|$json_array|$json_object|$json_bool|$json_null|$json_missing|$json_invalid';
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;

        var $json_nested extract_json '{"a":{"b":{"c":3}}}' a b c;
        var $json_array_item extract_json '{"users":[{"name":"Alice"},{"name":"Bob"}]}' users [1] name;
        var $json_string extract_json '{"value":"hello"}' value;
        var $json_array extract_json '{"data":[1,2,3]}' data;
        var $json_object extract_json '{"user":{"name":"Bob","age":30}}' user;
        var $json_bool extract_json '{"value":true}' value;
        var $json_null extract_json '{"value":null}' value;
        var $json_missing extract_json '{"a":1}' missing;
        var $json_invalid extract_json '{invalid}' value;

        return '$json_nested|$json_array_item|$json_string|$json_array|$json_object|$json_bool|$json_null|$json_missing|$json_invalid';
    }
}

EOF

$t->run();

###############################################################################

check_values(http_content(http_get('/')), 'HTTP', \@cases);
check_values(stream('127.0.0.1:' . port(8081))->read(), 'Stream', \@cases);

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


sub check_values {
    my ($payload, $protocol, $tests) = @_;
    my @values = split /\|/, $payload, -1;

    is(scalar @values, scalar @$tests, "$protocol returns every JSON field");

    for my $i (0 .. $#$tests) {
        is($values[$i], $tests->[$i][1], "$protocol $tests->[$i][0]");
    }
}

###############################################################################
