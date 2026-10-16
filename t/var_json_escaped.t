#!/usr/bin/perl

# Tests for escaped strings with the nginx core JSON parser.

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
    [ 'key', 'key', 'decodes escaped object keys' ],
    [ 'path', 'path', 'decodes escaped quoted path segments' ],
    [ 'quote', 'quote', 'matches a quote in an object key' ],
    [ 'insensitive', 'case', 'ignores case after decoding a key' ],
    [ 'string', 'ab', 'decodes escaped string values' ],
    [ 'once', '\u0061', 'does not decode a string twice' ],
    [ 'controls', "\0\n\t", 'preserves decoded control characters' ],
    [ 'unicode', pack('H*', 'e4b8adf09f9880'), 'decodes Unicode and surrogate pairs' ],
    [ 'array_first', 'ab', 'extracts an escaped array element' ],
    [ 'array_second', 'tail', 'counts escaped array elements' ],
    [ 'skipped', 'found', 'skips an escaped key and its nested value' ],
    [ 'missing', '', 'returns empty for an unmatched escaped key' ],
    [ 'container', '{"\u0061":"x\u0062"}', 'preserves escapes in extracted JSON' ],
    [ 'empty', '', 'extracts an empty unescaped string' ],
    [ 'source_value', 'ab', 'decodes a value from a variable' ],
    [ 'source_tail', 'tail', 'reuses the source after decoding a value' ],
    [ 'source', '{"\u0061":"a\u0062","tail":"tail"}', 'leaves the source unchanged' ],
);

my $t = Test::Nginx->new()
    ->has(qw/http stream stream_return ngx_var_module/);

plan(skip_all => 'requires the nginx core JSON parser')
    unless binary_contains($Test::Nginx::NGINX, "ngx_json_parse_ctx\0");

plan(skip_all => 'no extract_json support in ngx_var_module')
    unless binary_contains($Test::Nginx::NGINX, "extract_json\0");

$t->plan(2 * (@cases + 1));

$t->write_file('json-vars.conf', <<'EOF');
var $json_key extract_json '{"\u0061":"key"}' a;
var $json_path extract_json '{"a.b":"path"}' '["\u0061.b"]';
var $json_quote extract_json '{"a\u0022b":"quote"}' '["a\u0022b"]';
var $json_insensitive extract_json -i '{"\u004eame":"case"}' name;
var $json_string extract_json '{"value":"a\u0062"}' value;
var $json_once extract_json '{"value":"\u005cu0061"}' value;
var $json_controls extract_json '{"value":"\u0000\u000a\u0009"}' value;
var $json_unicode extract_json '{"value":"\u4e2d\ud83d\ude00"}' value;
var $json_array_first extract_json '["a\u0062","tail"]' [0];
var $json_array_second extract_json '["a\u0062","tail"]' [1];
var $json_skipped extract_json '{"\u0073kip":{"\u0061":["\u0062"]},"\u0074arget":"found"}' target;
var $json_missing extract_json '{"\u0061":"\u0062"}' missing;
var $json_container extract_json '{"value": { "\u0061": "x\u0062" }}' value;
var $json_empty extract_json '{"value":""}' value;
var $json_source set '{"\u0061":"a\u0062","tail":"tail"}';
var $json_source_value extract_json $json_source a;
var $json_source_tail extract_json $json_source tail;
EOF

my $response = join('|', map { '$json_' . $_->[0] } @cases);

$t->write_file('json-http-return.conf', "return 200 '$response';\n");
$t->write_file('json-stream-return.conf', "return '$response';\n");

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

        include json-vars.conf;
        include json-http-return.conf;
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;

        include json-vars.conf;
        include json-stream-return.conf;
    }
}

EOF

$t->run();

###############################################################################

check_values(http_content(http_get('/')), 'HTTP');
check_values(stream('127.0.0.1:' . port(8081))->read(), 'Stream');

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
    my ($payload, $protocol) = @_;
    my @values = split /\|/, $payload, -1;

    is(scalar @values, scalar @cases, "$protocol returns every JSON field");

    for my $i (0 .. $#cases) {
        is($values[$i], $cases[$i][1], "$protocol $cases[$i][2]");
    }
}

###############################################################################
