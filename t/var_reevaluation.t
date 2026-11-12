#!/usr/bin/perl

# Tests for reevaluation through expr and precompiled JSON paths.

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

my $t = Test::Nginx->new()
    ->has(qw/http rewrite stream stream_return pcre ngx_expr_module ngx_var_module/)
    ->plan(7);

my $definitions = <<'EOF';
    var $value set $input;
    expr first ~ alpha '^(?<input>.*)$';
    expr second ~ beta '^(?<input>.*)$';
    expr member str_in $value alpha gamma;
    expr selected and first member second !member;
    when selected { var $answer set pass; }
    var $answer set fail;

    var $json extract_json $document value;
    expr doc_one ~ '{"value":"one"}' '^(?<document>.*)$';
    expr doc_two ~ '{"value":"two"}' '^(?<document>.*)$';
    expr json_one str_eq $json one;
    expr json_selected and doc_one json_one doc_two !json_one;
    when json_selected { var $json_answer set pass; }
    var $json_answer set fail;

    var $path set $path_input;
    var $dynamic extract_json '{"a":"one","b":"two"}' $path;
    expr path_a ~ a '^(?<path_input>.*)$';
    expr path_b ~ b '^(?<path_input>.*)$';
    expr dynamic_one str_eq $dynamic one;
    expr path_selected and path_a dynamic_one path_b !dynamic_one;
    when path_selected { var $path_answer set pass; }
    var $path_answer set fail;

    var $invalid extract_json '{"a":1}' '[bad]';
    var $empty extract_json '' '[empty]';
    var $quoted extract_json '{"a.b":{"x y":"quoted"}}' 'a.b';
    var $escaped extract_json '{"a.b":{"x y":"quoted"}}' '["a.b"]["x y"]';
EOF

my $conf = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    %%DEFINITIONS%%
    server {
        listen 127.0.0.1:8080;
        var $live set $state;
        location / {
            return 200 '$answer|$json_answer|$path_answer|$invalid|$empty|$quoted|$escaped';
        }
        location /set {
            set $state one;
            set $before $live;
            set $state two;
            return 200 '$before|$live';
        }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    %%DEFINITIONS%%
    server {
        listen 127.0.0.1:8081;
        return '$answer|$json_answer|$path_answer|$invalid|$empty|$quoted|$escaped';
    }
}
EOF
$conf =~ s/%%DEFINITIONS%%/$definitions/g;
$t->write_file_expand('nginx.conf', $conf)->run();

for (1 .. 2) {
    is(http_content(http_get('/')), 'pass|pass|pass||||quoted',
        "HTTP reevaluation and immutable paths, request $_");
    is(stream('127.0.0.1:' . port(8081))->read(), 'pass|pass|pass||||quoted',
        "Stream reevaluation and immutable paths, session $_");
}
is(http_content(http_get('/set')), 'one|two', 'var observes rewrite assignments');

$t->stop();
my $log = $t->read_file('error.log');
like($log, qr/invalid JSON path "\[bad\]"/, 'invalid literal path fails at runtime');
unlike($log, qr/invalid JSON path "\[empty\]"/, 'empty input skips path validation');

###############################################################################
