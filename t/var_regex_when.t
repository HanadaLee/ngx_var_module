#!/usr/bin/perl

# Tests for UTF and byte-mode regex substitutions selected by when.

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
    ->has(qw/http stream stream_return pcre ngx_expr_module ngx_var_module/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    expr use_utf = $arg_utf 1;

    when use_utf {
        var $result regex_gsub "茅" "(*UTF)" X;
    }
    var $result regex_gsub "茅" "" X;

    server {
        listen 127.0.0.1:8080;
        return 200 $result;
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    expr use_utf bool true;
    expr use_bytes bool false;

    server {
        listen 127.0.0.1:8081;
        when use_utf {
            var $result regex_gsub "茅" "(*UTF)" X;
        }
        var $result regex_gsub "茅" "" X;
        return $result;
    }

    server {
        listen 127.0.0.1:8082;
        when use_bytes {
            var $result regex_gsub "茅" "(*UTF)" X;
        }
        var $result regex_gsub "茅" "" X;
        return $result;
    }
}

EOF

$t->try_run('PCRE UTF support is not available')->plan(4);

###############################################################################

my $bytes = 'X' . join('X', split //, '茅') . 'X';

is(http_content(http_get('/?utf=1')), 'X茅X',
    'HTTP when selects UTF character advancement');
is(http_content(http_get('/')), $bytes,
    'HTTP default preserves byte advancement');
is(stream('127.0.0.1:' . port(8081))->read(), 'X茅X',
    'Stream when selects UTF character advancement');
is(stream('127.0.0.1:' . port(8082))->read(), $bytes,
    'Stream default preserves byte advancement');

###############################################################################
