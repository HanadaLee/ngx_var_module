#!/usr/bin/perl

# Tests for overwriting var variables with the nginx set directive.

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
    ->has(qw/http rewrite stream stream_return stream_set ngx_var_module/)
    ->plan(12);

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

        var $mutable set initial;
        var $source set source;
        var $target set initial-target;
        var $random_mutable rand 0 10000;

        location = /override {
            set $mutable overridden;
            return 200 $mutable;
        }

        location = /chain {
            set $mutable first;
            set $mutable "$mutable-second";
            return 200 $mutable;
        }

        location = /from-var {
            set $target $source;
            return 200 '$source|$target';
        }

        location = /empty {
            set $mutable "";
            return 200 "[$mutable]";
        }

        location = /random {
            set $random_copy $random_mutable;
            set $random_mutable fixed;
            return 200 '$random_copy|$random_mutable';
        }

        location = /original {
            return 200 '$mutable|$target';
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    var $mutable set initial;
    var $source set source;
    var $target set initial-target;
    var $random_mutable rand 0 10000;

    server {
        listen 127.0.0.1:8081;
        set $mutable overridden;
        return $mutable;
    }

    server {
        listen 127.0.0.1:8082;
        set $mutable first;
        set $mutable "$mutable-second";
        return $mutable;
    }

    server {
        listen 127.0.0.1:8083;
        set $target $source;
        return '$source|$target';
    }

    server {
        listen 127.0.0.1:8084;
        set $mutable "";
        return "[$mutable]";
    }

    server {
        listen 127.0.0.1:8085;
        set $random_copy $random_mutable;
        set $random_mutable fixed;
        return '$random_copy|$random_mutable';
    }

    server {
        listen 127.0.0.1:8086;
        return '$mutable|$target';
    }
}

EOF

$t->run();

###############################################################################

is(http_content(http_get('/override')), 'overridden',
    'HTTP set overwrites a var variable');
is(http_content(http_get('/chain')), 'first-second',
    'HTTP repeated set reads the previously assigned value');
is(http_content(http_get('/from-var')), 'source|source',
    'HTTP set copies another var variable');
is(http_content(http_get('/empty')), '[]',
    'HTTP set assigns an empty value to a var variable');
like(http_content(http_get('/random')), qr/^\d+\|fixed$/,
    'HTTP set copies a random var value before overwriting it');
is(http_content(http_get('/original')), 'initial|initial-target',
    'HTTP set assignments do not leak into another request');

is(stream('127.0.0.1:' . port(8081))->read(), 'overridden',
    'Stream set overwrites a var variable');
is(stream('127.0.0.1:' . port(8082))->read(), 'first-second',
    'Stream repeated set reads the previously assigned value');
is(stream('127.0.0.1:' . port(8083))->read(), 'source|source',
    'Stream set copies another var variable');
is(stream('127.0.0.1:' . port(8084))->read(), '[]',
    'Stream set assigns an empty value to a var variable');
like(stream('127.0.0.1:' . port(8085))->read(), qr/^\d+\|fixed$/,
    'Stream set copies a random var value before overwriting it');
is(stream('127.0.0.1:' . port(8086))->read(), 'initial|initial-target',
    'Stream set assignments do not leak into another session');

###############################################################################
