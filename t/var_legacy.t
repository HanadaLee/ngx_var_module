#!/usr/bin/perl

# Tests for indexed variable lookup with legacy var conditions.

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
    ->has(qw/http stream stream_return ngx_var_module/);

plan(skip_all => 'legacy if conditions require a build without condition')
    if $t->has_module('ngx_condition_module');

$t->plan(17);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format index_padding '$arg_pad00$arg_pad01$arg_pad02$arg_pad03'
                             '$arg_pad04$arg_pad05$arg_pad06$arg_pad07';

    var $http_chain set parent-hit if=$arg_parent;
    var $http_chain set parent-default;

    var $http_terminal set first-default;
    var $http_terminal set unreachable if=1;

    var $http_no_default set condition-hit if=$arg_only;
    var $http_high_index set high-index;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        var $scope set alpha;
        var $http_chain set child-hit if=$arg_child;

        var $negative set negative-hit if!=$arg_flag;
        var $negative set negative-default;

        var $http_self set direct if=$http_self;
        var $http_cycle_a set cycle-a if=$http_cycle_b;
        var $http_cycle_b set cycle-b if=$http_cycle_a;
        var $safe set safe;

        location = /matrix {
            return 200 '$scope|$http_chain|$negative|$http_terminal|$http_no_default|$http_high_index';
        }

        location = /local {
            var $scope set local;
            return 200 '$scope|$http_chain';
        }

        location = /self {
            return 200 '$http_self|$safe';
        }

        location = /cycle {
            return 200 '$http_cycle_a|$safe';
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        var $scope set beta;

        location / {
            return 200 '$scope|$http_high_index';
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    map $remote_addr $pad00 { default pad; }
    map $remote_addr $pad01 { default pad; }
    map $remote_addr $pad02 { default pad; }
    map $remote_addr $pad03 { default pad; }
    log_format index_padding '$pad00$pad01$pad02$pad03';

    var $stream_chain set parent-hit if=1;
    var $stream_chain set parent-default;

    var $stream_default set parent-condition if=0;
    var $stream_default set parent-default;

    var $stream_override set parent-hit if=1;
    var $stream_override set parent-default;

    var $stream_terminal set first-default;
    var $stream_terminal set unreachable if=1;

    var $stream_no_default set condition-hit if=0;
    var $stream_high_index set high-index;

    server {
        listen 127.0.0.1:8082;

        var $stream_scope set alpha;
        var $stream_chain set child-miss if=0;
        var $stream_default set child-miss if=0;

        return '$stream_scope|$stream_chain|$stream_default|$stream_terminal|$stream_no_default|$stream_high_index';
    }

    server {
        listen 127.0.0.1:8083;
        var $stream_scope set beta;
        return '$stream_scope|$stream_high_index';
    }

    server {
        listen 127.0.0.1:8084;
        var $stream_chain set child-hit if=1;
        return $stream_chain;
    }

    server {
        listen 127.0.0.1:8085;
        var $stream_override set child-default;
        return $stream_override;
    }

    server {
        listen 127.0.0.1:8086;
        var $stream_self set direct if=$stream_self;
        var $stream_safe set safe;
        return '$stream_self|$stream_safe';
    }

    server {
        listen 127.0.0.1:8087;
        var $stream_cycle_a set cycle-a if=$stream_cycle_b;
        var $stream_cycle_b set cycle-b if=$stream_cycle_a;
        var $stream_safe set safe;
        return '$stream_cycle_a|$stream_safe';
    }
}

EOF

$t->run();

###############################################################################

is(http_content(http_get('/matrix?child=1')),
    'alpha|child-hit|negative-hit|first-default||high-index',
    'HTTP child condition has highest priority');
is(http_content(http_get('/matrix?parent=1')),
    'alpha|parent-hit|negative-hit|first-default||high-index',
    'HTTP parent condition is inherited');
is(http_content(http_get('/matrix?flag=1')),
    'alpha|parent-default|negative-default|first-default||high-index',
    'HTTP defaults and negative condition are selected');
is(http_content(http_get('/matrix?only=1')),
    'alpha|parent-default|negative-hit|first-default|condition-hit|high-index',
    'HTTP condition-only variable can match without a default');
is(http_content(http_get('/local?child=1')), 'local|child-hit',
    'HTTP local variable coexists with inherited indexed variables');
is(http_content(http_get('/',
    PeerAddr => '127.0.0.1:' . port(8081))), 'beta|high-index',
    'HTTP servers keep separate definitions for the same index');
is(http_content(http_get('/self')), '|safe',
    'HTTP direct circular reference returns an empty value');
is(http_content(http_get('/cycle')), '|safe',
    'HTTP indirect circular reference releases all locks');

is(stream('127.0.0.1:' . port(8082))->read(),
    'alpha|parent-hit|parent-default|first-default||high-index',
    'Stream child misses fall through to parent rules and default');
is(stream('127.0.0.1:' . port(8083))->read(), 'beta|high-index',
    'Stream servers keep separate definitions for the same index');
is(stream('127.0.0.1:' . port(8084))->read(), 'child-hit',
    'Stream child condition has highest priority');
is(stream('127.0.0.1:' . port(8085))->read(), 'child-default',
    'Stream child default suppresses parent rules');
is(stream('127.0.0.1:' . port(8086))->read(), '|safe',
    'Stream direct circular reference returns an empty value');
is(stream('127.0.0.1:' . port(8087))->read(), '|safe',
    'Stream indirect circular reference releases all locks');

my $log = $t->read_file('error.log');

like($log, qr/circular reference detected for variable "http_self"/,
    'HTTP direct circular reference is logged');
like($log, qr/circular reference detected for variable "http_cycle_a"/,
    'HTTP indirect circular reference is logged');
like($log, qr/circular reference detected for variable "stream_(?:self|cycle_a)"/,
    'Stream circular references are logged');

###############################################################################
