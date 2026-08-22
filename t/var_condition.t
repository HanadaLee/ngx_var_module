#!/usr/bin/perl

# Tests for indexed variable lookup with ngx_condition_module.

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
    ->has(qw/http stream stream_return ngx_condition_module ngx_var_module/)
    ->plan(20);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    log_format index_padding '$arg_pad00$arg_pad01$arg_pad02$arg_pad03'
                             '$arg_pad04$arg_pad05$arg_pad06$arg_pad07';

    condition h_true bool true;
    condition h_false bool false;
    condition h_location = $arg_location 1;
    condition h_child = $arg_child 1;
    condition h_parent = $arg_parent 1;
    condition h_only = $arg_only 1;
    condition h_self != $http_self "";
    condition h_cycle_a != $http_cycle_b "";
    condition h_cycle_b != $http_cycle_a "";

    when h_parent {
        var $http_chain set parent-hit;
    }
    var $http_chain set parent-default;

    var $http_terminal set first-default;
    when h_true {
        var $http_terminal set unreachable;
    }

    when h_only {
        var $http_no_default set condition-hit;
    }
    var $http_high_index set high-index;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        var $scope set alpha;

        when h_child {
            var $http_chain set child-hit;
        }

        when h_self {
            var $http_self set direct;
        }
        when h_cycle_a {
            var $http_cycle_a set cycle-a;
        }
        when h_cycle_b {
            var $http_cycle_b set cycle-b;
        }
        var $safe set safe;

        location = /chain {
            when h_location {
                var $http_chain set location-hit;
            }

            return 200 '$scope|$http_chain|$http_terminal|$http_no_default|$http_high_index';
        }

        location = /local {
            var $scope set local;
            return 200 '$scope|$http_chain';
        }

        location = /default {
            var $http_chain set location-default;
            return 200 $http_chain;
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

    condition s_true bool true;
    condition s_false bool false;
    condition s_self != $stream_self "";
    condition s_cycle_a != $stream_cycle_b "";
    condition s_cycle_b != $stream_cycle_a "";

    when s_true {
        var $stream_chain set parent-hit;
    }
    var $stream_chain set parent-default;

    when s_false {
        var $stream_default set parent-condition;
    }
    var $stream_default set parent-default;

    when s_true {
        var $stream_override set parent-hit;
    }
    var $stream_override set parent-default;

    var $stream_terminal set first-default;
    when s_true {
        var $stream_terminal set unreachable;
    }

    when s_false {
        var $stream_no_default set condition-hit;
    }
    var $stream_high_index set high-index;

    server {
        listen 127.0.0.1:8082;

        var $stream_scope set alpha;
        when s_false {
            var $stream_chain set child-miss;
            var $stream_default set child-miss;
        }

        return '$stream_scope|$stream_chain|$stream_default|$stream_terminal|$stream_no_default|$stream_high_index';
    }

    server {
        listen 127.0.0.1:8083;
        var $stream_scope set beta;
        return '$stream_scope|$stream_high_index';
    }

    server {
        listen 127.0.0.1:8084;
        when s_true {
            var $stream_chain set child-hit;
        }
        return $stream_chain;
    }

    server {
        listen 127.0.0.1:8085;
        var $stream_override set child-default;
        return $stream_override;
    }

    server {
        listen 127.0.0.1:8086;
        when s_self {
            var $stream_self set direct;
        }
        var $stream_safe set safe;
        return '$stream_self|$stream_safe';
    }

    server {
        listen 127.0.0.1:8087;
        when s_cycle_a {
            var $stream_cycle_a set cycle-a;
        }
        when s_cycle_b {
            var $stream_cycle_b set cycle-b;
        }
        var $stream_safe set safe;
        return '$stream_cycle_a|$stream_safe';
    }
}

EOF

$t->run();

###############################################################################

is(http_content(http_get('/chain?location=1&child=1&parent=1')),
    'alpha|location-hit|first-default||high-index',
    'HTTP location condition has highest priority');
is(http_content(http_get('/chain?child=1&parent=1')),
    'alpha|child-hit|first-default||high-index',
    'HTTP server condition precedes inherited parent rules');
is(http_content(http_get('/chain?parent=1')),
    'alpha|parent-hit|first-default||high-index',
    'HTTP parent condition is inherited through two levels');
is(http_content(http_get('/chain')),
    'alpha|parent-default|first-default||high-index',
    'HTTP parent default is inherited through two levels');
is(http_content(http_get('/chain?only=1')),
    'alpha|parent-default|first-default|condition-hit|high-index',
    'HTTP condition-only variable can match without a default');
is(http_content(http_get('/local?child=1')), 'local|child-hit',
    'HTTP local variable coexists with inherited indexed variables');
is(http_content(http_get('/default?child=1&parent=1')), 'location-default',
    'HTTP location default suppresses all parent rules');
is(http_content(http_get('/',
    PeerAddr => '127.0.0.1:' . port(8081))), 'beta|high-index',
    'HTTP servers keep separate definitions for the same index');
is(http_content(http_get('/self')), '|safe',
    'HTTP condition evaluation detects a direct circular reference');
is(http_content(http_get('/cycle')), '|safe',
    'HTTP condition evaluation detects an indirect circular reference');

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
    'Stream condition evaluation detects a direct circular reference');
is(stream('127.0.0.1:' . port(8087))->read(), '|safe',
    'Stream condition evaluation detects an indirect circular reference');

my $log = $t->read_file('error.log');

like($log, qr/circular reference detected for variable "http_self"/,
    'HTTP direct circular reference is logged');
like($log, qr/circular reference detected for variable "http_cycle_a"/,
    'HTTP indirect circular reference is logged');
like($log, qr/circular reference detected for variable "stream_self"/,
    'Stream direct circular reference is logged');
like($log, qr/circular reference detected for variable "stream_cycle_a"/,
    'Stream indirect circular reference is logged');

###############################################################################
