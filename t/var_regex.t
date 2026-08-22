#!/usr/bin/perl

# Tests for var PCRE functions.

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
    [ 'regex_capture expands numbered captures', '123-widget' ],
    [ 'regex_capture supports case insensitive matching', 'Alice' ],
    [ 'regex_capture returns empty when unmatched', '' ],
    [ 'regex_sub replaces the first match', 'abcXdef' ],
    [ 'regex_sub expands captures in the replacement', 'abc<123>def' ],
    [ 'regex_sub supports case insensitive matching', 'xaBC' ],
    [ 'regex_sub preserves an unmatched source', 'abcdef' ],
);

my $t = Test::Nginx->new()
    ->has(qw/http stream stream_return pcre ngx_var_module/)
    ->plan(2 * (@cases + 1));

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

        var $regex_capture regex_capture "order-123-widget" "order-([0-9]+)-([a-z]+)" "$1-$2";
        var $regex_capture_i regex_capture -i "NAME=Alice" "name=([a-z]+)" $1;
        var $regex_capture_missing regex_capture abc "([0-9]+)" $1;
        var $regex_sub regex_sub abc123def "[0-9]+" X;
        var $regex_sub_capture regex_sub abc123def "([0-9]+)" "<$1>";
        var $regex_sub_i regex_sub -i AbCaBC abc x;
        var $regex_sub_missing regex_sub abcdef "[0-9]+" X;

        location / {
            return 200 '$regex_capture|$regex_capture_i|$regex_capture_missing|$regex_sub|$regex_sub_capture|$regex_sub_i|$regex_sub_missing';
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;

        var $regex_capture regex_capture "order-123-widget" "order-([0-9]+)-([a-z]+)" "$1-$2";
        var $regex_capture_i regex_capture -i "NAME=Alice" "name=([a-z]+)" $1;
        var $regex_capture_missing regex_capture abc "([0-9]+)" $1;
        var $regex_sub regex_sub abc123def "[0-9]+" X;
        var $regex_sub_capture regex_sub abc123def "([0-9]+)" "<$1>";
        var $regex_sub_i regex_sub -i AbCaBC abc x;
        var $regex_sub_missing regex_sub abcdef "[0-9]+" X;

        return '$regex_capture|$regex_capture_i|$regex_capture_missing|$regex_sub|$regex_sub_capture|$regex_sub_i|$regex_sub_missing';
    }
}

EOF

$t->run();

###############################################################################

check_values(http_content(http_get('/')), 'HTTP', \@cases);
check_values(stream('127.0.0.1:' . port(8081))->read(), 'Stream', \@cases);

###############################################################################

sub check_values {
    my ($payload, $protocol, $tests) = @_;
    my @values = split /\|/, $payload, -1;

    is(scalar @values, scalar @$tests, "$protocol returns every regex field");

    for my $i (0 .. $#$tests) {
        is($values[$i], $tests->[$i][1], "$protocol $tests->[$i][0]");
    }
}

###############################################################################
