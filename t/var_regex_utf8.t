#!/usr/bin/perl

# Tests for UTF character boundaries in global regex substitutions.

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
    [ 'empty matches', 'aé€😀', '(*UTF)', 'XaXéX€X😀X' ],
    [ 'lookahead', 'aé€😀', '(*UTF)(?=.)', 'XaXéX€X😀' ],
    [ 'lookbehind', 'aé€😀', '(*UTF)(?<=.)', 'aXéX€X😀X' ],
    [ 'start anchor', 'aé€😀', '(*UTF)^', 'Xaé€😀' ],
    [ 'end anchor', 'aé€😀', '(*UTF)$', 'aé€😀X' ],
    [ 'nonempty matches', 'aé€😀', '(*UTF).', 'XXXX' ],
    [ 'empty source', '', '(*UTF)', 'X' ],
    [ 'combining characters', 'é', '(*UTF)', 'XeX́X' ],
    [ 'byte mode', 'aé€😀', '', 'X' . join('X', split //, 'aé€😀') . 'X' ],
);

my $t = Test::Nginx->new()
    ->has(qw/http stream stream_return pcre ngx_var_module/);

my $rules = join '', map {
    'var $v' . $_ . ' regex_gsub "' . $cases[$_][1]
        . '" "' . $cases[$_][2] . '" X;' . "\n"
} 0 .. $#cases;
my $output = join '|', map { '$v' . $_ } 0 .. $#cases;

$t->write_file_expand('nginx.conf', <<EOF);

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:8080;
        $rules
        return 200 '$output';
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;
        $rules
        return '$output';
    }
}

EOF

$t->try_run('PCRE UTF support is not available')->plan(2 * (@cases + 1));

###############################################################################

check_values(http_content(http_get('/')), 'HTTP');
check_values(stream('127.0.0.1:' . port(8081))->read(), 'Stream');

###############################################################################

sub check_values {
    my ($payload, $protocol) = @_;
    my @values = split /\|/, $payload, -1;

    is(scalar @values, scalar @cases, "$protocol returns every regex field");

    for my $i (0 .. $#cases) {
        is($values[$i], $cases[$i][3], "$protocol $cases[$i][0]");
    }
}

###############################################################################
