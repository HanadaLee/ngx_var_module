#!/usr/bin/perl

# Tests for byte translation in HTTP and Stream.

###############################################################################

use warnings;
use strict;

use Test::More;
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my @cases = (
    ['abcabc', 'abc', 'xyz', 'xyzxyz', 'all occurrences'],
    ['ab', 'ab', 'ba', 'ba', 'translation is simultaneous'],
    ['a-a_~', '-_~', '+=/', 'a+a=/', 'signature alphabet'],
    ['a-z', 'a-z', 'xyz', 'xyz', 'hyphen is literal'],
    ['aA', 'a', 'x', 'xA', 'case sensitive'],
    ['a', 'aa', 'xy', 'y', 'last duplicate mapping wins'],
    ['abc', '', '', 'abc', 'empty sets preserve source'],
    ['', 'abc', 'xyz', '', 'empty source'],
    ['abc', 'xyz', '123', 'abc', 'no matches'],
);

my $t = Test::Nginx->new()->has(qw/http stream stream_return ngx_var_module/)
    ->plan(2 * (@cases + 3) + 1);

my (@directives, @variables, @expected);
for my $i (0 .. $#cases) {
    my ($source, $from, $to, $expected) = @{$cases[$i]};
    push @directives, "var \$tr_$i tr \"$source\" \"$from\" \"$to\";";
    push @variables, "\$tr_$i";
    push @expected, $expected;
}
push @directives, 'var $tr_source set abc;', 'var $tr_from set ac;',
    'var $tr_to set zx;', 'var $tr_dynamic tr $tr_source $tr_from $tr_to;';
push @variables, '$tr_dynamic';
push @expected, 'zbx';
push @directives, 'var $tr_bytes hex_decode 00ff80;',
    'var $tr_bytes_from hex_decode 00ff;', 'var $tr_bytes_to hex_decode ff00;',
    'var $tr_binary tr $tr_bytes $tr_bytes_from $tr_bytes_to;',
    'var $tr_hex hex_encode $tr_binary;',
    'var $tr_bad_from set ab;', 'var $tr_bad_to set x;',
    'var $tr_bad tr abc $tr_bad_from $tr_bad_to;';
push @variables, '$tr_hex', '$tr_bad';
push @expected, 'ff0080', '';
my $directives = join "\n", @directives;
my $response = join '|', @variables;

$t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        $directives
        location / { return 200 "$response"; }
        location = /reevaluate {
            var \$tr_result tr \$tr_mutable ab xy;
            set \$tr_mutable a;
            set \$first \$tr_result;
            set \$tr_mutable b;
            set \$second \$tr_result;
            return 200 "\$first|\$second";
        }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    server {
        listen 127.0.0.1:8081;
        $directives
        return "$response";
    }
}
EOF

$t->run();
my @http = split /\|/, http_content(http_get('/')), -1;
my @stream = split /\|/, stream('127.0.0.1:' . port(8081))->read(), -1;
for my $i (0 .. $#expected) {
    my $name = $i < @cases ? $cases[$i][4]
        : ('variable arguments', 'binary bytes', 'invalid variable lengths')[$i - @cases];
    is($http[$i], $expected[$i], "http $name");
    is($stream[$i], $expected[$i], "stream $name");
}
is(http_content(http_get('/reevaluate')), 'x|y', 'translation is reevaluated');

###############################################################################
