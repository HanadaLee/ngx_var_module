#!/usr/bin/perl

# Tests for var string, file, and parameter functions.

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
    [ 'set expands variables', 'Hello World' ],
    [ 'len counts bytes', '6' ],
    [ 'file reads relative path', 'file-content' ],
    [ 'file limits reads to 1024 bytes', '1024' ],
    [ 'file returns empty for a missing path', '' ],
    [ 'file returns empty for a directory', '' ],
    [ 'upper converts ASCII letters', 'ABC-19' ],
    [ 'lower converts ASCII letters', 'abc-19' ],
    [ 'initcap normalizes word case', 'Hello-World_42' ],
    [ 'trim removes surrounding whitespace', 'value' ],
    [ 'trim removes a custom character', 'value' ],
    [ 'ltrim preserves trailing whitespace', 'value  ' ],
    [ 'ltrim removes a custom character', 'valuexx' ],
    [ 'rtrim preserves leading whitespace', '  value' ],
    [ 'rtrim removes a custom character', 'xxvalue' ],
    [ 'reverse reverses bytes', 'dcba' ],
    [ 'position is one based', '2' ],
    [ 'position supports case insensitive matching', '2' ],
    [ 'position returns zero when absent', '0' ],
    [ 'repeat duplicates the source', 'ababab' ],
    [ 'repeat with zero returns empty', '' ],
    [ 'substr accepts start and length', 'cde' ],
    [ 'substr defaults to the remaining length', 'cdef' ],
    [ 'substr beyond the source returns empty', '' ],
    [ 'replace replaces every nonoverlapping match', 'x x' ],
    [ 'replace supports case insensitive matching', 'x x x' ],
    [ 'replace preserves a source without matches', 'abc' ],
    [ 'replace preserves a source shorter than the search', 'abc' ],
    [ 'extract_param returns the first value', 'two' ],
    [ 'extract_param supports case insensitive keys', 'two' ],
    [ 'extract_param returns empty when absent', '' ],
    [ 'keep_params retains selected keys in order', 'foo=1&baz=3' ],
    [ 'keep_params supports case insensitive keys', 'Foo=1' ],
    [ 'remove_params removes selected keys', 'foo=1&baz=3' ],
    [ 'remove_params supports case insensitive keys', 'BAR=2' ],
);

my $t = Test::Nginx->new()
    ->has(qw/http stream stream_return ngx_var_module/)
    ->plan(2 * (@cases + 1));

$t->write_file('var-data.txt', 'file-content');
$t->write_file('var-large.txt', 'x' x 1100);

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

        var $str_source set Hello;
        var $str_set set "$str_source World";
        var $str_len len abc123;
        var $str_file file var-data.txt;
        var $str_file_large file var-large.txt;
        var $str_file_large_len len $str_file_large;
        var $str_file_missing file missing.txt;
        var $str_file_dir file .;
        var $str_upper upper aBc-19;
        var $str_lower lower AbC-19;
        var $str_initcap initcap hELLO-world_42;
        var $str_trim trim "  value  ";
        var $str_trim_char trim xxvaluexx x;
        var $str_ltrim ltrim "  value  ";
        var $str_ltrim_char ltrim xxvaluexx x;
        var $str_rtrim rtrim "  value  ";
        var $str_rtrim_char rtrim xxvaluexx x;
        var $str_reverse reverse abcd;
        var $str_position position abcabc bc;
        var $str_position_i position -i AbCd bC;
        var $str_position_missing position abc z;
        var $str_repeat repeat ab 3;
        var $str_repeat_zero repeat ab 0;
        var $str_substr substr abcdef 2 3;
        var $str_substr_rest substr abcdef 2;
        var $str_substr_missing substr abc 5;
        var $str_replace replace "cat cat" cat x;
        var $str_replace_i replace -i "One oNE one" one x;
        var $str_replace_missing replace abc z x;
        var $str_replace_long_search replace abc abcdef x;
        var $str_extract extract_param "foo=1&bar= two &bar=three" "&" "=" bar;
        var $str_extract_i extract_param -i "Foo=1&BAR=two" "&" "=" bar;
        var $str_extract_missing extract_param "foo=1" "&" "=" bar;
        var $str_keep keep_params "foo=1&bar=2&baz=3" "&" "=" foo baz;
        var $str_keep_i keep_params -i "Foo=1&BAR=2" "&" "=" foo;
        var $str_remove remove_params "foo=1&bar=2&baz=3" "&" "=" bar;
        var $str_remove_i remove_params -i "Foo=1&BAR=2" "&" "=" foo;

        location / {
            return 200 '$str_set|$str_len|$str_file|$str_file_large_len|$str_file_missing|$str_file_dir|$str_upper|$str_lower|$str_initcap|$str_trim|$str_trim_char|$str_ltrim|$str_ltrim_char|$str_rtrim|$str_rtrim_char|$str_reverse|$str_position|$str_position_i|$str_position_missing|$str_repeat|$str_repeat_zero|$str_substr|$str_substr_rest|$str_substr_missing|$str_replace|$str_replace_i|$str_replace_missing|$str_replace_long_search|$str_extract|$str_extract_i|$str_extract_missing|$str_keep|$str_keep_i|$str_remove|$str_remove_i';
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;

        var $str_source set Hello;
        var $str_set set "$str_source World";
        var $str_len len abc123;
        var $str_file file var-data.txt;
        var $str_file_large file var-large.txt;
        var $str_file_large_len len $str_file_large;
        var $str_file_missing file missing.txt;
        var $str_file_dir file .;
        var $str_upper upper aBc-19;
        var $str_lower lower AbC-19;
        var $str_initcap initcap hELLO-world_42;
        var $str_trim trim "  value  ";
        var $str_trim_char trim xxvaluexx x;
        var $str_ltrim ltrim "  value  ";
        var $str_ltrim_char ltrim xxvaluexx x;
        var $str_rtrim rtrim "  value  ";
        var $str_rtrim_char rtrim xxvaluexx x;
        var $str_reverse reverse abcd;
        var $str_position position abcabc bc;
        var $str_position_i position -i AbCd bC;
        var $str_position_missing position abc z;
        var $str_repeat repeat ab 3;
        var $str_repeat_zero repeat ab 0;
        var $str_substr substr abcdef 2 3;
        var $str_substr_rest substr abcdef 2;
        var $str_substr_missing substr abc 5;
        var $str_replace replace "cat cat" cat x;
        var $str_replace_i replace -i "One oNE one" one x;
        var $str_replace_missing replace abc z x;
        var $str_replace_long_search replace abc abcdef x;
        var $str_extract extract_param "foo=1&bar= two &bar=three" "&" "=" bar;
        var $str_extract_i extract_param -i "Foo=1&BAR=two" "&" "=" bar;
        var $str_extract_missing extract_param "foo=1" "&" "=" bar;
        var $str_keep keep_params "foo=1&bar=2&baz=3" "&" "=" foo baz;
        var $str_keep_i keep_params -i "Foo=1&BAR=2" "&" "=" foo;
        var $str_remove remove_params "foo=1&bar=2&baz=3" "&" "=" bar;
        var $str_remove_i remove_params -i "Foo=1&BAR=2" "&" "=" foo;

        return '$str_set|$str_len|$str_file|$str_file_large_len|$str_file_missing|$str_file_dir|$str_upper|$str_lower|$str_initcap|$str_trim|$str_trim_char|$str_ltrim|$str_ltrim_char|$str_rtrim|$str_rtrim_char|$str_reverse|$str_position|$str_position_i|$str_position_missing|$str_repeat|$str_repeat_zero|$str_substr|$str_substr_rest|$str_substr_missing|$str_replace|$str_replace_i|$str_replace_missing|$str_replace_long_search|$str_extract|$str_extract_i|$str_extract_missing|$str_keep|$str_keep_i|$str_remove|$str_remove_i';
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

    is(scalar @values, scalar @$tests, "$protocol returns every string field");

    for my $i (0 .. $#$tests) {
        is($values[$i], $tests->[$i][1], "$protocol $tests->[$i][0]");
    }
}

###############################################################################
