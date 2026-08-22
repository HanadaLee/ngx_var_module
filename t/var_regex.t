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
    [ 'regex_gsub replaces every match', 'abcXdefX' ],
    [ 'regex_gsub expands numbered captures', 'a<1>b<22>' ],
    [ 'regex_gsub expands named captures', 'a[1]b[2]' ],
    [ 'regex_gsub supports case insensitive matching', 'xx' ],
    [ 'regex_gsub preserves an unmatched source', 'abcdef' ],
    [ 'regex_gsub replaces adjacent matches', 'XX' ],
    [ 'regex_gsub handles an empty pattern', 'XaXbX' ],
    [ 'regex_gsub handles a zero-length lookahead', 'aXb' ],
    [ 'regex_gsub preserves start anchor semantics', 'Xabc' ],
    [ 'regex_gsub preserves absolute start semantics', 'Xabc' ],
    [ 'regex_gsub preserves lookbehind context', 'aXaX' ],
    [ 'regex_gsub evaluates a dynamic replacement per match',
      'a<Z1>b<Z2>' ],
    [ 'regex_gsub supports an empty replacement', 'bnn' ],
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
        var $replacement set Z;
        var $regex_gsub regex_gsub abc123def456 "[0-9]+" X;
        var $regex_gsub_capture regex_gsub a1b22 "([0-9]+)" "<$1>";
        var $regex_gsub_named regex_gsub a1b2 "(?<digit>[0-9])" "[$digit]";
        var $regex_gsub_i regex_gsub -i AbCaBC abc x;
        var $regex_gsub_missing regex_gsub abcdef "[0-9]+" X;
        var $regex_gsub_adjacent regex_gsub aaaa aa X;
        var $regex_gsub_empty regex_gsub ab "" X;
        var $regex_gsub_lookahead regex_gsub ab "(?=b)" X;
        var $regex_gsub_anchor regex_gsub abc "^" X;
        var $regex_gsub_absolute regex_gsub abc "\\A" X;
        var $regex_gsub_lookbehind regex_gsub abab "(?<=a)b" X;
        var $regex_gsub_dynamic regex_gsub a1b2 "([0-9])" "<$replacement$1>";
        var $regex_gsub_delete regex_gsub banana a "";

        location / {
            return 200 '$regex_capture|$regex_capture_i|$regex_capture_missing|$regex_sub|$regex_sub_capture|$regex_sub_i|$regex_sub_missing|$regex_gsub|$regex_gsub_capture|$regex_gsub_named|$regex_gsub_i|$regex_gsub_missing|$regex_gsub_adjacent|$regex_gsub_empty|$regex_gsub_lookahead|$regex_gsub_anchor|$regex_gsub_absolute|$regex_gsub_lookbehind|$regex_gsub_dynamic|$regex_gsub_delete';
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
        var $replacement set Z;
        var $regex_gsub regex_gsub abc123def456 "[0-9]+" X;
        var $regex_gsub_capture regex_gsub a1b22 "([0-9]+)" "<$1>";
        var $regex_gsub_named regex_gsub a1b2 "(?<digit>[0-9])" "[$digit]";
        var $regex_gsub_i regex_gsub -i AbCaBC abc x;
        var $regex_gsub_missing regex_gsub abcdef "[0-9]+" X;
        var $regex_gsub_adjacent regex_gsub aaaa aa X;
        var $regex_gsub_empty regex_gsub ab "" X;
        var $regex_gsub_lookahead regex_gsub ab "(?=b)" X;
        var $regex_gsub_anchor regex_gsub abc "^" X;
        var $regex_gsub_absolute regex_gsub abc "\\A" X;
        var $regex_gsub_lookbehind regex_gsub abab "(?<=a)b" X;
        var $regex_gsub_dynamic regex_gsub a1b2 "([0-9])" "<$replacement$1>";
        var $regex_gsub_delete regex_gsub banana a "";

        return '$regex_capture|$regex_capture_i|$regex_capture_missing|$regex_sub|$regex_sub_capture|$regex_sub_i|$regex_sub_missing|$regex_gsub|$regex_gsub_capture|$regex_gsub_named|$regex_gsub_i|$regex_gsub_missing|$regex_gsub_adjacent|$regex_gsub_empty|$regex_gsub_lookahead|$regex_gsub_anchor|$regex_gsub_absolute|$regex_gsub_lookbehind|$regex_gsub_dynamic|$regex_gsub_delete';
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
