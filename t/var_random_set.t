#!/usr/bin/perl

# Regression tests for random var values used by the nginx set directive.

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
    ->plan(4);

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

        var $random_length rand 0 10000;
        var $random_hex hexrand 31;

        location / {
            set $random_copy "[$random_length][$random_length]";
            set $random_copy_again "<$random_length>";
            set $hex_copy "$random_hex:$random_hex";

            return 200 '$random_copy|$random_copy_again|$random_length|$hex_copy|$random_hex';
        }
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    server {
        listen 127.0.0.1:8081;

        var $random_length rand 0 10000;
        var $random_hex hexrand 31;

        set $random_copy "[$random_length][$random_length]";
        set $random_copy_again "<$random_length>";
        set $hex_copy "$random_hex:$random_hex";

        return '$random_copy|$random_copy_again|$random_length|$hex_copy|$random_hex';
    }
}

EOF

$t->run();

###############################################################################

my ($http_ok, $http_error, %http_lengths) = (1, '');

for (1 .. 200) {
    my $body = http_content(http_get('/'));
    my ($ok, $length) = check_random_payload($body);

    if (!$ok) {
        $http_ok = 0;
        $http_error = $body;
        last;
    }

    $http_lengths{$length} = 1;
}

ok($http_ok, 'HTTP set reuses cached rand and hexrand values')
    or diag("invalid HTTP random payload: $http_error");
cmp_ok(scalar keys %http_lengths, '>=', 2,
    'HTTP requests exercise more than one rand result length');

my ($stream_ok, $stream_error, %stream_lengths) = (1, '');

for (1 .. 200) {
    my $body = stream('127.0.0.1:' . port(8081))->read();
    my ($ok, $length) = check_random_payload($body);

    if (!$ok) {
        $stream_ok = 0;
        $stream_error = $body;
        last;
    }

    $stream_lengths{$length} = 1;
}

ok($stream_ok, 'Stream set reuses cached rand and hexrand values')
    or diag("invalid Stream random payload: $stream_error");
cmp_ok(scalar keys %stream_lengths, '>=', 2,
    'Stream sessions exercise more than one rand result length');

###############################################################################

sub check_random_payload {
    my ($payload) = @_;

    return (0, 0) unless $payload =~
        /^\[(\d+)\]\[\1\]\|<\1>\|\1\|([0-9a-f]{31}):\2\|\2$/;

    my $number = $1;

    return (0, 0) if $number > 10000;

    return (1, length($number));
}

###############################################################################
