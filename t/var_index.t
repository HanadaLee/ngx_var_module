#!/usr/bin/perl

# Tests for variable index pages and scope inheritance.

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
    ->has(qw/http rewrite stream stream_return ngx_var_module/)->plan(10);

my @ids = (0, 1, 62, 63, 64, 65, 126, 127, 128, 129, 254, 255);
my $definitions = join '', map { "var \$v$_ set root$_;\n" } 0 .. 255;
my $overrides = join '', map { "var \$v$_ set server$_;\n" } 63, 64, 127, 128;
my $values = join '|', map { "\$v$_" } @ids;

my $conf = <<'EOF';
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    %%DEFINITIONS%%
    server {
        listen 127.0.0.1:8080;
        %%OVERRIDES%%
        location / { return 200 '%%VALUES%%'; }
        location /nested/ {
            var $v64 set nested64;
            var $v65 set nested65;
            var $v255 set nested255;
            var $late set late;
            location /nested/inherit { return 200 '%%VALUES%%|$late'; }
            location /nested/restore {
                var $v64 set restored64;
                return 200 '%%VALUES%%|$late';
            }
        }
        location /sibling { return 200 '%%VALUES%%'; }
    }
    server {
        listen 127.0.0.1:8081;
        location / { return 200 '%%VALUES%%'; }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    %%DEFINITIONS%%
    server { listen 127.0.0.1:8082; return '%%VALUES%%'; }
    server {
        listen 127.0.0.1:8083;
        %%OVERRIDES%%
        return '%%VALUES%%';
    }
    server { listen 127.0.0.1:8084; return '%%VALUES%%'; }
}
EOF

$conf =~ s/%%DEFINITIONS%%/$definitions/g;
$conf =~ s/%%OVERRIDES%%/$overrides/g;
$conf =~ s/%%VALUES%%/$values/g;
$t->write_file_expand('nginx.conf', $conf)->run();

my %server = map { $_ => "server$_" } 63, 64, 127, 128;
my %nested = (%server, map { $_ => "nested$_" } 64, 65, 255);

is(http_content(http_get('/')), expected(\%server), 'HTTP server overrides');
is(http_content(http_get('/nested/inherit')), expected(\%nested) . '|late',
    'HTTP nested overrides and late variable');
$nested{64} = 'restored64';
is(http_content(http_get('/nested/restore')), expected(\%nested) . '|late',
    'HTTP nested page copied only once');
is(http_content(http_get('/sibling')), expected(\%server),
    'HTTP sibling retains server definitions');
is(http_content(http_get('/', PeerAddr => '127.0.0.1:' . port(8081))),
    expected({}), 'HTTP sibling server retains root definitions');
is(http_content(http_get('/')), expected(\%server), 'HTTP repeated lookup');

is(stream('127.0.0.1:' . port(8082))->read(), expected({}), 'Stream root');
is(stream('127.0.0.1:' . port(8083))->read(), expected(\%server),
    'Stream overrides across pages');
is(stream('127.0.0.1:' . port(8084))->read(), expected({}), 'Stream sibling');
is(stream('127.0.0.1:' . port(8083))->read(), expected(\%server),
    'Stream repeated lookup');

###############################################################################

sub expected {
    my ($overrides) = @_;
    return join '|', map { $overrides->{$_} // "root$_" } @ids;
}

###############################################################################
