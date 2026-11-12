#!/usr/bin/perl

# Tests for nested var evaluation and recovery after circular references.

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
    ['self', '$self|$ok', '|ok'],
    ['cycle', '$cycle_a|$ok', '|ok'],
    ['map', '$map_source|$ok', '|ok'],
    ['diamond', '$diamond|$repeat|$ok', '[x]<x>|xx|ok'],
    ['error', '$bad|$bad|$ok', '||ok'],
    ['deep', '$deep_0|$deep_0|$ok', 'deep|deep|ok'],
    ['limit', '$limit_0|$ok', '|ok'],
    ['recovery', '$cycle_a|$deep_0|$diamond', '|deep|[x]<x>'],
);

my $t = Test::Nginx->new()
    ->has(qw/http rewrite map stream stream_map stream_return ngx_var_module/)
    ->plan(2 * scalar(@cases) + 8);

my $variables = <<'EOF';
    var $ok set ok;
    var $self set $self;
    var $cycle_a set $cycle_b;
    var $cycle_b set $cycle_a;

    map $map_source $map_bridge {
        volatile;
        default $map_source;
    }
    var $map_source set $map_bridge;

    var $leaf set x;
    var $left set [$leaf];
    var $right set <$leaf>;
    var $diamond set $left$right;
    var $repeat set $leaf$leaf;
    var $bad div 1 0;
EOF

$variables .= chain('deep', 64, 'deep');
$variables .= chain('limit', 120, 'unreachable');

my ($http_locations, $stream_servers) = ('', '');
for my $i (0 .. $#cases) {
    my ($name, $value) = @{$cases[$i]};
    my $http_value = prefix($value, 'h_');
    my $stream_value = prefix($value, 's_');
    my $port = 8081 + $i;

    $http_locations .= <<EOF;
        location = /$name {
            return 200 '$http_value';
        }
EOF

    $stream_servers .= <<EOF;
    server {
        listen 127.0.0.1:$port;
        return '$stream_value';
    }
EOF
}

my $conf = <<'EOF';

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    %%HTTP_VARIABLES%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        %%HTTP_LOCATIONS%%
    }
}

stream {
    %%TEST_GLOBALS_STREAM%%

    %%STREAM_VARIABLES%%

    %%STREAM_SERVERS%%
}

EOF

$conf =~ s/%%HTTP_VARIABLES%%/prefix($variables, 'h_')/e;
$conf =~ s/%%STREAM_VARIABLES%%/prefix($variables, 's_')/e;
$conf =~ s/%%HTTP_LOCATIONS%%/$http_locations/;
$conf =~ s/%%STREAM_SERVERS%%/$stream_servers/;

$t->write_file_expand('nginx.conf', $conf)->run();

###############################################################################

for my $i (0 .. $#cases) {
    my ($name, undef, $expected) = @{$cases[$i]};

    is(http_content(http_get('/' . $name)), $expected, 'HTTP ' . $name);
    is(stream('127.0.0.1:' . port(8081 + $i))->read(), $expected,
        'Stream ' . $name);
}

my $log = $t->read_file('error.log');

for my $subsystem (['HTTP', 'h_'], ['Stream', 's_']) {
    my ($name, $prefix) = @$subsystem;

    for my $variable (qw/self cycle_a map_source/) {
        like($log, qr/circular reference detected for variable "$prefix$variable"/,
            "$name detects a cycle through $variable");
    }

    like($log, qr/cycle while evaluating variable "${prefix}limit_\d+"/,
        "$name preserves the core variable depth limit");
}

###############################################################################

sub prefix {
    my ($text, $prefix) = @_;

    $text =~ s/\$(\w+)/\$$prefix$1/g;
    return $text;
}

sub chain {
    my ($name, $depth, $value) = @_;
    my $text = '';

    for my $i (0 .. $depth - 2) {
        $text .= "    var \$${name}_$i set \$${name}_" . ($i + 1) . ";\n";
    }

    return $text . "    var \$${name}_" . ($depth - 1) . " set $value;\n";
}

###############################################################################
