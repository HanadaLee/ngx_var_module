#!/usr/bin/perl

# Tests for translation configuration errors.

###############################################################################

use warnings;
use strict;
use Test::More;
use Test::Nginx;

###############################################################################

my @cases = (
    ['var $result tr abc ab x;', qr/equal lengths/, 'unequal sets'],
    ['var $result tr -i abc ab xy;', qr/does not support "-i"/, 'case option'],
    ['var $result tr abc ab;', qr/invalid number of arguments/, 'missing set'],
);
my $t = Test::Nginx->new()->has(qw/http stream ngx_var_module/)
    ->plan(4 * scalar @cases);

for my $context ('http', 'stream') {
    for my $case (@cases) {
        my ($directive, $expected, $name) = @$case;
        $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
$context { $directive }
EOF
        my $output = $t->dump_config();
        isnt($?, 0, "$context $name rejected");
        like($output, $expected, "$context $name diagnostic");
    }
}

###############################################################################
