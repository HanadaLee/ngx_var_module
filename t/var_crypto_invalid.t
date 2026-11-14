#!/usr/bin/perl

# Tests for cipher configuration validation in HTTP and Stream.

###############################################################################

use warnings;
use strict;
use Test::More;
use Test::Nginx;

###############################################################################

my @cases = (
    ['aes_encrypt x key;', qr/key length/, 'short literal key'],
    ['aes_encrypt x $key cipher=rc4;', qr/unsupported AES cipher/, 'invalid AES cipher'],
    ['aes_encrypt x $key cipher=aes-256-ccm;', qr/unsupported AES cipher/, 'CCM not registered'],
    ['aes_encrypt x $key cipher=aes-256-cfb8;', qr/unsupported AES cipher/, 'CFB8 not registered'],
    ['aes_encrypt x $key cipher=aes-256-cbc cipher=aes-256-ctr;', qr/duplicate/, 'duplicate parameter'],
    ['aes_encrypt x $key typo=1;', qr/invalid cipher parameter/, 'unknown parameter'],
    ['aes_encrypt x $key mode=gcm;', qr/invalid cipher parameter/, 'mode option removed'],
    ['aes_encrypt x $key cipher=gcm;', qr/unsupported AES cipher/, 'short mode name rejected'],
    ['aes_encrypt x $key cipher=;', qr/unsupported AES cipher/, 'empty cipher rejected'],
    ['aes_encrypt x 1234567890123456 cipher=aes-256-gcm;', qr/key length/, '128-bit key with AES-256'],
    ['aes_decrypt x 12345678901234567890123456789012 cipher=aes-128-gcm;', qr/key length/, '256-bit key with AES-128'],
    ['aes_encrypt x $key format=raw;', qr/requires an explicit IV/, 'raw without IV'],
    ['aes_encrypt x $key iv=short;', qr/IV length/, 'short IV'],
    ['aes_encrypt x $key cipher=aes-256-ecb iv=1234567890123456;', qr/IV length/, 'ECB with IV'],
    ['aes_encrypt x $key cipher=aes-256-cbc aad=x;', qr/only supported by authenticated/, 'CBC with AAD'],
    ['aes_encrypt x $key padding=pkcs7;', qr/padding is only supported/, 'GCM with padding'],
    ['aes_encrypt x $key cipher=aes-256-cbc padding=zero;', qr/invalid cipher padding/, 'unknown padding'],
    ['aes_encrypt x $key format=other;', qr/invalid cipher format/, 'unknown format'],
    ['aes_decrypt x $key iv=123456789012;', qr/cannot be used with packed decryption/, 'packed decryption with IV'],
    ['aes_encrypt -i x $key;', qr/do not support/, 'case option'],
    ['chacha20_encrypt x 1234567890123456;', qr/key length/, 'ChaCha20 needs 32-byte key'],
    ['chacha20_encrypt x $key cipher=aes-256-gcm;', qr/cipher is only supported by AES/, 'ChaCha20 rejects cipher'],
    ['chacha20_decrypt x $key cipher=$cipher;', qr/cipher is only supported by AES/, 'ChaCha20 rejects dynamic cipher'],
    ['chacha20_encrypt x $key padding=none;', qr/padding is only supported/, 'ChaCha20 rejects padding'],
    ['chacha20_encrypt x $key format=raw;', qr/requires an explicit IV/, 'ChaCha20 raw needs IV'],
    ['chacha20_encrypt x $key iv=1234567890123456;', qr/IV length/, 'ChaCha20 requires 12-byte IV'],
    ['chacha20_decrypt x $key iv=123456789012;', qr/cannot be used with packed decryption/, 'ChaCha20 packed reads IV'],
    ['encrypt x $key;', qr/unsupported function/, 'generic encrypt removed'],
    ['decrypt x $key;', qr/unsupported function/, 'generic decrypt removed'],
);
my $t = Test::Nginx->new()->has(qw/http http_ssl stream ngx_var_module/)
    ->plan(4 * scalar @cases);
for my $context ('http', 'stream') {
    for my $case (@cases) {
        my ($expr, $expected, $name) = @$case;
        $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
$context {
    var \$key set 12345678901234567890123456789012;
    var \$cipher set aes-256-gcm;
    var \$result $expr
}
EOF
        my $output = $t->dump_config();
        isnt($?, 0, "$context $name rejected");
        like($output, $expected, "$context $name diagnostic");
    }
}

###############################################################################
