#!/usr/bin/perl

# Tests for RSA configuration validation.

###############################################################################

use warnings;
use strict;
use FindBin;
use Test::More;
use Test::Nginx;

###############################################################################

my @cases = (
    ['rsa_verify x rsa-one.pub;', qr/number of arguments/, 'signature required'],
    ['rsa_encrypt x rsa-one.pub padding=pkcs1;', qr/invalid RSA padding/, 'OAEP only'],
    ['rsa_decrypt x rsa-one.pem padding=none;', qr/invalid RSA padding/, 'raw RSA rejected'],
    ['rsa_sign x rsa-one.pem padding=oaep;', qr/invalid RSA padding/, 'signing padding'],
    ['rsa_verify x rsa-one.pub x padding=oaep;', qr/invalid RSA padding/, 'verification padding'],
    ['rsa_encrypt x rsa-one.pub hash=sha256;', qr/invalid RSA parameter/, 'OAEP hash parameter name'],
    ['rsa_sign x rsa-one.pem oaep_hash=sha256;', qr/invalid RSA parameter/, 'signing hash parameter name'],
    ['rsa_sign x rsa-one.pem hash=md5;', qr/unsupported RSA hash/, 'MD5 not exposed'],
    ['rsa_encrypt x rsa-one.pub oaep_hash=shake128;', qr/unsupported RSA hash/, 'XOF not exposed'],
    ['rsa_verify x rsa-one.pub x mgf1_hash=invalid;', qr/unsupported RSA MGF1/, 'invalid MGF1 hash'],
    ['rsa_sign x rsa-one.pem padding=pkcs1 mgf1_hash=sha256;', qr/cannot be used with pkcs1/, 'PKCS1 with MGF1'],
    ['rsa_verify x rsa-one.pub x padding=pkcs1 salt_length=digest;', qr/cannot be used with pkcs1/, 'PKCS1 with salt'],
    ['rsa_encrypt x rsa-one.pub password=x;', qr/password is only supported/, 'public operation password'],
    ['rsa_verify x rsa-one.pub x password=x;', qr/password is only supported/, 'verification password'],
    ['rsa_sign x rsa-one.pem label=x;', qr/label is only supported/, 'signing label'],
    ['rsa_encrypt x rsa-one.pub salt_length=32;', qr/salt_length is only supported/, 'OAEP salt'],
    ['rsa_sign x rsa-one.pem salt_length=-1;', qr/invalid RSA PSS salt length/, 'negative salt'],
    ['rsa_sign x rsa-one.pem salt_length=auto;', qr/invalid RSA PSS salt length/, 'auto salt only verifies'],
    ['rsa_verify x rsa-one.pub x salt_length=2147483648;', qr/invalid RSA PSS salt length/, 'salt overflow'],
    ['rsa_sign x rsa-one.pem hash=sha256 hash=sha1;', qr/duplicate RSA parameter/, 'duplicate parameter'],
    ['rsa_sign -i x rsa-one.pem;', qr/do not support/, 'case option'],
    ['rsa_sign x missing.pem;', qr/invalid RSA key/, 'missing private key'],
    ['rsa_encrypt x rsa-wrong-type.pub;', qr/invalid RSA key/, 'non-RSA public key'],
    ['rsa_verify x data:invalid x;', qr/invalid RSA key/, 'invalid static PEM'],
    ['rsa_sign x rsa-encrypted.pem;', qr/invalid RSA key/, 'encrypted key without password'],
    ['rsa_sign x rsa-encrypted.pem password=incorrect;', qr/invalid RSA key/, 'incorrect static password'],
    ['rsa_sign x .;', qr/invalid RSA key/, 'directory is not a key file'],
);

my $t = Test::Nginx->new()->has(qw/http http_ssl stream ngx_var_module/)
    ->plan(4 * @cases);
system('python3', "$FindBin::Bin/generate_rsa.py", $t->testdir()) == 0
    or BAIL_OUT('could not generate RSA fixtures');

for my $context ('http', 'stream') {
    for my $case (@cases) {
        my ($expression, $pattern, $name) = @$case;
        $t->write_file_expand('nginx.conf', <<EOF);
%%TEST_GLOBALS%%
daemon off;
events {}
$context { var \$result $expression }
EOF
        my $output = $t->dump_config();
        isnt($?, 0, "$context $name rejected");
        like($output, $pattern, "$context $name diagnostic");
    }
}

###############################################################################
