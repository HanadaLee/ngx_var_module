#!/usr/bin/perl

# Tests for input-sensitive RSA results and boolean verification reevaluation.

###############################################################################

use warnings;
use strict;
use FindBin;
use Test::More;
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

my @cases = (
    ['encrypt', 'message', 'second'],
    ['encrypt', 'key', 'data:$rsa_public_two'],
    ['encrypt', 'hash', 'sha384'],
    ['encrypt', 'mgf1', 'sha1'],
    ['encrypt', 'label', 'second'],
    ['sign', 'message', 'second'],
    ['sign', 'key', 'data:$rsa_private_two'],
    ['sign', 'hash', 'sha384'],
    ['sign', 'mgf1', 'sha1'],
    ['sign', 'padding', 'pkcs1'],
    ['sign', 'salt_length', '8'],
);
my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite stream stream_return
    stream_set ngx_var_module/)->plan(14 * @cases + 6);
system('python3', "$FindBin::Bin/generate_rsa.py", $t->testdir()) == 0
    or BAIL_OUT('could not generate RSA fixtures');
my $definitions = join "\n", grep { /^var \$rsa_(?:private|public)_(?:one|two) / }
    split /\n/, $t->read_file('rsa-directives.conf');
my ($http, $stream) = ('', '');

for my $i (0 .. $#cases) {
    my ($operation, $input, $changed) = @{$cases[$i]};
    my $options = $operation eq 'encrypt'
        ? 'oaep_hash=$hash mgf1_hash=$mgf1 label=$label'
        : 'hash=$hash padding=$padding';
    $options .= ' mgf1_hash=$mgf1 salt_length=$salt_length'
        if $operation eq 'sign' && $input ne 'padding';
    my $key = $operation eq 'encrypt' ? 'data:$rsa_public_one' : 'data:$rsa_private_one';
    my $check = $operation eq 'encrypt' ? 'rsa_decrypt $saved data:$private'
        : 'rsa_verify $message data:$public $saved';
    my $body = <<EOF;
        var \$output rsa_$operation \$message \$key $options;
        var \$encoded hex_encode \$output;
        var \$check $check $options;
        set \$message first;
        set \$key $key;
        set \$public \$rsa_public_one;
        set \$private \$rsa_private_one;
        set \$hash sha256;
        set \$mgf1 sha256;
        set \$padding pss;
        set \$label first;
        set \$salt_length digest;
        set \$original \$$input;
        set \$first \$encoded;
        set \$repeat \$encoded;
        set \$$input $changed;
EOF
    if ($input eq 'key') {
        $body .= 'set $public $rsa_public_two; set $private $rsa_private_two;' . "\n";
    }
    $body .= <<EOF;
        set \$second \$encoded;
        set \$saved \$output;
        set \$checked \$check;
        set \$$input \$original;
        set \$public \$rsa_public_one;
        set \$private \$rsa_private_one;
EOF
    my $result = '$first|$repeat|$second|$encoded|$checked';
    $http .= "location = /case$i { $body return 200 '$result'; }\n";
    my $port = 8081 + $i;
    $stream .= "server { listen 127.0.0.1:$port; $body return '$result'; }\n";
}

my $verify = <<'EOF';
    var $signature rsa_sign original rsa-one.pem;
    var $valid rsa_verify $message $public_key $supplied;
    set $message original;
    set $public_key rsa-one.pub;
    set $supplied $signature;
    set $one $valid;
    set $message altered;
    set $two $valid;
    set $message original;
    set $three $valid;
    set $public_key invalid;
    set $four $valid;
    set $public_key rsa-one.pub;
    set $supplied invalid;
    set $five $valid;
    set $supplied $signature;
EOF
my $decrypt = <<'EOF';
    var $encrypted rsa_encrypt $message rsa-one.pub;
    var $opened rsa_decrypt $saved rsa-one.pem;
    set $message first;
    set $saved $encrypted;
    set $original $saved;
    set $one $opened;
    set $message second;
    set $saved $encrypted;
    set $two $opened;
    set $saved invalid;
    set $three $opened;
    set $saved $original;
EOF

$t->write_file_expand('nginx.conf', <<EOF)->run();
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    $definitions
    server {
        listen 127.0.0.1:8080;
        $http
        location /verify {
            $verify
            return 200 '\$one|\$two|\$three|\$four|\$five|\$valid';
        }
        location /decrypt {
            $decrypt
            return 200 '\$one|\$two|\$three|\$opened';
        }
        var \$redirect_signature rsa_sign message rsa-one.pem;
        var \$redirect_hex hex_encode \$redirect_signature;
        location = /start {
            set \$before \$redirect_hex;
            rewrite ^ /finish last;
        }
        location = /finish { return 200 '\$before|\$redirect_hex'; }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    $definitions
    $stream
    server {
        listen 127.0.0.1:8101;
        $verify
        return '\$one|\$two|\$three|\$four|\$five|\$valid';
    }
    server {
        listen 127.0.0.1:8102;
        $decrypt
        return '\$one|\$two|\$three|\$opened';
    }
}
EOF

for my $context ('http', 'stream') {
    for my $i (0 .. $#cases) {
        my ($operation, $input, $changed) = @{$cases[$i]};
        my $name = "$context $operation $input";
        my $response = $context eq 'http' ? http_content(http_get("/case$i"))
            : stream('127.0.0.1:' . port(8081 + $i))->io('');
        my ($first, $repeat, $second, $restored, $checked) = split /\|/, $response, -1;
        like($first, qr/^[0-9a-f]+$/, "$name initial result");
        is(length $first, 512, "$name modulus-sized output");
        is($repeat, $first, "$name reuses identical inputs");
        isnt($second, $first, "$name changed input is recomputed");
        is($restored, $first, "$name A-B-A returns the original result");
        is($checked, $operation eq 'sign' ? '1' : $input eq 'message' ? 'second' : 'first',
            "$name current result validates");
        my $next = $context eq 'http' ? http_content(http_get("/case$i"))
            : stream('127.0.0.1:' . port(8081 + $i))->io('');
        my ($next_first) = split /\|/, $next;
        isnt($next_first, $first, "$name uses fresh randomness in the next context");
    }
    my $verification = $context eq 'http' ? http_content(http_get('/verify'))
        : stream('127.0.0.1:' . port(8101))->io('');
    is($verification, '1|0|1|0|0|1', "$context verification reevaluates message, key and signature");
    my $decryption = $context eq 'http' ? http_content(http_get('/decrypt'))
        : stream('127.0.0.1:' . port(8102))->io('');
    is($decryption, 'first|second||first', "$context decryption is reevaluated");
}
my ($before, $after) = split /\|/, http_content(http_get('/start'));
like($before, qr/^[0-9a-f]{512}$/, 'PSS signature before internal redirect');
is($after, $before, 'PSS signature is stable across internal redirect');

###############################################################################
