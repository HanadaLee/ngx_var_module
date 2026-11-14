#!/usr/bin/perl

# Tests for cipher cache keys and reevaluation across assignments and redirects.

###############################################################################

use warnings;
use strict;
use Test::More;
use Test::Nginx qw/ :DEFAULT http_content /;
use Test::Nginx::Stream qw/ stream /;

###############################################################################

my @cases = (
    ['message', 'message', 'second', 'aes-256-gcm', '', 24],
    ['key', 'key', 'abcdef0123456789abcdef0123456789', 'aes-256-gcm', '', 24],
    ['cipher', 'cipher', 'aes-256-ctr', 'aes-256-cbc', '', 32],
    ['AAD', 'aad', 'second', 'aes-256-gcm', '', 24],
    ['IV', 'iv', 'abcdefghijkl', 'aes-256-gcm', 'iv=$iv', 0],
    ['format', 'format', 'raw', 'aes-256-gcm', 'iv=$iv', 0],
    ['padding', 'padding', 'none', 'aes-256-cbc', 'padding=$padding', 32],
    ['key size', 'key', '0123456789abcdef', '', '', 24],
    ['message', 'message', 'second', 'aes-256-gcm', '', 24, 'chacha20'],
    ['key', 'key', 'abcdef0123456789abcdef0123456789', 'aes-256-gcm', '', 24, 'chacha20'],
    ['AAD', 'aad', 'second', 'aes-256-gcm', '', 24, 'chacha20'],
    ['IV', 'iv', 'abcdefghijkl', 'aes-256-gcm', 'iv=$iv', 0, 'chacha20'],
    ['format', 'format', 'raw', 'aes-256-gcm', 'iv=$iv', 0, 'chacha20'],
);

my $t = Test::Nginx->new()->has(qw/http http_ssl rewrite stream stream_return
    stream_set ngx_var_module/)->plan(2 * (7 * @cases + 14) + 4);

my $http = '';
my $stream = '';
for my $i (0 .. $#cases) {
    my ($name, $input, $changed, $cipher, $extra) = @{$cases[$i]};
    my $operation = $cases[$i][6] // 'aes';
    my $cipher_option = $operation eq 'aes' && $cipher
        ? 'cipher=$cipher' : '';
    my $aad = !$cipher || $cipher =~ /gcm/ ? 'aad=$aad' : '';
    my $decrypt = $extra =~ /iv=/ ? 'iv=$iv' : $extra;
    my $body = <<EOF;
        var \$encrypted ${operation}_encrypt \$message \$key $cipher_option
            $aad $extra format=\$format;
        var \$encoded hex_encode \$encrypted;
        var \$decoded ${operation}_decrypt \$saved \$key $cipher_option
            $aad $decrypt format=raw;
        var \$packed_decoded ${operation}_decrypt \$saved \$key $cipher_option
            $aad @{[$extra =~ /padding/ ? $extra : '']};
        set \$message 0123456789abcdef;
        set \$key 0123456789abcdef0123456789abcdef;
        set \$cipher "$cipher";
        set \$aad first;
        set \$iv 123456789012;
        set \$format packed;
        set \$padding pkcs7;
        set \$original \$$input;
        set \$first \$encoded;
        set \$repeat \$encoded;
        set \$$input $changed;
        set \$second \$encoded;
        set \$saved \$encrypted;
        set \$plain @{[$name eq 'format' ? '$decoded' : '$packed_decoded']};
        set \$$input \$original;
        set \$third \$encoded;
EOF
    # The unused raw decoder still has to be valid for automatic-IV cases.
    $body =~ s/var \$decoded.*?format=raw;//s unless $extra =~ /iv=/;
    my $result = '$first|$repeat|$second|$third|$plain';
    $http .= "location = /case$i { $body return 200 '$result'; }\n";
    my $port = 8081 + $i;
    $stream .= "server { listen 127.0.0.1:$port; $body return '$result'; }\n";
}

my $invalid = <<'EOF';
    var $encrypted aes_encrypt message $key cipher=aes-256-gcm;
    var $encoded hex_encode $encrypted;
    set $key 0123456789abcdef0123456789abcdef;
    set $first $encoded;
    set $key 0123456789abcdef;
    set $second $encoded;
    set $key 0123456789abcdef0123456789abcdef;
EOF
my $distinct = <<'EOF';
    var $one aes_encrypt message 0123456789abcdef0123456789abcdef;
    var $two aes_encrypt message 0123456789abcdef0123456789abcdef;
    var $one_hex hex_encode $one;
    var $two_hex hex_encode $two;
EOF
my $decrypt = <<'EOF';
    var $encrypted aes_encrypt $message 0123456789abcdef0123456789abcdef;
    var $opened aes_decrypt $saved 0123456789abcdef0123456789abcdef;
    set $message first;
    set $original $encrypted;
    set $saved $original;
    set $first $opened;
    set $message second;
    set $saved $encrypted;
    set $second $opened;
    set $saved invalid;
    set $bad $opened;
    set $saved $original;
EOF
my $collision = <<'EOF';
    var $binary hex_decode $collision_input;
    var $checksum crc32 $binary;
    var $encrypted aes_encrypt $binary 0123456789abcdef0123456789abcdef;
    var $encoded hex_encode $encrypted;
    var $opened aes_decrypt $saved 0123456789abcdef0123456789abcdef;
    var $opened_hex hex_encode $opened;
    set $collision_input fa3cfb3f1bb823aa;
    set $first_crc $checksum;
    set $first $encoded;
    set $collision_input af84d31d6d078015;
    set $second_crc $checksum;
    set $second $encoded;
    set $saved $encrypted;
    set $plain $opened_hex;
    set $collision_input fa3cfb3f1bb823aa;
EOF

$t->write_file_expand('nginx.conf', <<EOF)->run();
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        $http
        location /invalid { $invalid return 200 '\$first|\$second|\$encoded'; }
        location /distinct { $distinct return 200 '\$one_hex|\$two_hex'; }
        location /decrypt { $decrypt return 200 '\$first|\$second|\$bad|\$opened'; }
        location /collision {
            $collision
            return 200 '\$first_crc|\$second_crc|\$first|\$second|\$encoded|\$plain';
        }
        var \$redirect_encrypted aes_encrypt \$state 0123456789abcdef0123456789abcdef;
        var \$redirect_hex hex_encode \$redirect_encrypted;
        location = /start {
            set \$state first;
            set \$before \$redirect_hex;
            rewrite ^ /finish last;
        }
        location = /finish {
            set \$after \$redirect_hex;
            set \$state second;
            set \$changed \$redirect_hex;
            set \$state first;
            return 200 '\$before|\$after|\$changed|\$redirect_hex';
        }
    }
}
stream {
    %%TEST_GLOBALS_STREAM%%
    $stream
    server { listen 127.0.0.1:8101; $invalid return '\$first|\$second|\$encoded'; }
    server { listen 127.0.0.1:8102; $distinct return '\$one_hex|\$two_hex'; }
    server { listen 127.0.0.1:8103; $decrypt return '\$first|\$second|\$bad|\$opened'; }
    server {
        listen 127.0.0.1:8104;
        $collision
        return '\$first_crc|\$second_crc|\$first|\$second|\$encoded|\$plain';
    }
}
EOF

for my $context ('http', 'stream') {
    for my $i (0 .. $#cases) {
        my ($name, $input, $changed, $cipher, $extra, $nonce, $operation) = @{$cases[$i]};
        $name = ($operation // 'aes') . ' ' . $name;
        my $response = $context eq 'http' ? http_content(http_get("/case$i"))
            : stream('127.0.0.1:' . port(8081 + $i))->io('');
        my ($first, $repeat, $second, $third, $plain) = split /\|/, $response, -1;
        like($first, qr/^[0-9a-f]+$/, "$context $name initial encryption");
        is($repeat, $first, "$context $name repeated inputs reuse the result");
        isnt($second, $first, "$context $name changes the result");
        is($third, $first, "$context $name A-B-A restores the original result");
        is($plain, $input eq 'message' ? $changed : '0123456789abcdef',
            "$context $name decrypts with the current inputs");
        if ($nonce) {
            isnt(substr($second, 0, $nonce), substr($first, 0, $nonce),
                "$context $name generates a fresh IV after input changes");
        } else {
            like($second, qr/^[0-9a-f]+$/, "$context $name explicit IV encryption");
        }
        my $next = $context eq 'http' ? http_content(http_get("/case$i"))
            : stream('127.0.0.1:' . port(8081 + $i))->io('');
        my ($next_first) = split /\|/, $next;
        if ($nonce) {
            isnt($next_first, $first, "$context $name cache is context-local");
        } else {
            is($next_first, $first, "$context $name explicit IV is deterministic");
        }
    }

    my $invalid_result = $context eq 'http' ? http_content(http_get('/invalid'))
        : stream('127.0.0.1:' . port(8101))->io('');
    my ($first, $bad, $last) = split /\|/, $invalid_result, -1;
    like($first, qr/^[0-9a-f]+$/, "$context valid input is encrypted");
    is($bad, '', "$context invalid input does not return a previous result");
    is($last, $first, "$context failure does not destroy a previous result");
    my $different = $context eq 'http' ? http_content(http_get('/distinct'))
        : stream('127.0.0.1:' . port(8102))->io('');
    my ($one, $two) = split /\|/, $different;
    like($one, qr/^[0-9a-f]+$/, "$context first rule encrypts");
    isnt($one, $two, "$context separate rules have separate IVs");
    my $decoded = $context eq 'http' ? http_content(http_get('/decrypt'))
        : stream('127.0.0.1:' . port(8103))->io('');
    my @decoded = split /\|/, $decoded, -1;
    is($decoded[0], 'first', "$context initial ciphertext decrypts");
    is($decoded[1], 'second', "$context changed ciphertext is reevaluated");
    is($decoded[2], '', "$context invalid ciphertext produces no plaintext");
    is($decoded[3], 'first', "$context valid ciphertext decrypts after failure");
    my $collided = $context eq 'http' ? http_content(http_get('/collision'))
        : stream('127.0.0.1:' . port(8104))->io('');
    my ($crc_a, $crc_b, $cipher_a, $cipher_b, $again, $plain) =
        split /\|/, $collided;
    is($crc_a, $crc_b, "$context inputs have the same CRC32");
    like($cipher_a, qr/^[0-9a-f]+$/, "$context first colliding input encrypts");
    isnt($cipher_a, $cipher_b, "$context cache compares full inputs on hash collision");
    is($again, $cipher_a, "$context original colliding input remains cached");
    is($plain, 'af84d31d6d078015', "$context colliding input decrypts correctly");
}

my ($before, $after, $changed, $restored) = split /\|/,
    http_content(http_get('/start'));
like($before, qr/^[0-9a-f]+$/, 'encryption before internal redirect');
is($after, $before, 'internal redirect retains the request cache');
isnt($changed, $before, 'input is reevaluated after internal redirect');
is($restored, $before, 'original inputs retrieve the original result after redirect');

###############################################################################
