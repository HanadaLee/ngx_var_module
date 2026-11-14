# ngx_var_module

`ngx_http_var_module` and `ngx_stream_var_module` define nginx variables using string, number, encoding, cryptographic, time, and IP functions. Both modules provide the same functions through the `var` directive.

This module is experimental. Issues and pull requests are welcome.

## Contents

- [Example](#example)
- [Installation](#installation)
- [Directive](#directive)
- [Conditional definitions](#conditional-definitions)
- [Function reference](#function-reference)
- [Testing](#testing)
- [Author](#author)
- [License](#license)

## Example

```nginx
http {
    server {
        listen 8080;

        var $normalized_host lower $host;
        var $cache_id md5 "$normalized_host$uri";

        location / {
            return 200 "$cache_id\n";
        }
    }
}

stream {
    server {
        listen 8081;

        var $client_network cidr $remote_addr 24 64;
        return "$client_network\n";
    }
}
```

## Installation

Build nginx with this repository as an additional module:

```sh
./configure --with-http_ssl_module --with-stream --with-stream_ssl_module \
    --add-module=/path/to/ngx_var_module
make
make install
```

The HTTP module is built when HTTP is enabled. The Stream module is built when Stream is enabled. To use named conditions, also build `ngx_expr_module` statically in the same nginx configuration.

### Dependencies

| Dependency | Functions |
| --- | --- |
| OpenSSL | `sha224`, `sha256`, `sha384`, `sha512`, all HMAC, AES, ChaCha20, and RSA functions |
| PCRE or PCRE2 | `regex_capture`, `regex_sub`, `regex_gsub` |
| cJSON, with nginx earlier than 1.31.5 | `extract_json` |

Functions whose dependencies are unavailable are not registered. Using them causes configuration validation to fail.

Enable OpenSSL through an nginx SSL module, such as `--with-http_ssl_module` or `--with-stream_ssl_module`. PCRE is normally enabled by the default nginx build. `crc32`, `md5`, `sha1`, `rand`, and `hexrand` do not require OpenSSL.

With nginx 1.31.5 and later, `extract_json` uses the core JSON parser. For earlier versions, install cJSON before configuring nginx:

```sh
# Debian / Ubuntu
sudo apt-get install libcjson-dev

# CentOS / RHEL
sudo yum install cjson-devel

# macOS
brew install cjson
```

Rerun `configure` after installing or upgrading cJSON.

## Directive

### var

**Syntax:** `var $variable function [-i] arguments...;`

**Default:** —

**HTTP context:** `http`, `server`, `location`, `when`

**Stream context:** `stream`, `server`, `when`

Defines a variable whose value is calculated when it is read. Arguments can contain text, variables, or both. Function names, option names, `-i`, and regular expression patterns are fixed in the configuration.

Functions can be composed through intermediate variables:

```nginx
var $digest hmac_sha256 $uri $secret;
var $token base64url_encode $digest;
```

Strings are byte sequences. Lengths and offsets are measured in bytes, and case conversion applies to ASCII letters. Binary values can be passed directly between functions; encode them before placing them in URLs, headers, or logs.

Invalid runtime arguments generally produce an empty value. Exceptions are described with the function: for example, `rsa_verify` returns `0`, and parameter filtering preserves the input if its separator or delimiter is invalid. A failed calculation does not select another definition of the variable.

Definitions and arguments are reevaluated when the variable is read, with these exceptions:

- `rand` and `hexrand` retain the first generated value for each definition within the request or Stream session, even if their arguments later change.
- Encryption and signing functions reuse a result only for the same definition and identical inputs within the request or Stream session. Different inputs do not share a cached result. Decryption and verification results are not cached.

`var` must not share a variable name with a `map` or `geo` definition. Assignment directives such as HTTP `set` can overwrite a variable defined by `var`.

## Conditional definitions

With `ngx_expr_module`, use `expr` to define conditions and `when` to select a definition:

```nginx
expr has_header_a !is_empty $http_a;
expr has_header_b !is_empty $http_b;

when has_header_a {
    var $selected set $http_a;
}

when !has_header_a has_header_b {
    var $selected set $http_b;
}

var $selected set default;
```

Multiple condition names in a `when` block are combined with AND. Prefix a name with `!` to negate it. The same syntax is available in Stream with Stream variables.

Definitions of the same variable are checked in configuration order. The first matching definition is used. An unconditional definition ends the chain, so place the fallback last. If no definition matches, the result is empty.

Inheritance is applied separately for each variable. Local definitions are checked first; if they contain no unconditional definition, the parent definitions follow them. A local unconditional definition replaces the inherited chain.

```nginx
http {
    var $selected set parent;

    server {
        listen 8080;

        expr has_override !is_empty $arg_override;
        when has_override {
            var $selected set $arg_override;
        }

        location / {
            # Uses the argument when present, otherwise "parent".
            return 200 $selected;
        }

        location /fixed {
            var $selected set fixed;
            return 200 $selected;
        }
    }
}
```

Without `ngx_expr_module`, use a trailing `if=` or `if!=` parameter:

```nginx
var $selected set $http_a if=$http_a;
var $selected set no-header if!=$http_a;
```

`if=` matches a non-empty value other than `0`; `if!=` matches an empty value or `0`. These parameters are not accepted in builds with `ngx_expr_module`.

## Function reference

Square brackets in syntax descriptions mark optional arguments; they are not literal configuration characters. Examples show the resulting value in comments where it is fixed.

| Category | Functions |
| --- | --- |
| [Strings and files](#strings-and-files) | [set](#set), [len](#len), [file](#file), [upper, lower](#upper-and-lower), [initcap](#initcap), [trim, ltrim, rtrim](#trim-ltrim-and-rtrim), [reverse](#reverse), [position](#position), [repeat](#repeat), [substr](#substr), [replace](#replace), [tr](#tr) |
| [Parameter lists](#parameter-lists) | [extract_param](#extract_param), [keep_params, remove_params](#keep_params-and-remove_params) |
| [JSON](#json) | [extract_json](#extract_json) |
| [Regular expressions](#regular-expressions) | [regex_capture](#regex_capture), [regex_sub](#regex_sub), [regex_gsub](#regex_gsub) |
| [Numbers](#numbers) | [abs](#abs), [min, max](#min-and-max), [add, sub, mul, div, mod](#integer-arithmetic), [bitwise_and, bitwise_not, bitwise_or, bitwise_xor](#bitwise-operations), [lshift, rshift, urshift](#bit-shifts), [round](#round), [trunc, floor, ceil](#trunc-floor-and-ceil) |
| [Random values](#random-values) | [rand](#rand), [hexrand](#hexrand) |
| [Encoding](#encoding) | [hex_encode, hex_decode](#hex_encode-and-hex_decode), [itohex, hextoi](#itohex-and-hextoi), [escape_uri, escape_args, escape_uri_component, escape_html](#escaping), [unescape_uri](#unescape_uri), [base64_encode, base64url_encode, base64_decode, base64url_decode](#base64) |
| [Checksums and hashes](#checksums-and-hashes) | [crc32](#crc32), [md5, sha1, sha224, sha256, sha384, sha512](#message-digests), [hmac_md5, hmac_sha1, hmac_sha224, hmac_sha256, hmac_sha384, hmac_sha512](#hmac) |
| [Symmetric encryption](#symmetric-encryption) | [aes_encrypt, aes_decrypt](#aes_encrypt-and-aes_decrypt), [chacha20_encrypt, chacha20_decrypt](#chacha20_encrypt-and-chacha20_decrypt) |
| [RSA](#rsa) | [rsa_encrypt, rsa_decrypt](#rsa_encrypt-and-rsa_decrypt), [rsa_sign](#rsa_sign), [rsa_verify](#rsa_verify) |
| [Time](#time) | [gmt_time](#gmt_time), [local_time](#local_time), [unix_time](#unix_time) |
| [IP addresses](#ip-addresses) | [cidr](#cidr) |

## Strings and files

### set

**Syntax:** `set value`

Returns the expanded value. This function defines a value to calculate on access; it does not run an assignment in the rewrite phase.

```nginx
var $origin set "$scheme://$host";
var $greeting set "Hello world";  # Hello world
```

### len

**Syntax:** `len value`

Returns the byte length as a decimal integer. An empty value has length `0`.

```nginx
var $length len hello;  # 5
var $empty_length len "";  # 0
```

### file

**Syntax:** `file path`

Reads up to the first 1024 bytes of a file. Relative paths are resolved against the nginx prefix. A missing file or a directory produces an empty value.

```nginx
var $message file /etc/nginx/messages/maintenance.txt;
var $marker file status.txt;
```

### upper and lower

**Syntax:** `upper value`

**Syntax:** `lower value`

Converts ASCII letters to uppercase or lowercase. Other bytes are unchanged.

```nginx
var $upper upper aBc-19;  # ABC-19
var $lower lower AbC-19;  # abc-19
```

### initcap

**Syntax:** `initcap value`

Uppercases the first character of each word and lowercases the remaining letters. Words are sequences of ASCII letters and digits, separated by other bytes.

```nginx
var $title initcap hELLO-world_42;  # Hello-World_42
```

### trim, ltrim, and rtrim

**Syntax:** `trim value [character]`

**Syntax:** `ltrim value [character]`

**Syntax:** `rtrim value [character]`

Removes characters from both ends, the left end, or the right end. By default, space, tab, carriage return, and line feed are removed. An explicit `character` must be a single byte and replaces the default whitespace set.

```nginx
var $trimmed trim "  value  ";  # value
var $left ltrim "  value  ";  # "value  "
var $right rtrim "  value  ";  # "  value"
var $unquoted trim xxvaluexx x;  # value
```

### reverse

**Syntax:** `reverse value`

Reverses the bytes of a string. Multibyte characters are not preserved.

```nginx
var $reversed reverse abcd;  # dcba
```

### position

**Syntax:** `position [-i] value substring`

Returns the 1-based byte position of the first occurrence, or `0` if absent. An empty substring matches at position `1`. `-i` ignores ASCII case.

```nginx
var $position position abcabc bc;  # 2
var $position_i position -i AbCd bC;  # 2
var $absent position abc z;  # 0
```

### repeat

**Syntax:** `repeat value count`

Repeats the string `count` times. `count` is a nonnegative decimal integer; `0` produces an empty value.

```nginx
var $repeated repeat ab 3;  # ababab
```

### substr

**Syntax:** `substr value start [length]`

Returns bytes starting at the 0-based `start` offset. If omitted, `length` extends to the end of the string. Both numbers must be nonnegative decimal integers. An excessive length is shortened to the remaining bytes; a start at or beyond the end produces an empty value.

```nginx
var $middle substr abcdef 2 3;  # cde
var $tail substr abcdef 2;  # cdef
```

### replace

**Syntax:** `replace [-i] value search replacement`

Replaces every non-overlapping literal match. `search` must not be empty. If no match exists, the input is returned unchanged. `-i` ignores ASCII case in the search.

```nginx
var $replaced replace "cat cat" cat dog;  # dog dog
var $replaced_i replace -i "One oNE one" one x;  # x x x
var $removed replace a-b-c - "";  # abc
```

### tr

**Syntax:** `tr value from to`

Translates each input byte using the corresponding positions in `from` and `to`. Both sets must have the same byte length. Repeated bytes in `from` use their last mapping. Unlisted bytes are unchanged.

The sets are literal: ranges, character classes, deletion, and `-i` are not supported. Unequal constant sets fail configuration validation; unequal sets produced by variables return an empty value.

```nginx
var $translated tr abca abc XYZ;  # XYZX

# Convert CloudFront signature encoding to standard Base64.
var $signature_base64 tr $arg_signature "-_~" "+=/";
var $signature_binary base64_decode $signature_base64;
```

## Parameter lists

These functions operate on literal name/value lists. `separator` separates entries and `delimiter` separates a name from its value. Each must be one byte. Values are not percent-decoded, and names are case-sensitive unless `-i` is used.

### extract_param

**Syntax:** `extract_param [-i] value separator delimiter name`

Returns the value of the first matching `name`, without surrounding spaces. The name must immediately precede the delimiter. A missing name or an entry without a delimiter produces an empty value.

```nginx
var $parameter extract_param "foo=1&bar= two &bar=three" "&" "=" bar;  # two
var $cookie extract_param -i "id=7; Token=abc" ";" "=" token;  # abc
var $token extract_param $args "&" "=" token;
```

### keep_params and remove_params

**Syntax:** `keep_params [-i] value separator delimiter name...`

**Syntax:** `remove_params [-i] value separator delimiter name...`

Keeps or removes every entry with a listed name. At least one name is required. The original order, duplicate entries, and contents of retained entries are preserved. Spaces around entry names are ignored for matching; entries without a delimiter are matched by their entire name.

Empty entries and entries with empty names are omitted. Invalid separator or delimiter lengths return the original input.

```nginx
var $kept keep_params "a=1&b=2&a=3&flag" "&" "=" a flag;  # a=1&a=3&flag
var $removed_params remove_params "a=1&b=2&c=3" "&" "=" b;  # a=1&c=3
var $unsigned_args remove_params $args "&" "=" signature expires;
```

## JSON

### extract_json

**Syntax:** `extract_json [-i] json path`

Extracts a value from a JSON document. Object names are case-sensitive unless `-i` is used. The path supports dotted object names, zero-based array indices, and quoted object names in brackets.

| Path | Selection |
| --- | --- |
| `user.name` | Nested object member |
| `users[1].name` | Member of the second array element |
| `[0].id` | Member of the first element of a root array |
| `["a.b"]["sp ace"]` | Object names containing dots or spaces |

Strings are returned without JSON quotes, with JSON escapes decoded. Numbers, booleans, and `null` are returned as JSON text. Objects and arrays are returned as compact JSON. Invalid JSON, an invalid path, or a missing value produces an empty result.

```nginx
var $name extract_json '{"users":[{"name":"Alice"},{"name":"Bob"}]}' users[1].name;  # Bob
var $quoted extract_json '{"a.b":{"sp ace":"value"}}' '["a.b"]["sp ace"]';  # value
var $object extract_json '{"user":{"name":"Bob","age":30}}' user;  # {"name":"Bob","age":30}
var $case_i extract_json -i '{"Name":"Alice"}' name;  # Alice
```

This function requires nginx 1.31.5 or later, or cJSON on earlier versions.

## Regular expressions

These functions require PCRE or PCRE2. Patterns are compiled when the configuration is loaded and cannot contain nginx variable references. The input and replacement support variables, including numbered captures such as `$1` and named captures from the pattern. `-i` enables case-insensitive matching.

Quote patterns containing spaces, braces, or semicolons. Backslashes in nginx configuration may need doubling, for example `"\\d+"`.

### regex_capture

**Syntax:** `regex_capture [-i] value pattern replacement`

Matches the input and returns the expanded replacement using captures from the first match. It returns an empty value if no match exists.

```nginx
var $order regex_capture order-123-widget "order-([0-9]+)-([a-z]+)" "$1-$2";  # 123-widget
var $name_capture regex_capture -i NAME=Alice "name=([a-z]+)" $1;  # Alice
```

### regex_sub

**Syntax:** `regex_sub [-i] value pattern replacement`

Replaces the first match. Unmatched input is returned unchanged.

```nginx
var $first regex_sub abc123def456 "[0-9]+" X;  # abcXdef456
var $first_capture regex_sub abc123def "([0-9]+)" "<$1>";  # abc<123>def
```

### regex_gsub

**Syntax:** `regex_gsub [-i] value pattern replacement`

Replaces all non-overlapping matches, expanding the replacement separately for each match. Unmatched input is returned unchanged. Zero-length matches are supported.

```nginx
var $all regex_gsub abc123def456 "[0-9]+" X;  # abcXdefX
var $captures regex_gsub a1b22 "(?<digits>[0-9]+)" "<$digits>";  # a<1>b<22>
var $deleted regex_gsub banana a "";  # bnn
```

## Numbers

Numeric input uses decimal notation, with an optional leading minus sign where signed values are accepted. Integer operations do not accept hexadecimal prefixes, fractional values, or exponent notation. Integer ranges follow the nginx platform's native integer size.

### abs

**Syntax:** `abs number`

Returns the absolute value of an integer or decimal number, preserving its textual representation apart from a leading minus sign.

```nginx
var $absolute abs -0012.50;  # 0012.50
```

### min and max

**Syntax:** `min number number`

**Syntax:** `max number number`

Compares two integers or decimal numbers and returns the selected argument with its original formatting. Equal values select the first argument. Decimal comparison is limited by the native integer range after scaling both values to the same number of fractional digits.

```nginx
var $minimum min -2.5 -1.25;  # -2.5
var $maximum max 2.50 10.0;  # 10.0
var $equal_max max 2.00 2;  # 2.00
```

### Integer arithmetic

| Syntax | Operation | Example result |
| --- | --- | --- |
| `add a b` | Addition | `add 7 -3` → `4` |
| `sub a b` | Subtraction | `sub -2 5` → `-7` |
| `mul a b` | Multiplication | `mul -6 -7` → `42` |
| `div a b` | Integer division, truncated toward zero | `div -7 3` → `-2` |
| `mod a b` | Remainder, with the dividend's sign | `mod -7 3` → `-1` |

Results are decimal integers. Division or remainder by zero produces an empty value. Addition, subtraction, and multiplication reject integer overflow.

```nginx
var $sum add 7 -3;  # 4
var $difference sub -2 5;  # -7
var $product mul -6 -7;  # 42
var $quotient div -7 3;  # -2
var $remainder mod -7 3;  # -1
```

### Bitwise operations

| Syntax | Operation |
| --- | --- |
| `bitwise_and a b` | Bitwise AND |
| `bitwise_not number` | Bitwise complement |
| `bitwise_or a b` | Bitwise OR |
| `bitwise_xor a b` | Bitwise XOR |

Arguments and results are signed decimal integers. The operations use the native integer width.

```nginx
var $bits_and bitwise_and 10 6;  # 2
var $bits_not bitwise_not 10;  # -11
var $bits_or bitwise_or 10 6;  # 14
var $bits_xor bitwise_xor 10 6;  # 12
```

### Bit shifts

| Syntax | Operation | Result format |
| --- | --- | --- |
| `lshift number bits` | Shift left | Signed decimal |
| `rshift number bits` | Shift right, preserving the sign bit | Signed decimal |
| `urshift number bits` | Shift right, filling with zero bits | Unsigned decimal |

`bits` must be a nonnegative integer smaller than the native integer width, normally 64 on a 64-bit build. Use values that remain representable when shifting left.

```nginx
var $shift_left lshift 3 4;  # 48
var $shift_right rshift -16 2;  # -4
var $shift_unsigned urshift 16 2;  # 4
```

### round

**Syntax:** `round number places`

Rounds to `places` fractional digits, padding with zeros when necessary. `places` must be a nonnegative decimal integer. Halfway values are rounded away from zero.

```nginx
var $rounded round 12.345 2;  # 12.35
var $rounded_negative round -12.345 2;  # -12.35
var $padded round 12 2;  # 12.00
```

### trunc, floor, and ceil

**Syntax:** `trunc number`

**Syntax:** `floor number`

**Syntax:** `ceil number`

`trunc` removes the fractional part toward zero. `floor` rounds down to an integer; `ceil` rounds up.

```nginx
var $truncated trunc -12.9;  # -12
var $floored floor -12.1;  # -13
var $ceiling ceil -12.9;  # -12
```

## Random values

Random values are retained for each definition within the request or Stream session. Use these functions for sampling and identifiers, not for cryptographic keys or IVs.

### rand

**Syntax:** `rand [end]`

**Syntax:** `rand start end`

Returns a random nonnegative decimal integer. With one argument, the inclusive range is `0` through `end`. With two arguments, it is `start` through `end`. Bounds must be nonnegative integers with `start <= end`. Without arguments, the function uses its default generator range.

```nginx
var $random rand;
var $bucket rand 99;  # 0 through 99
var $dice rand 1 6;  # 1 through 6
var $fixed rand 7 7;  # 7
```

### hexrand

**Syntax:** `hexrand [length]`

Returns `length` lowercase hexadecimal characters. The default length is `32`; supported lengths are `1` through `32`. The length counts output characters, not bytes before encoding.

```nginx
var $random_id hexrand;  # 32 hexadecimal characters
var $short_id hexrand 8;  # 8 hexadecimal characters
```

## Encoding

### hex_encode and hex_decode

**Syntax:** `hex_encode value`

**Syntax:** `hex_decode value`

`hex_encode` converts bytes to lowercase hexadecimal, with two characters per byte. `hex_decode` accepts uppercase or lowercase digits; odd lengths or invalid digits produce an empty value.

```nginx
var $hex hex_encode hello;  # 68656c6c6f
var $decoded_hex hex_decode 68656C6C6F;  # hello
```

### itohex and hextoi

**Syntax:** `itohex integer`

**Syntax:** `hextoi hexadecimal`

Converts between a decimal integer and its hexadecimal representation. A leading minus sign is preserved. Hexadecimal input has no `0x` prefix; hexadecimal output uses lowercase letters. These functions convert numbers, while `hex_encode` and `hex_decode` convert bytes.

```nginx
var $integer_hex itohex 255;  # ff
var $negative_hex itohex -255;  # -ff
var $integer_decimal hextoi FF;  # 255
var $negative_decimal hextoi -ff;  # -255
```

### Escaping

| Syntax | Escaping rule | Example |
| --- | --- | --- |
| `escape_uri value` | nginx URI escaping | `a&b/c?d` → `a&b/c%3Fd` |
| `escape_args value` | nginx argument escaping | `a&b/c?d` → `a%26b/c%3Fd` |
| `escape_uri_component value` | URI component escaping | `a&b/c?d` → `a%26b%2Fc%3Fd` |
| `escape_html value` | nginx `NGX_ESCAPE_HTML` escaping | `a'b` → `a%27b` |

Use `escape_uri_component` to escape a complete query parameter value. Escaped bytes are written as `%XX`. `escape_html` does not produce HTML entities such as `&lt;` or `&amp;`.

```nginx
var $uri_encoded escape_uri "a&b/c?d";  # a&b/c%3Fd
var $args_encoded escape_args "a&b/c?d";  # a%26b/c%3Fd
var $component_encoded escape_uri_component "a&b/c?d";  # a%26b%2Fc%3Fd
var $html_encoded escape_html "a'b";  # a%27b
```

### unescape_uri

**Syntax:** `unescape_uri value`

Decodes `%XX` escape sequences using nginx URI unescaping. `+` remains a literal plus sign. Decoding stops after a literal or decoded `?`, including that character in the result.

```nginx
var $uri_decoded unescape_uri a%20b%2Fc;  # a b/c
var $plus unescape_uri a+b;  # a+b
```

### Base64

| Syntax | Input | Output |
| --- | --- | --- |
| `base64_encode value` | Binary | Standard Base64, with `=` padding |
| `base64url_encode value` | Binary | URL-safe Base64, without padding |
| `base64_decode value` | Standard Base64 | Binary |
| `base64url_decode value` | URL-safe Base64 | Binary |

URL-safe Base64 uses `-` and `_` instead of `+` and `/`. Decoding uses nginx's Base64 decoder; a decoding failure produces an empty value.

```nginx
var $base64 base64_encode hello;  # aGVsbG8=
var $base64url base64url_encode hello;  # aGVsbG8
var $decoded_base64 base64_decode aGVsbG8=;  # hello
var $decoded_base64url base64url_decode aGVsbG8;  # hello
```

## Checksums and hashes

### crc32

**Syntax:** `crc32 value`

Returns the CRC32 checksum as eight lowercase hexadecimal digits.

```nginx
var $checksum crc32 123456789;  # cbf43926
```

### Message digests

All digest functions return lowercase hexadecimal text.

| Syntax | Output length | OpenSSL required |
| --- | --- | --- |
| `md5 value` | 32 characters | No |
| `sha1 value` | 40 characters | No |
| `sha224 value` | 56 characters | Yes |
| `sha256 value` | 64 characters | Yes |
| `sha384 value` | 96 characters | Yes |
| `sha512 value` | 128 characters | Yes |

```nginx
var $md5 md5 abc;  # 900150983cd24fb0d6963f7d28e17f72
var $sha1 sha1 abc;  # a9993e364706816aba3e25717850c26c9cd0d89d
var $sha224 sha224 abc;
var $sha256 sha256 abc;
var $sha384 sha384 abc;
var $sha512 sha512 abc;

# Convert a hexadecimal digest to Base64.
var $digest_bytes hex_decode $sha256;
var $digest_base64 base64_encode $digest_bytes;
```

### HMAC

HMAC functions take the message first and the secret key second. They require OpenSSL and return raw binary bytes.

| Syntax | Output length |
| --- | --- |
| `hmac_md5 value key` | 16 bytes |
| `hmac_sha1 value key` | 20 bytes |
| `hmac_sha224 value key` | 28 bytes |
| `hmac_sha256 value key` | 32 bytes |
| `hmac_sha384 value key` | 48 bytes |
| `hmac_sha512 value key` | 64 bytes |

```nginx
var $hmac_md5 hmac_md5 abc key;
var $hmac_sha1 hmac_sha1 abc key;
var $hmac_sha224 hmac_sha224 abc key;
var $hmac_sha256 hmac_sha256 abc key;
var $hmac_sha384 hmac_sha384 abc key;
var $hmac_sha512 hmac_sha512 abc key;

var $hmac_hex hex_encode $hmac_sha256;
# 9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab

var $hmac_token base64url_encode $hmac_sha256;
```

## Symmetric encryption

These functions require OpenSSL. Plaintext, ciphertext, keys, IVs, and additional authenticated data are binary strings. Decode hexadecimal or Base64 inputs with the [encoding functions](#encoding). Keys are used directly, without password derivation.

### aes_encrypt and aes_decrypt

**Syntax:** `aes_encrypt data key [cipher=name] [iv=value] [aad=value] [padding=pkcs7|none] [format=packed|raw]`

**Syntax:** `aes_decrypt data key [cipher=name] [iv=value] [aad=value] [padding=pkcs7|none] [format=packed|raw]`

Encrypts or decrypts data with the named AES cipher. `aes-128-*`, `aes-192-*`, and `aes-256-*` require a 16-, 24-, and 32-byte key, respectively. A mismatched key length is rejected. If `cipher=` is omitted, the key length selects `aes-128-gcm`, `aes-192-gcm`, or `aes-256-gcm`.

| Cipher | IV length | Authentication tag | Padding |
| --- | --- | --- | --- |
| `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm` | 12 bytes | 16 bytes | None |
| `aes-128-cbc`, `aes-192-cbc`, `aes-256-cbc` | 16 bytes | None | PKCS#7 by default |
| `aes-128-ctr`, `aes-192-ctr`, `aes-256-ctr` | 16 bytes | None | None |
| `aes-128-cfb`, `aes-192-cfb`, `aes-256-cfb` | 16 bytes | None | None; uses CFB128 |
| `aes-128-ofb`, `aes-192-ofb`, `aes-256-ofb` | 16 bytes | None | None |
| `aes-128-ecb`, `aes-192-ecb`, `aes-256-ecb` | None | None | PKCS#7 by default |

`cipher=` supports variables, such as `cipher=$selected_cipher`. Cipher names are case-insensitive.

`aad=` supplies additional authenticated data for GCM and is empty by default. Decryption requires the same AAD and verifies the authentication tag before returning plaintext. Other modes do not authenticate ciphertext. `padding=` applies only to CBC and ECB; `padding=none` requires a plaintext length divisible by 16.

AES-256-GCM encryption with a generated IV:

```nginx
# Example key; replace with your own key.
var $aes_key hex_decode 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;

var $aes_packet aes_encrypt $arg_message $aes_key cipher=aes-256-gcm aad=token-v1;
var $aes_token base64url_encode $aes_packet;

var $aes_input base64url_decode $arg_token;
var $aes_plaintext aes_decrypt $aes_input $aes_key cipher=aes-256-gcm aad=token-v1;
```

AES-256-CBC with an externally supplied 32-byte key, 16-byte IV, and raw ciphertext:

```nginx
var $cbc_key hex_decode $key_hex;
var $cbc_iv hex_decode $iv_hex;
var $cbc_ciphertext aes_encrypt $message $cbc_key cipher=aes-256-cbc iv=$cbc_iv format=raw;
var $cbc_plaintext aes_decrypt $cbc_ciphertext $cbc_key cipher=aes-256-cbc iv=$cbc_iv format=raw;
```

### chacha20_encrypt and chacha20_decrypt

**Syntax:** `chacha20_encrypt data key [iv=value] [aad=value] [format=packed|raw]`

**Syntax:** `chacha20_decrypt data key [iv=value] [aad=value] [format=packed|raw]`

Encrypts or decrypts using ChaCha20-Poly1305, with a 32-byte key, a 12-byte IV, and a 16-byte authentication tag. `aad=` is empty by default and must match during decryption. `cipher=` and `padding=` are not accepted.

```nginx
var $chacha_key hex_decode 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
var $chacha_packet chacha20_encrypt $arg_message $chacha_key aad=token-v1;
var $chacha_token base64url_encode $chacha_packet;
var $chacha_plaintext chacha20_decrypt $chacha_packet $chacha_key aad=token-v1;
```

### Cipher formats and results

`format=packed` is the default for both function families:

| Format | CBC, CTR, CFB, OFB | GCM, ChaCha20-Poly1305 |
| --- | --- | --- |
| `packed` | IV followed by ciphertext | IV followed by ciphertext and tag |
| `raw` | Ciphertext | Ciphertext followed by tag |

ECB returns only ciphertext in either format. Neither format includes the cipher name or key.

In `packed` format, encryption generates a cryptographically random IV unless `iv=` is supplied. Decryption reads the IV from the input and does not accept `iv=`. In `raw` format, `iv=` is required except for ECB, which does not accept an IV.

All argument values support variables. Encryption reuses its complete result only for the same definition and identical inputs within a request or Stream session. Each distinct set of inputs gets its own result and, when generated automatically, a fresh IV. Explicit IVs are used as supplied; GCM, CTR, and ChaCha20-Poly1305 require a unique IV for each distinct encryption under the same key.

Constant parameters are checked when the configuration is loaded. Invalid runtime parameters, failed authentication, other encryption or decryption failures, and empty plaintext produce an empty value.

## RSA

RSA functions require OpenSSL. Argument values support variables. Ciphertext and signatures are binary; encode them for transport and decode them before decryption or verification.

### RSA keys

The `key` argument accepts a PEM file path or `data:value`. Relative file paths are resolved against the nginx configuration prefix. Public keys use SubjectPublicKeyInfo format (`BEGIN PUBLIC KEY`); private keys use PKCS#8 or PKCS#1 PEM format. Use ordinary RSA keys; restricted RSA-PSS keys are not accepted.

```nginx
var $file_signature rsa_sign $message keys/private.pem;
var $inline_signature rsa_sign $message data:$private_key_pem;
var $inline_valid rsa_verify $message data:$public_key_pem $inline_signature;
```

`password=` unlocks an encrypted private key and applies only to `rsa_decrypt` and `rsa_sign`. Constant keys and passwords are loaded with the configuration. Variable keys and passwords are evaluated on each operation. Select key paths and verification keys from trusted configuration.

### rsa_encrypt and rsa_decrypt

**Syntax:** `rsa_encrypt data key [padding=oaep] [oaep_hash=name] [mgf1_hash=name] [label=value]`

**Syntax:** `rsa_decrypt data key [padding=oaep] [oaep_hash=name] [mgf1_hash=name] [label=value] [password=value]`

Encrypts with a public key or decrypts with a private key using RSA-OAEP. Returns binary ciphertext or plaintext. PKCS#1 v1.5 encryption is not supported.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `padding=` | `oaep` | Padding scheme; only OAEP is accepted |
| `oaep_hash=` | `sha256` | OAEP hash |
| `mgf1_hash=` | Same as `oaep_hash` | MGF1 hash |
| `label=` | Empty | Binary OAEP label |
| `password=` | Empty | Private key password, decryption only |

Supported hashes are `sha1`, `sha256`, `sha384`, and `sha512`. Decryption must use the same hashes and label as encryption. The maximum plaintext length is the RSA modulus length in bytes minus twice the OAEP hash length minus two: 190 bytes for a 2048-bit key with SHA-256.

```nginx
var $rsa_ciphertext rsa_encrypt $message /etc/nginx/keys/public.pem label=token-v1;
var $rsa_token base64url_encode $rsa_ciphertext;

var $rsa_input base64url_decode $arg_token;
var $rsa_plaintext rsa_decrypt $rsa_input /etc/nginx/keys/private.pem label=token-v1;
```

Use the same options on both operations when interoperating with an existing format:

```nginx
var $oaep_ciphertext rsa_encrypt $message data:$public_key_pem oaep_hash=sha256 mgf1_hash=sha1;
var $oaep_plaintext rsa_decrypt $oaep_ciphertext data:$private_key_pem oaep_hash=sha256 mgf1_hash=sha1 password=$key_password;
```

### rsa_sign

**Syntax:** `rsa_sign data key [padding=pss|pkcs1] [hash=name] [mgf1_hash=name] [salt_length=value] [password=value]`

Signs the original message with a private key and returns a binary signature. Do not pass a precomputed digest as `data`.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `padding=` | `pss` | RSA-PSS or PKCS#1 v1.5 signatures |
| `hash=` | `sha256` | Message hash |
| `mgf1_hash=` | Same as `hash` | MGF1 hash, PSS only |
| `salt_length=` | `digest` | PSS salt length in bytes; `digest` uses the hash length |
| `password=` | Empty | Private key password |

Hashes are `sha1`, `sha256`, `sha384`, or `sha512`. PSS salt length may be `digest` or a nonnegative integer. `padding=pkcs1` does not accept `mgf1_hash=` or `salt_length=`.

```nginx
var $pss_signature rsa_sign $message /etc/nginx/keys/private.pem;
var $pss_token base64url_encode $pss_signature;

var $pkcs1_signature rsa_sign $message data:$private_key_pem padding=pkcs1 hash=sha256;
```

### rsa_verify

**Syntax:** `rsa_verify data key signature [padding=pss|pkcs1] [hash=name] [mgf1_hash=name] [salt_length=value]`

Verifies a binary signature with a public key. Returns `1` on success and `0` on failure, including invalid runtime keys, parameters, or signatures. `data` is the original message.

Defaults and parameters match `rsa_sign`, except that `password=` is unavailable and PSS verification also accepts `salt_length=auto` to detect the signature's salt length.

```nginx
var $received_signature base64url_decode $arg_signature;
var $signature_valid rsa_verify $message /etc/nginx/keys/public.pem $received_signature;

var $pkcs1_valid rsa_verify $message data:$public_key_pem $pkcs1_signature padding=pkcs1 hash=sha256;
var $pss_auto_valid rsa_verify $message data:$public_key_pem $received_signature salt_length=auto;
```

### RSA results

Constant keys and parameters are validated when the configuration is loaded. Encryption, decryption, and signing failures produce an empty value; verification failures produce `0`.

Encryption and signing reuse a result within the request or Stream session only when the definition, message, actual key material, and all parameters are unchanged. Decryption and verification results are recalculated.

## Time

Timestamps are Unix time in seconds. Formatting uses the system `strftime()` conventions; parsing uses `strptime()`. See [strftime(3)](https://man7.org/linux/man-pages/man3/strftime.3.html) and [strptime(3)](https://man7.org/linux/man-pages/man3/strptime.3.html) for format specifiers and platform extensions.

| Format | Meaning |
| --- | --- |
| `%Y-%m-%d` | Year, month, and day, such as `2021-01-01` |
| `%H:%M:%S` | 24-hour time, such as `00:00:00` |
| `%Y%m%d%H%M%S` | Compact numeric date and time |
| `%%` | Literal percent sign |

### gmt_time

**Syntax:** `gmt_time [timestamp] format`

Formats a nonnegative timestamp in GMT/UTC. Omitting the timestamp uses the current time. `http_time` and `cookie_time` select nginx's HTTP and cookie date formats. A format of exactly `%s` returns the timestamp itself.

```nginx
var $http_date gmt_time 1609459200 http_time;  # Fri, 01 Jan 2021 00:00:00 GMT
var $cookie_date gmt_time 1609459200 cookie_time;  # Fri, 01-Jan-21 00:00:00 GMT
var $iso_date gmt_time 1609459200 "%Y-%m-%dT%H:%M:%SZ";  # 2021-01-01T00:00:00Z
var $current_date gmt_time "%Y%m%d%H%M%S";
```

### local_time

**Syntax:** `local_time [timestamp] format`

Formats a nonnegative timestamp in the nginx process's local timezone. Omitting the timestamp uses the current time. A format of exactly `%s` returns the timestamp itself. The `http_time` and `cookie_time` shortcuts belong to `gmt_time` only.

```nginx
var $local_date local_time 1609459200 "%Y-%m-%d %H:%M:%S";
var $local_now local_time "%Y-%m-%d %H:%M:%S";
var $local_epoch local_time 1609459200 "%s";  # 1609459200
```

### unix_time

**Syntax:** `unix_time`

**Syntax:** `unix_time value format [timezone]`

Without arguments, returns the current Unix timestamp. Otherwise, parses the input using `format`. `http_time` uses nginx's HTTP date parser; custom formats use GMT by default.

For a custom format, `timezone` accepts `GMT`, `GMT+HHMM`, or `GMT-HHMM`. The offset is applied to the parsed date. Use this parameter to specify the source timezone. The `http_time` form does not use it.

```nginx
var $now unix_time;
var $http_timestamp unix_time "Fri, 01 Jan 2021 00:00:00 GMT" http_time;  # 1609459200
var $timestamp unix_time "2021-01-01 00:00:00" "%Y-%m-%d %H:%M:%S";  # 1609459200
var $offset_timestamp unix_time "2021-01-01 08:00:00" "%Y-%m-%d %H:%M:%S" GMT+0800;  # 1609459200
```

## IP addresses

### cidr

**Syntax:** `cidr address ipv4_bits [ipv6_bits]`

Returns the network address after applying the prefix length, without a `/prefix` suffix. IPv4 lengths are `1` through `32`; IPv6 lengths are `1` through `128`. If omitted, `ipv6_bits` uses the value of `ipv4_bits`. The IPv4 argument must remain valid even when the input is IPv6.

IPv4-mapped IPv6 addresses use the IPv4 prefix and return IPv4 notation. IPv6 support requires an nginx build with IPv6 enabled. Invalid addresses or prefix lengths produce an empty value.

```nginx
var $ipv4_network cidr 192.168.12.34 24;  # 192.168.12.0
var $ipv6_network cidr 2001:db8:1234:5678::1 24 64;  # 2001:db8:1234:5678::
var $mapped_network cidr ::ffff:192.168.12.34 24;  # 192.168.12.0
var $client_network cidr $remote_addr 24 64;
```

## Testing

The test suite uses the nginx-tests framework. Cipher and RSA tests additionally require Python 3 and the `cryptography` package (`python3-cryptography` on Debian and Ubuntu).

```sh
TEST_NGINX_BINARY=/path/to/nginx \
    prove -I /path/to/nginx-tests/lib t
```

Run with a binary built with `ngx_expr_module` for named condition tests, and with a binary built without it for legacy `if=` tests. Tests whose required modules are unavailable are skipped.

## Author

Hanada <im@hanada.info>

## License

[BSD 2-Clause License](LICENSE).
