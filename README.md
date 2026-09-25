# Name

This repository provides `ngx_http_var_module` and `ngx_stream_var_module`.
Both modules dynamically assign new variables through predefined functions.

# Table of Content

- [Name](#name)
- [Table of Content](#table-of-content)
- [Status](#status)
- [Synopsis](#synopsis)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Build Module](#build-module)
- [Conditional syntax](#conditional-syntax)
- [Directives](#directives)
  - [var](#var)
- [Testing](#testing)
- [Author](#author)
- [License](#license)

# Status

This Nginx module is currently considered experimental. Issues and PRs are welcome if you encounter any problems.

> The condition variable definition operator has been removed. Please migrate to ngx_expr_module.
> ```nginx
> # before
> var $bool_var str_eq $uri /abc;   # deprecated
> # after:
> condition uri_is_abc str_eq $uri /abc;
> when uri_is_abc {
>     var $new_var set 1;
> }
> var $new_var set 0;
> ```


# Synopsis

HTTP:

```nginx
server {
    listen 127.0.0.1:8080;
    server_name localhost;

    location / {
        var $new_var set $scheme://$host$request_uri;
    }
}
```

Stream:

```nginx
stream {
    server {
        listen 127.0.0.1:8081;
        var $new_var set $remote_addr:$remote_port;
        return $new_var;
    }
}
```

# Installation

## Prerequisites

The following optional build dependencies control whether their corresponding
`var` functions are registered:

| Dependency | Required by `var` functions |
| --- | --- |
| OpenSSL (`NGX_OPENSSL`) | `sha224`, `sha256`, `sha384`, `sha512`, `hmac_md5`, `hmac_sha1`, `hmac_sha224`, `hmac_sha256`, `hmac_sha384`, `hmac_sha512` |
| PCRE/PCRE2 (`NGX_PCRE`) | `regex_capture`, `regex_sub`, `regex_gsub` |
| cJSON (`NGX_CJSON`) | `extract_json` with nginx versions earlier than 1.31.5 |

If a dependency is unavailable, its functions are not registered and
nginx configuration validation fails when one of them is used. Enable OpenSSL
support with an nginx SSL module such as `--with-http_ssl_module` or
`--with-stream_ssl_module`. PCRE/PCRE2 is normally enabled by the default nginx
build; do not configure nginx with `--without-pcre` when the regex functions
are required.

The `crc32`, `md5`, and `sha1` functions use nginx core implementations and do
not require OpenSSL. The `rand` and `hexrand` functions also remain available
without OpenSSL and use their fallback random generator when necessary.

With nginx 1.31.5 and later, `extract_json` uses the nginx core JSON parser and
does not require cJSON. With earlier nginx versions, install cJSON before
configuring nginx when `extract_json` is required:

**Debian/Ubuntu:**
```bash
sudo apt-get install libcjson-dev
```

**CentOS/RHEL:**
```bash
sudo yum install cjson-devel
```

**macOS:**
```bash
brew install cjson
```

**Build from source:**
```bash
git clone https://github.com/DaveGamble/cJSON.git
cd cJSON
mkdir build && cd build
cmake ..
make
sudo make install
```

After installing or upgrading cJSON, rerun the nginx `configure` script so the
module can detect it.

## Build Module

Configure nginx with this repository as an additional module. Enable Stream to
build both modules:

```bash
./configure --with-stream --add-module=/path/to/ngx_http_var_module
```

Without `--with-stream`, only `ngx_http_var_module` is built. With Stream
enabled, the same build also includes `ngx_stream_var_module`.

To enable named conditions, build `ngx_expr_module` and this module statically in the same nginx configuration.

# Conditional syntax

Conditional syntax is selected at compile time:

- With `ngx_expr_module`, use named `expr` expressions and place `var` inside an HTTP or Stream `when` block at a context supported by the corresponding module. `if=` and `if!=` parameters are rejected.
- Without `ngx_expr_module`, `when` is unavailable and legacy `if=`/`if!=` parameters remain supported. `if=` matches a non-empty value other than `"0"`; `if!=` matches an empty value or `"0"`.

If a condition does not match, the definition is skipped and the next definition of the same variable is evaluated.

# Directives

## var

**Syntax:** *var $new_variable function [-i] args...;*

**Default:** *-*

**HTTP context:** *http, server, location, http when, server when, location when*

**Stream context:** *stream, server, stream when, server when*

Define a new variable whose value is the result of function calculation. The variable value cannot be cached and is recalculated each time it is used.

If the current level does not define a variable with the same variable name, it can be inherited from the previous level.

The `-i` parameter is used to ignore case (Available only in some functions).

Except for the function name, the `-i` parameter, and the regular expression, all parameters are allowed to contain variables.

When the value of a parameter is invalid, the variable's value is empty.

`var` cannot be used to define the same variable simultaneously with the `map` or `geo` directives. However, the `set` directive can be used to override variables defined by `var`.

The following functions are available:

```nginx
#### General String Operations ####
# Set the value directly of the variable
var $new_var set src_str;

# Length of the string
var $new_var len src_str;

# Read up to the first 1024 bytes of a file
# Relative paths are resolved against the nginx prefix
# Missing files and directories produce an empty result
var $new_var file path;

# Convert to uppercase
var $new_var upper src_str;

# Convert to lowercase
var $new_var lower src_str;

# Capitalize the first letter of each word (words are separated by non-alphanumeric characters)
var $new_var initcap src_str;

# Trim leading and trailing whitespace characters or other characters
var $new_var trim src_str [char];

# Trim leading whitespace characters or other characters
var $new_var ltrim src_str [char];

# Trim trailing whitespace characters or other characters
var $new_var rtrim src_str [char];

# Reverse the string
var $new_var reverse src_str;

# Get starting position of substring
var $new_var position [-i] src_str sub_str;

# Repeat the string a given number of times
var $new_var repeat src_str times;

# Extract substring
var $new_var substr src_str start [len];

# Replace keyword
var $new_var replace [-i] src_str src dst;

# Extract parameters
# Extract a value from a list of parameters. A use case for this is to extract query parameters without having to write a regular expression, but it can be used to look up values in any name/value pair list. If several occurrences of the parameter exist, only the first one is returned. the variable gets a blank value. The separator and delimiter must be explicitly specified as single characters.
var $new_var extract_param [-i] src_string separator delimiter param_name;

# example: a query "foo=123&bar=456&baz=789". If the parameter name is bar, the Separator is &, and the delimiter is =, then the resulting variable value will be 456.
# var $extraed_arg_bar extract_param "foo=123&bar=456&baz=789" & = bar;

# Keep parameters
# Keep only the specified parameters from a name/value pair list. All other parameters are removed. The separator and delimiter must be explicitly specified as single characters.
var $new_var keep_params [-i] src_string separator delimiter <key1> <key2> ...;

# example: a query "foo=123&bar=456&baz=789". If we keep "foo" and "baz", the result will be "foo=123&baz=789".
# var $kept keep_params "foo=123&bar=456&baz=789" & = foo baz;

# Remove parameters
# Remove the specified parameters from a name/value pair list. All other parameters are retained. The separator and delimiter must be explicitly specified as single characters.
var $new_var remove_params [-i] src_string separator delimiter <key1> <key2> ...;

# example: a query "foo=123&bar=456&baz=789". If we remove "bar", the result will be "foo=123&baz=789".
# var $removed remove_params "foo=123&bar=456&baz=789" & = bar;

#### JSON operation ####
# Extract json value from a valid json string
# Object keys are case-sensitive by default; use -i to ignore case
var $new_var extract_json [-i] json path;

# The path syntax matches nginx json_set:
# - write paths relative to the JSON root, without a leading $
# - separate object keys with a dot
# - use [n] for an array index
# - use ["key"] for an object key that requires quoting
# Returns string values without quotes, other types as JSON strings
# Arrays and objects are returned as compact JSON strings

# Examples:
# Extract from nested object
# var $new_var extract_json '{"a":{"b":{"c":3}}}' a.b.c;
# Result: 3

# Extract from array using [index]
# var $new_var extract_json '{"users":[{"name":"Alice"},{"name":"Bob"}]}' users[0].name;
# Result: Alice

# Extract a key containing path syntax characters
# var $new_var extract_json '{"a.b":{"name":"Alice"}}' '["a.b"].name';
# Result: Alice

# Extract array as JSON string
# var $items extract_json '{"data":[1,2,3]}' data;
# Result: [1,2,3]

# Extract object as JSON string
# var $user extract_json '{"user":{"name":"Bob","age":30}}' user;
# Result: {"name":"Bob","age":30}


#### Regex Operations ####
# Capture regex (requires PCRE/PCRE2)
var $new_var regex_capture [-i] src_str regex assign_value;

# Substitute regex (requires PCRE/PCRE2)
var $new_var regex_sub [-i] src_str regex replacement;

# Globally substitute regex (requires PCRE/PCRE2)
var $new_var regex_gsub [-i] src_str regex replacement;


### Mathematical Operations ####
# Absolute value (returns original format without negative sign)
var $new_var abs num;

# Maximum value (returns with original format)
var $new_var max num1 num2;

# Minimum value (returns with original format)
var $new_var min num1 num2;

# Integer addition
var $new_var add int1 int2;

# Integer subtraction
var $new_var sub int1 int2;

# Integer multiplication
var $new_var mul int1 int2;

# Integer division, int2 cannot be 0
var $new_var div int1 int2;

# Integer modulus, int2 cannot be 0
var $new_var mod int1 int2;

# Bitwise AND operation
var $new_var bitwise_and int1 int2;

# Bitwise NOT operation
var $new_var bitwise_not int;

# Bitwise OR operation
var $new_var bitwise_or int1 int2;

# Bitwise XOR operation (exclusive or)
var $new_var bitwise_xor int1 int2;

# Left shift operation, shift_bits must be >= 0
var $new_var lshift int shift_bits;

# Right shift operation (arithmetic shift, sign bit preserved), shift_bits must be >= 0
var $new_var rshift int shift_bits;

# Unsigned right shift operation (logical shift, zero fill), shift_bits must be >= 0
var $new_var urshift int shift_bits;

# Round to n significant digits
var $new_var round src_num int;

# Truncate decimal part directly (no rounding)
var $new_var trunc src_num;

# Floor value, the largest integer less than or equal to the source
var $new_var floor src_num;

# Ceiling value, the smallest integer greater than or equal to the source
var $new_var ceil src_num;

# Random positive integer, the range is [start_int, end_int], if end_int is not specified, the range is [0, start_int]
var $new_var rand [start_int] [end_int];

# Random hex sequence in specified. number_of_bytes must be 1-32, default is 32
var $new_var hexrand [number_of_bytes];

# On nginx 1.31.3 and later, rand and hexrand use the SipHash-based generator.
# Older nginx versions retain the legacy generator.
# Each generated value is cached for the current request or session, so repeated
# evaluations of the same rule return the same value.
# These operators are intended for non-security identifiers, not secrets.


#### Encoding and Decoding ####
# Convert binary to hexadecimal
var $new_var hex_encode src_str;

# Convert hexadecimal to binary
var $new_var hex_decode src_str;

# Decimal to hexadecimal
var $new_var itohex int;

# Hexadecimal to decimal
var $new_var hextoi hex;

# Full URI encoding
var $new_var escape_uri src_str;

# Argument encoding
var $new_var escape_args src_str;

# URI component encoding
var $new_var escape_uri_component src_str;

# HTML encoding
var $new_var escape_html src_str;

# URI decoding
var $new_var unescape_uri src_str;

# Base64 encoding
var $new_var base64_encode src_str;

# Base64url encoding
var $new_var base64url_encode src_str;

# Base64 decoding
var $new_var base64_decode src_str;

# Base64url decoding
var $new_var base64url_decode src_str;


#### Cryptographic Hash Calculations ####
# CRC32
var $new_var crc32 src_str;

# MD5
var $new_var md5 src_str;

# SHA1
var $new_var sha1 src_str;

# SHA224 (requires OpenSSL)
var $new_var sha224 src_str;

# SHA256 (requires OpenSSL)
var $new_var sha256 src_str;

# SHA384 (requires OpenSSL)
var $new_var sha384 src_str;

# SHA512 (requires OpenSSL)
var $new_var sha512 src_str;

# HMAC_MD5 encryption (requires OpenSSL)
var $new_var hmac_md5 src_str secret;

# HMAC_SHA1 encryption (requires OpenSSL)
var $new_var hmac_sha1 src_str secret;

# HMAC_SHA224 encryption (requires OpenSSL)
var $new_var hmac_sha224 src_str secret;

# HMAC_SHA256 encryption (requires OpenSSL)
var $new_var hmac_sha256 src_str secret;

# HMAC_SHA384 encryption (requires OpenSSL)
var $new_var hmac_sha384 src_str secret;

# HMAC_SHA512 encryption (requires OpenSSL)
var $new_var hmac_sha512 src_str secret;

#### Time Format ####
# Convert timestamp to HTTP time (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] http_time;

# Convert timestamp to cookie time (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] cookie_time;

# Convert timestamp to GMT time in specified format (current time if timestamp is omitted)
var $new_var gmt_time [src_ts] date_format;

# Convert timestamp to local time in specified format (current time if timestamp is omitted)
var $new_var local_time [src_ts] date_format;

# Return current timestamp
var $new_var unix_time;

# Convert HTTP time to timestamp
var $new_var unix_time src_time http_time;

# Convert specified date to timestamp (return current timestamp if all are omitted)
var $new_var unix_time src_time date_format [timezone];


#### IP ####
# Calculate the network address based on IP address and network bits
# For IPv4: network_bits range is 1-32
# For IPv6: network_bits range is 1-128
# If ipv6_network_bits is not specified, it will use the same value as ipv4_network_bits
# Returns only the network address without the prefix length (e.g., "10.0.0.0" not "10.0.0.0/8")
var $new_var cidr ipv4/ipv6 ipv4_network_bits [ipv6_network_bits];
```

All parameters except regular expressions can contain variables. However, incorrect parameter values will cause the function calculation result to be empty.

Variables defined with the `var` directive can be overwritten by HTTP or Stream directives that assign the same variable.

With `ngx_expr_module`, conditional definitions use `when`. Multiple names in one `when` block are combined with AND, and a condition name can be negated with a `!` prefix:

```nginx
expr has_header_a !is_empty $http_a;
expr has_header_b !is_empty $http_b;

# When request header A is present, the value of the variable is 'have-header-a'
when has_header_a {
    var $new_var set have-header-a;
}

# When request header A is not present but request header B is present, the value of the variable is 'have-header-b'
when !has_header_a has_header_b {
    var $new_var set have-header-b;
}

# When both request header A and B are not present, the value of the variable is 'not-have-a-or-b'
var $new_var set not-have-a-or-b;
```

Without `ngx_expr_module`, express the same chain with legacy `if=`/`if!=` parameters.

The same conditional model is available in Stream. For example:

```nginx
expr has_sni !is_empty $ssl_preread_server_name;
expr is_example str_eq -i $ssl_preread_server_name example.com;

when has_sni is_example {
    var $new_var set example-sni;
}

when !has_sni {
    var $new_var set no-sni;
}

var $new_var set other-sni;
```

# Testing

The test suite uses the nginx-tests framework. Run the legacy condition tests
with an nginx binary built without `ngx_expr_module`:

```bash
TEST_NGINX_BINARY=/path/to/nginx \
    prove -I /path/to/nginx-tests/lib t
```

Run the named condition tests with an nginx binary that includes both this
module and `ngx_expr_module`:

```bash
TEST_NGINX_BINARY=/path/to/nginx-with-condition \
    prove -I /path/to/nginx-tests/lib t
```

# Author

Hanada im@hanada.info

# License

This Nginx module is licensed under [BSD 2-Clause License](LICENSE).
