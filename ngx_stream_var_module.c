
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_md5.h>
#include <ngx_sha1.h>

#if (NGX_CONDITION)
#include <ngx_stream_condition_module.h>
#endif

#if (NGX_STREAM_SSL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

#if (NGX_CJSON)
#include <cjson/cJSON.h>
#endif


#define ngx_stream_var_isspace(c)                                            \
    ((c) == ' ' || (c) == '\t' || (c) == CR || (c) == LF)


typedef enum {
    NGX_STREAM_VAR_OP_SET = 0,
    NGX_STREAM_VAR_OP_LEN,
    NGX_STREAM_VAR_OP_UPPER,
    NGX_STREAM_VAR_OP_LOWER,
    NGX_STREAM_VAR_OP_INITCAP,
    NGX_STREAM_VAR_OP_TRIM,
    NGX_STREAM_VAR_OP_LTRIM,
    NGX_STREAM_VAR_OP_RTRIM,
    NGX_STREAM_VAR_OP_REVERSE,
    NGX_STREAM_VAR_OP_POSITION,
    NGX_STREAM_VAR_OP_REPEAT,
    NGX_STREAM_VAR_OP_SUBSTR,
    NGX_STREAM_VAR_OP_REPLACE,
    NGX_STREAM_VAR_OP_EXTRACT_PARAM,
    NGX_STREAM_VAR_OP_KEEP_PARAMS,
    NGX_STREAM_VAR_OP_REMOVE_PARAMS,

#if (NGX_CJSON)
    NGX_STREAM_VAR_OP_EXTRACT_JSON,
#endif

#if (NGX_PCRE)
    NGX_STREAM_VAR_OP_REGEX_CAPTURE,
    NGX_STREAM_VAR_OP_REGEX_SUB,
#endif

    NGX_STREAM_VAR_OP_ABS,
    NGX_STREAM_VAR_OP_MAX,
    NGX_STREAM_VAR_OP_MIN,
    NGX_STREAM_VAR_OP_ADD,
    NGX_STREAM_VAR_OP_SUB,
    NGX_STREAM_VAR_OP_MUL,
    NGX_STREAM_VAR_OP_DIV,
    NGX_STREAM_VAR_OP_MOD,
    NGX_STREAM_VAR_OP_BITWISE_AND,
    NGX_STREAM_VAR_OP_BITWISE_NOT,
    NGX_STREAM_VAR_OP_BITWISE_OR,
    NGX_STREAM_VAR_OP_BITWISE_XOR,
    NGX_STREAM_VAR_OP_LSHIFT,
    NGX_STREAM_VAR_OP_RSHIFT,
    NGX_STREAM_VAR_OP_URSHIFT,
    NGX_STREAM_VAR_OP_ROUND,
    NGX_STREAM_VAR_OP_INT,
    NGX_STREAM_VAR_OP_FLOOR,
    NGX_STREAM_VAR_OP_CEIL,
    NGX_STREAM_VAR_OP_RAND,
    NGX_STREAM_VAR_OP_HEXRAND,

    NGX_STREAM_VAR_OP_HEX_ENCODE,
    NGX_STREAM_VAR_OP_HEX_DECODE,
    NGX_STREAM_VAR_OP_DEC_TO_HEX,
    NGX_STREAM_VAR_OP_HEX_TO_DEC,
    NGX_STREAM_VAR_OP_ESCAPE_URI,
    NGX_STREAM_VAR_OP_ESCAPE_ARGS,
    NGX_STREAM_VAR_OP_ESCAPE_URI_COMPONENT,
    NGX_STREAM_VAR_OP_ESCAPE_HTML,
    NGX_STREAM_VAR_OP_UNESCAPE_URI,
    NGX_STREAM_VAR_OP_BASE64_ENCODE,
    NGX_STREAM_VAR_OP_BASE64URL_ENCODE,
    NGX_STREAM_VAR_OP_BASE64_DECODE,
    NGX_STREAM_VAR_OP_BASE64URL_DECODE,

    NGX_STREAM_VAR_OP_CRC32,
    NGX_STREAM_VAR_OP_MD5,
    NGX_STREAM_VAR_OP_SHA1,

#if (NGX_STREAM_SSL)
    NGX_STREAM_VAR_OP_SHA224,
    NGX_STREAM_VAR_OP_SHA256,
    NGX_STREAM_VAR_OP_SHA384,
    NGX_STREAM_VAR_OP_SHA512,

    NGX_STREAM_VAR_OP_HMAC_MD5,
    NGX_STREAM_VAR_OP_HMAC_SHA1,
    NGX_STREAM_VAR_OP_HMAC_SHA224,
    NGX_STREAM_VAR_OP_HMAC_SHA256,
    NGX_STREAM_VAR_OP_HMAC_SHA384,
    NGX_STREAM_VAR_OP_HMAC_SHA512,
#endif

    NGX_STREAM_VAR_OP_GMT_TIME,
    NGX_STREAM_VAR_OP_LOCAL_TIME,
    NGX_STREAM_VAR_OP_UNIX_TIME,
    NGX_STREAM_VAR_OP_CIDR,

    NGX_STREAM_VAR_OP_UNKNOWN
} ngx_stream_var_operator_e;


typedef struct {
    ngx_array_t                   *vars;
} ngx_stream_var_conf_t;


typedef struct {
    ngx_stream_var_operator_e      operator;    /* operator type */
    ngx_uint_t                     ignore_case; /* ignore case sensitivity */
    ngx_array_t                   *args;        /* operator extra args */
#if (NGX_CONDITION)
    ngx_condition_expr_id_t        expr_id;     /* associated expression */
#else
    ngx_stream_complex_value_t    *filter;      /* filter complex value */
    ngx_uint_t                     negative;    /* negative filter */
#endif

#if (NGX_PCRE)
    ngx_stream_regex_t            *regex;       /* compiled regex */
#endif
} ngx_stream_var_rule_t;


typedef struct {
    ngx_str_t                      name;        /* variable name */
    ngx_int_t                      index;       /* variable index */
    ngx_array_t                   *rules;       /* variable rules */
} ngx_stream_var_variable_t;


typedef struct {
    ngx_stream_var_rule_t         *rule;
    ngx_str_t                      value;
} ngx_stream_var_random_value_t;


typedef struct {
    ngx_uint_t                    *locked_vars;
    ngx_array_t                   *random_values;
} ngx_stream_var_ctx_t;


typedef struct {
    ngx_str_t                      name;        /* operator string */
    ngx_stream_var_operator_e      op;          /* operator enum */
    ngx_uint_t                     min_args;    /* min number of arguments */
    ngx_uint_t                     max_args;    /* max number of arguments */
} ngx_stream_var_operator_enum_t;


static void *ngx_stream_var_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_var_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_stream_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_stream_var_ctx_t *ngx_stream_var_get_ctx(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_variable_acquire_lock(ngx_stream_session_t *s,
    ngx_int_t index);
static void ngx_stream_variable_release_lock(ngx_stream_session_t *s,
    ngx_int_t index);
static ngx_int_t ngx_stream_var_get_cached_random(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_cache_random(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_find_rule(ngx_stream_session_t *s,
    ngx_stream_var_variable_t *var, ngx_stream_var_rule_t **rule);
static ngx_int_t ngx_stream_var_evaluate_rule(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_variable_handler(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_stream_var_utils_check_str_is_num(ngx_str_t num_str);
static ngx_int_t ngx_stream_var_utils_auto_atoi(ngx_str_t val,
    ngx_int_t *int_val);
static ngx_int_t ngx_stream_var_utils_auto_atofp(ngx_str_t val1,
    ngx_str_t val2, ngx_int_t *int_val1, ngx_int_t *int_val2);
static ngx_int_t ngx_stream_var_utils_escape_uri(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule,
    ngx_uint_t type);
static u_char *ngx_stream_var_utils_strlstrn(u_char *s1, u_char *last,
    u_char *s2, size_t n);
static ngx_int_t ngx_stream_var_utils_filter_params(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule,
    ngx_uint_t keep);

#if (NGX_STREAM_SSL)
static ngx_int_t ngx_stream_var_utils_sha(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule,
    const EVP_MD *evp_md, size_t len);
static ngx_int_t ngx_stream_var_utils_hmac(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule,
    const EVP_MD *evp_md);
#endif


static ngx_int_t ngx_stream_var_exec_set(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_len(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_upper(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_lower(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_initcap(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_trim(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_ltrim(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_rtrim(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_reverse(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_position(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_repeat(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_substr(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_replace(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_extract_param(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_keep_params(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_remove_params(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);

#if (NGX_CJSON)
static ngx_int_t ngx_stream_var_exec_extract_json(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
#endif

#if (NGX_PCRE)
static ngx_int_t ngx_stream_var_exec_regex_capture(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_regex_sub(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
#endif


static ngx_int_t ngx_stream_var_exec_abs(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_max(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_min(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_add(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_sub(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_mul(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_div(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_mod(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_bitwise_and(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_bitwise_not(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_bitwise_or(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_bitwise_xor(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_lshift(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_rshift(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_urshift(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_round(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_int(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_floor(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_ceil(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_rand(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_hexrand(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);

static ngx_int_t ngx_stream_var_exec_hex_encode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_hex_decode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_dec_to_hex(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_hex_to_dec(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_escape_uri(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_escape_args(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_escape_uri_component(
    ngx_stream_session_t *s, ngx_stream_variable_value_t *v,
    ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_escape_html(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_unescape_uri(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_base64_encode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_base64url_encode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_base64_decode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_base64url_decode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);

static ngx_int_t ngx_stream_var_exec_crc32(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_md5(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_sha1(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);

#if (NGX_STREAM_SSL)
static ngx_int_t ngx_stream_var_exec_sha224(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_sha256(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_sha384(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_sha512(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_hmac_md5(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_hmac_sha1(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_hmac_sha224(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_hmac_sha256(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_hmac_sha384(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_hmac_sha512(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
#endif

static ngx_int_t ngx_stream_var_exec_gmt_time(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_local_time(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);
static ngx_int_t ngx_stream_var_exec_unix_time(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);

static ngx_int_t ngx_stream_var_exec_cidr(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule);


static ngx_stream_var_operator_enum_t  ngx_stream_var_operators[] = {
    { ngx_string("set"),              NGX_STREAM_VAR_OP_SET,           1, 1  },
    { ngx_string("len"),              NGX_STREAM_VAR_OP_LEN,           1, 1  },
    { ngx_string("upper"),            NGX_STREAM_VAR_OP_UPPER,         1, 1  },
    { ngx_string("lower"),            NGX_STREAM_VAR_OP_LOWER,         1, 1  },
    { ngx_string("initcap"),          NGX_STREAM_VAR_OP_INITCAP,       1, 1  },
    { ngx_string("trim"),             NGX_STREAM_VAR_OP_TRIM,          1, 2  },
    { ngx_string("ltrim"),            NGX_STREAM_VAR_OP_LTRIM,         1, 2  },
    { ngx_string("rtrim"),            NGX_STREAM_VAR_OP_RTRIM,         1, 2  },
    { ngx_string("reverse"),          NGX_STREAM_VAR_OP_REVERSE,       1, 1  },
    { ngx_string("position"),         NGX_STREAM_VAR_OP_POSITION,      2, 2  },
    { ngx_string("repeat"),           NGX_STREAM_VAR_OP_REPEAT,        2, 2  },
    { ngx_string("substr"),           NGX_STREAM_VAR_OP_SUBSTR,        2, 3  },
    { ngx_string("replace"),          NGX_STREAM_VAR_OP_REPLACE,       3, 3  },
    { ngx_string("extract_param"),    NGX_STREAM_VAR_OP_EXTRACT_PARAM, 4, 4  },
    { ngx_string("keep_params"),      NGX_STREAM_VAR_OP_KEEP_PARAMS,   4, 99 },
    { ngx_string("remove_params"),    NGX_STREAM_VAR_OP_REMOVE_PARAMS, 4, 99 },

#if (NGX_CJSON)
    { ngx_string("extract_json"),     NGX_STREAM_VAR_OP_EXTRACT_JSON,  2, 99 },
#endif

#if (NGX_PCRE)
    { ngx_string("regex_capture"),    NGX_STREAM_VAR_OP_REGEX_CAPTURE, 3, 3  },
    { ngx_string("regex_sub"),        NGX_STREAM_VAR_OP_REGEX_SUB,     3, 3  },
#endif

    { ngx_string("abs"),              NGX_STREAM_VAR_OP_ABS,           1, 1  },
    { ngx_string("max"),              NGX_STREAM_VAR_OP_MAX,           2, 2  },
    { ngx_string("min"),              NGX_STREAM_VAR_OP_MIN,           2, 2  },
    { ngx_string("add"),              NGX_STREAM_VAR_OP_ADD,           2, 2  },
    { ngx_string("sub"),              NGX_STREAM_VAR_OP_SUB,           2, 2  },
    { ngx_string("mul"),              NGX_STREAM_VAR_OP_MUL,           2, 2  },
    { ngx_string("div"),              NGX_STREAM_VAR_OP_DIV,           2, 2  },
    { ngx_string("mod"),              NGX_STREAM_VAR_OP_MOD,           2, 2  },
    { ngx_string("bitwise_and"),      NGX_STREAM_VAR_OP_BITWISE_AND,   2, 2  },
    { ngx_string("bitwise_not"),      NGX_STREAM_VAR_OP_BITWISE_NOT,   1, 1  },
    { ngx_string("bitwise_or"),       NGX_STREAM_VAR_OP_BITWISE_OR,    2, 2  },
    { ngx_string("bitwise_xor"),      NGX_STREAM_VAR_OP_BITWISE_XOR,   2, 2  },
    { ngx_string("lshift"),           NGX_STREAM_VAR_OP_LSHIFT,        2, 2  },
    { ngx_string("rshift"),           NGX_STREAM_VAR_OP_RSHIFT,        2, 2  },
    { ngx_string("urshift"),          NGX_STREAM_VAR_OP_URSHIFT,       2, 2  },
    { ngx_string("round"),            NGX_STREAM_VAR_OP_ROUND,         2, 2  },
    { ngx_string("int"),              NGX_STREAM_VAR_OP_INT,           1, 1  },
    { ngx_string("floor"),            NGX_STREAM_VAR_OP_FLOOR,         1, 1  },
    { ngx_string("ceil"),             NGX_STREAM_VAR_OP_CEIL,          1, 1  },
    { ngx_string("rand"),             NGX_STREAM_VAR_OP_RAND,          0, 2  },
    { ngx_string("hexrand"),          NGX_STREAM_VAR_OP_HEXRAND,       0, 1  },

    { ngx_string("hex_encode"),       NGX_STREAM_VAR_OP_HEX_ENCODE,    1, 1  },
    { ngx_string("hex_decode"),       NGX_STREAM_VAR_OP_HEX_DECODE,    1, 1  },
    { ngx_string("dec_to_hex"),       NGX_STREAM_VAR_OP_DEC_TO_HEX,    1, 1  },
    { ngx_string("hex_to_dec"),       NGX_STREAM_VAR_OP_HEX_TO_DEC,    1, 1  },
    { ngx_string("escape_uri"),       NGX_STREAM_VAR_OP_ESCAPE_URI,    1, 1  },
    { ngx_string("escape_args"),      NGX_STREAM_VAR_OP_ESCAPE_ARGS,   1, 1  },
    { ngx_string("escape_uri_component"),
                               NGX_STREAM_VAR_OP_ESCAPE_URI_COMPONENT, 1, 1  },
    { ngx_string("escape_html"),      NGX_STREAM_VAR_OP_ESCAPE_HTML,   1, 1  },
    { ngx_string("unescape_uri"),     NGX_STREAM_VAR_OP_UNESCAPE_URI,  1, 1  },
    { ngx_string("base64_encode"),    NGX_STREAM_VAR_OP_BASE64_ENCODE, 1, 1  },
    { ngx_string("base64url_encode"),
                                   NGX_STREAM_VAR_OP_BASE64URL_ENCODE, 1, 1  },
    { ngx_string("base64_decode"),    NGX_STREAM_VAR_OP_BASE64_DECODE, 1, 1  },
    { ngx_string("base64url_decode"),
                                   NGX_STREAM_VAR_OP_BASE64URL_DECODE, 1, 1  },

    { ngx_string("crc32"),            NGX_STREAM_VAR_OP_CRC32,         1, 1  },
    { ngx_string("md5"),              NGX_STREAM_VAR_OP_MD5,           1, 1  },
    { ngx_string("sha1"),             NGX_STREAM_VAR_OP_SHA1,          1, 1  },

#if (NGX_STREAM_SSL)
    { ngx_string("sha224"),           NGX_STREAM_VAR_OP_SHA224,        1, 1  },
    { ngx_string("sha256"),           NGX_STREAM_VAR_OP_SHA256,        1, 1  },
    { ngx_string("sha384"),           NGX_STREAM_VAR_OP_SHA384,        1, 1  },
    { ngx_string("sha512"),           NGX_STREAM_VAR_OP_SHA512,        1, 1  },
    { ngx_string("hmac_md5"),         NGX_STREAM_VAR_OP_HMAC_MD5,      2, 2  },
    { ngx_string("hmac_sha1"),        NGX_STREAM_VAR_OP_HMAC_SHA1,     2, 2  },
    { ngx_string("hmac_sha224"),      NGX_STREAM_VAR_OP_HMAC_SHA224,   2, 2  },
    { ngx_string("hmac_sha256"),      NGX_STREAM_VAR_OP_HMAC_SHA256,   2, 2  },
    { ngx_string("hmac_sha384"),      NGX_STREAM_VAR_OP_HMAC_SHA384,   2, 2  },
    { ngx_string("hmac_sha512"),      NGX_STREAM_VAR_OP_HMAC_SHA512,   2, 2  },
#endif

    { ngx_string("gmt_time"),         NGX_STREAM_VAR_OP_GMT_TIME,      1, 2  },
    { ngx_string("local_time"),       NGX_STREAM_VAR_OP_LOCAL_TIME,    1, 2  },
    { ngx_string("unix_time"),        NGX_STREAM_VAR_OP_UNIX_TIME,     0, 3  },
    { ngx_string("cidr"),             NGX_STREAM_VAR_OP_CIDR,          2, 3  },

    { ngx_null_string,                NGX_STREAM_VAR_OP_UNKNOWN,       0, 0  }
};


static ngx_command_t  ngx_stream_var_commands[] = {

    { ngx_string("var"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF
#if (NGX_CONDITION)
                           |NGX_STREAM_MAIN_WHEN_CONF
                           |NGX_STREAM_SRV_WHEN_CONF
#endif
                           |NGX_CONF_2MORE,
      ngx_stream_var_create_variable,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_stream_module_t  ngx_stream_var_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_stream_var_create_srv_conf,        /* create server configuration */
    ngx_stream_var_merge_srv_conf          /* merge server configuration */
};


ngx_module_t  ngx_stream_var_module = {
    NGX_MODULE_V1,
    &ngx_stream_var_module_ctx,            /* module context */
    ngx_stream_var_commands,               /* module directives */
    NGX_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_stream_var_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_var_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_var_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->vars = NULL;

    return conf;
}


static char *
ngx_stream_var_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_var_conf_t      *prev = parent;
    ngx_stream_var_conf_t      *conf = child;
    ngx_stream_var_variable_t  *var, *prev_var, *conf_var;
    ngx_stream_var_rule_t      *rule;
    ngx_uint_t                  i, j, found;

    if (conf->vars == NULL) {
        conf->vars = prev->vars;
        return NGX_CONF_OK;
    }

    if (prev->vars == NULL) {
        return NGX_CONF_OK;
    }

    prev_var = prev->vars->elts;
    for (i = 0; i < prev->vars->nelts; i++) {
        found = 0;

        conf_var = conf->vars->elts;
        for (j = 0; j < conf->vars->nelts; j++) {
            if (prev_var[i].index == conf_var[j].index) {
                rule = ngx_array_push_n(conf_var[j].rules,
                                        prev_var[i].rules->nelts);
                if (rule == NULL) {
                    return NGX_CONF_ERROR;
                }

                ngx_memcpy(rule, prev_var[i].rules->elts,
                           prev_var[i].rules->nelts
                           * sizeof(ngx_stream_var_rule_t));

                found = 1;
                break;
            }
        }

        if (!found) {
            var = ngx_array_push(conf->vars);
            if (var == NULL) {
                return NGX_CONF_ERROR;
            }

            *var = prev_var[i];
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_var_create_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_var_conf_t       *vcf = conf;

    ngx_str_t                   *value;
    ngx_uint_t                   cur, last;
#if !(NGX_CONDITION)
    ngx_str_t                    val;
#endif
    ngx_stream_variable_t       *v;
    ngx_stream_var_variable_t   *var;
    ngx_stream_var_rule_t       *rule;
    ngx_uint_t                   i;
    ngx_stream_var_operator_e    op;
    ngx_uint_t                   ignore_case, args, min_args, max_args;
#if !(NGX_CONDITION)
    ngx_stream_complex_value_t  *filter;
    ngx_uint_t                   negative;
#endif
    ngx_int_t                    index;

#if (NGX_PCRE)
    ngx_regex_compile_t          rc;
    u_char                       errstr[NGX_MAX_CONF_ERRSTR];
    ngx_str_t                    regex;
    size_t                       regex_len;
#endif

    ngx_stream_complex_value_t          *cv;
    ngx_stream_compile_complex_value_t   ccv;

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    if (value[1].len == 0 || value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "var: invalid variable name \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    ngx_strlow(value[1].data, value[1].data, value[1].len);
    value[1].len--;
    value[1].data++;

    ngx_strlow(value[2].data, value[2].data, value[2].len);

    op = NGX_STREAM_VAR_OP_UNKNOWN;
    for (i = 0; ngx_stream_var_operators[i].name.len > 0; i++) {

        if (value[2].len == ngx_stream_var_operators[i].name.len
            && ngx_strncmp(value[2].data,
                     ngx_stream_var_operators[i].name.data, value[2].len) == 0)
        {
            op = ngx_stream_var_operators[i].op;
            min_args = ngx_stream_var_operators[i].min_args;
            max_args = ngx_stream_var_operators[i].max_args;
            break;
        }
    }

    if (op == NGX_STREAM_VAR_OP_UNKNOWN) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "var: unsupported operator \"%V\"",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

#if (NGX_CONDITION)
    if (cf->args->nelts > 3
        && (ngx_strncmp(value[last].data, "if=", 3) == 0
            || ngx_strncmp(value[last].data, "if!=", 4) == 0))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[last]);
        return NGX_CONF_ERROR;
    }

    args = cf->args->nelts - 3;
#else
    filter = NULL;
    negative = 0;
    if (cf->args->nelts > 3
        && (ngx_strncmp(value[last].data, "if=", 3) == 0
            || ngx_strncmp(value[last].data, "if!=", 4) == 0))
    {
        if (value[last].data[2] == '=') {
            val.len = value[last].len - 3;
            val.data = value[last].data + 3;
            negative = 0;

        } else {
            val.len = value[last].len - 4;
            val.data = value[last].data + 4;
            negative = 1;
        }

        ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &val;
        ccv.complex_value = ngx_palloc(cf->pool,
                                       sizeof(ngx_stream_complex_value_t));
        if (ccv.complex_value == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        filter = ccv.complex_value;
        args = cf->args->nelts - 4;
        last--;

    } else {
        args = cf->args->nelts - 3;
    }
#endif

    cur = 3;
    ignore_case = 0;
    if (cur <= last && value[cur].len == 2
        && value[cur].data[0] == '-' && value[cur].data[1] == 'i')
    {
        ignore_case = 1;
        args--;
        cur++;
    }

    if (args < min_args || args > max_args) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "var: invalid number of arguments "
                           "for operator \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    v = ngx_stream_add_variable(cf, &value[1],
                                NGX_STREAM_VAR_CHANGEABLE
                                |NGX_STREAM_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    if (v->get_handler && v->get_handler != ngx_stream_var_variable_handler) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "var: variable \"%V\" already "
                           "has other handler", &value[1]);
        return NGX_CONF_ERROR;
    }

    index = ngx_stream_get_variable_index(cf, &value[1]);

    if (vcf->vars == NULL) {
        vcf->vars = ngx_array_create(cf->pool, 4,
                                     sizeof(ngx_stream_var_variable_t));
        if (vcf->vars == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 0; i < vcf->vars->nelts; i++) {

        var = (ngx_stream_var_variable_t *) vcf->vars->elts + i;

        if (var->index == index) {
            break;
        }
    }

    if (i == vcf->vars->nelts) {
        var = ngx_array_push(vcf->vars);
        if (var == NULL) {
            return NGX_CONF_ERROR;
        }

        var->name = value[1];
        var->index = index;

        var->rules = ngx_array_create(cf->pool, 4,
                                      sizeof(ngx_stream_var_rule_t));
        if (var->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(var->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    rule->operator = op;
    rule->ignore_case = ignore_case;
#if (NGX_CONDITION)
    rule->expr_id = ngx_condition_get_associated_expr_id(cf);
#else
    rule->filter = filter;
    rule->negative = negative;
#endif

#if (NGX_PCRE)

    if (op == NGX_STREAM_VAR_OP_REGEX_CAPTURE
        || op == NGX_STREAM_VAR_OP_REGEX_SUB)
    {
        args--;

        rule->args = ngx_array_create(cf->pool, ngx_max(args, 1),
                                      sizeof(ngx_stream_complex_value_t));
        if (rule->args == NULL) {
            return NGX_CONF_ERROR;
        }

        cv = ngx_array_push(rule->args);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[cur];
        ccv.complex_value = cv;

        if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        cur++;

        if (op == NGX_STREAM_VAR_OP_REGEX_SUB) {
            regex_len = value[cur].len + 2;
            regex.data = ngx_pnalloc(cf->pool, regex_len);
            if (regex.data == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memcpy(regex.data, value[cur].data, value[cur].len);
            ngx_memcpy(regex.data + value[cur].len, "()", 2);
            regex.len = regex_len;

        } else {
            regex = value[cur];
        }

        ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

        rc.pattern = regex;
        rc.pool = cf->pool;
        rc.err.len = NGX_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        if (ignore_case == 1) {
            rc.options = NGX_REGEX_CASELESS;
        }

        rule->regex = ngx_stream_regex_compile(cf, &rc);
        if (rule->regex == NULL) {
            return NGX_CONF_ERROR;
        }

        cur++;

        cv = ngx_array_push(rule->args);
        if (cv == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[cur];
        ccv.complex_value = cv;

        if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

    } else {

#endif

        rule->args = ngx_array_create(cf->pool, ngx_max(args, 1),
                                      sizeof(ngx_stream_complex_value_t));
        if (rule->args == NULL) {
            return NGX_CONF_ERROR;
        }

        for (i = 0; i < args; i++) {
            cv = ngx_array_push(rule->args);
            if (cv == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(&ccv, sizeof(ngx_stream_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[cur + i];
            ccv.complex_value = cv;

            if (ngx_stream_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }

#if (NGX_PCRE)

    }

#endif

    v->data = (uintptr_t) &var->index;
    v->get_handler = ngx_stream_var_variable_handler;

    return NGX_CONF_OK;
}


static ngx_stream_var_ctx_t *
ngx_stream_var_get_ctx(ngx_stream_session_t *s)
{
    ngx_stream_core_main_conf_t  *cmcf;

    ngx_stream_var_ctx_t  *ctx;

    /* attempt to get the current request context */
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_var_module);
    if (ctx != NULL) {
        return ctx;
    }

    /* if the context does not exist, create and attach it to the request */
    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_stream_var_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    /* initialize the variable lock array */
    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);

    ctx->locked_vars = ngx_pcalloc(s->connection->pool,
                                   cmcf->variables.nelts * sizeof(ngx_uint_t));
    if (ctx->locked_vars == NULL) {
        return NULL;
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_var_module);

    return ctx;
}


static ngx_int_t
ngx_stream_variable_acquire_lock(ngx_stream_session_t *s, ngx_int_t index)
{
    ngx_stream_var_ctx_t       *ctx;

    /* get or create the context */
    ctx = ngx_stream_var_get_ctx(s);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    /* check if it is already locked */
    if (ctx->locked_vars[index] == 1) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "var: circular reference detected "
                      "for variable index %ui", index);
        return NGX_ERROR;
    }

    /* mark the variable as locked */
    ctx->locked_vars[index] = 1;

    return NGX_OK;
}


static void
ngx_stream_variable_release_lock(ngx_stream_session_t *s, ngx_int_t index)
{
    ngx_stream_var_ctx_t       *ctx;

    /* get the current request context */
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_var_module);
    if (ctx == NULL) {
        return;
    }

    /* clear the lock mark */
    ctx->locked_vars[index] = 0;
}


static ngx_int_t
ngx_stream_var_get_cached_random(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_uint_t                       i;
    ngx_stream_var_ctx_t            *ctx;
    ngx_stream_var_random_value_t   *values;

    ctx = ngx_stream_var_get_ctx(s);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->random_values == NULL) {
        return NGX_DECLINED;
    }

    values = ctx->random_values->elts;

    for (i = 0; i < ctx->random_values->nelts; i++) {
        if (values[i].rule == rule) {
            v->len = values[i].value.len;
            v->data = values[i].value.data;

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_stream_var_cache_random(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_var_ctx_t           *ctx;
    ngx_stream_var_random_value_t  *value;

    ctx = ngx_stream_var_get_ctx(s);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->random_values == NULL) {
        ctx->random_values = ngx_array_create(s->connection->pool, 2,
                                      sizeof(ngx_stream_var_random_value_t));
        if (ctx->random_values == NULL) {
            return NGX_ERROR;
        }
    }

    value = ngx_array_push(ctx->random_values);
    if (value == NULL) {
        return NGX_ERROR;
    }

    value->rule = rule;
    value->value.len = v->len;
    value->value.data = v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_find_rule(ngx_stream_session_t *s,
    ngx_stream_var_variable_t *var, ngx_stream_var_rule_t **rule)
{
    ngx_stream_var_rule_t      *rules;
    ngx_uint_t                  i;
#if !(NGX_CONDITION)
    ngx_str_t                   val;
#endif

    rules = var->rules->elts;

    for (i = 0; i < var->rules->nelts; i++) {

#if (NGX_CONDITION)
        if (ngx_stream_condition_get_expr_result(s, rules[i].expr_id)
            != NGX_CONDITION_EXPR_HIT)
        {
            continue;
        }
#else
        if (rules[i].filter) {

            if (ngx_stream_complex_value(s, rules[i].filter, &val)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {

                if (!rules[i].negative) {
                    continue;
                }

            } else {

                if (rules[i].negative) {
                    continue;
                }
            }
        }
#endif

        *rule = &rules[i];

        return NGX_OK;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_stream_var_evaluate_rule(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    switch (rule->operator) {

    case NGX_STREAM_VAR_OP_SET:
        return ngx_stream_var_exec_set(s, v, rule);

    case NGX_STREAM_VAR_OP_LEN:
        return ngx_stream_var_exec_len(s, v, rule);

    case NGX_STREAM_VAR_OP_UPPER:
        return ngx_stream_var_exec_upper(s, v, rule);

    case NGX_STREAM_VAR_OP_LOWER:
        return ngx_stream_var_exec_lower(s, v, rule);

    case NGX_STREAM_VAR_OP_INITCAP:
        return ngx_stream_var_exec_initcap(s, v, rule);

    case NGX_STREAM_VAR_OP_TRIM:
        return ngx_stream_var_exec_trim(s, v, rule);

    case NGX_STREAM_VAR_OP_LTRIM:
        return ngx_stream_var_exec_ltrim(s, v, rule);

    case NGX_STREAM_VAR_OP_RTRIM:
        return ngx_stream_var_exec_rtrim(s, v, rule);

    case NGX_STREAM_VAR_OP_REVERSE:
        return ngx_stream_var_exec_reverse(s, v, rule);

    case NGX_STREAM_VAR_OP_POSITION:
        return ngx_stream_var_exec_position(s, v, rule);

    case NGX_STREAM_VAR_OP_REPEAT:
        return ngx_stream_var_exec_repeat(s, v, rule);

    case NGX_STREAM_VAR_OP_SUBSTR:
        return ngx_stream_var_exec_substr(s, v, rule);

    case NGX_STREAM_VAR_OP_REPLACE:
        return ngx_stream_var_exec_replace(s, v, rule);

    case NGX_STREAM_VAR_OP_EXTRACT_PARAM:
        return ngx_stream_var_exec_extract_param(s, v, rule);

    case NGX_STREAM_VAR_OP_KEEP_PARAMS:
        return ngx_stream_var_exec_keep_params(s, v, rule);

    case NGX_STREAM_VAR_OP_REMOVE_PARAMS:
        return ngx_stream_var_exec_remove_params(s, v, rule);

#if (NGX_CJSON)
    case NGX_STREAM_VAR_OP_EXTRACT_JSON:
        return ngx_stream_var_exec_extract_json(s, v, rule);
#endif

#if (NGX_PCRE)
    case NGX_STREAM_VAR_OP_REGEX_CAPTURE:
        return ngx_stream_var_exec_regex_capture(s, v, rule);

    case NGX_STREAM_VAR_OP_REGEX_SUB:
        return ngx_stream_var_exec_regex_sub(s, v, rule);
#endif

    case NGX_STREAM_VAR_OP_ABS:
        return ngx_stream_var_exec_abs(s, v, rule);

    case NGX_STREAM_VAR_OP_MAX:
        return ngx_stream_var_exec_max(s, v, rule);

    case NGX_STREAM_VAR_OP_MIN:
        return ngx_stream_var_exec_min(s, v, rule);

    case NGX_STREAM_VAR_OP_ADD:
        return ngx_stream_var_exec_add(s, v, rule);

    case NGX_STREAM_VAR_OP_SUB:
        return ngx_stream_var_exec_sub(s, v, rule);

    case NGX_STREAM_VAR_OP_MUL:
        return ngx_stream_var_exec_mul(s, v, rule);

    case NGX_STREAM_VAR_OP_DIV:
        return ngx_stream_var_exec_div(s, v, rule);

    case NGX_STREAM_VAR_OP_MOD:
        return ngx_stream_var_exec_mod(s, v, rule);

    case NGX_STREAM_VAR_OP_BITWISE_AND:
        return ngx_stream_var_exec_bitwise_and(s, v, rule);

    case NGX_STREAM_VAR_OP_BITWISE_NOT:
        return ngx_stream_var_exec_bitwise_not(s, v, rule);

    case NGX_STREAM_VAR_OP_BITWISE_OR:
        return ngx_stream_var_exec_bitwise_or(s, v, rule);

    case NGX_STREAM_VAR_OP_BITWISE_XOR:
        return ngx_stream_var_exec_bitwise_xor(s, v, rule);

    case NGX_STREAM_VAR_OP_LSHIFT:
        return ngx_stream_var_exec_lshift(s, v, rule);

    case NGX_STREAM_VAR_OP_RSHIFT:
        return ngx_stream_var_exec_rshift(s, v, rule);

    case NGX_STREAM_VAR_OP_URSHIFT:
        return ngx_stream_var_exec_urshift(s, v, rule);

    case NGX_STREAM_VAR_OP_ROUND:
        return ngx_stream_var_exec_round(s, v, rule);

    case NGX_STREAM_VAR_OP_INT:
        return ngx_stream_var_exec_int(s, v, rule);

    case NGX_STREAM_VAR_OP_FLOOR:
        return ngx_stream_var_exec_floor(s, v, rule);

    case NGX_STREAM_VAR_OP_CEIL:
        return ngx_stream_var_exec_ceil(s, v, rule);

    case NGX_STREAM_VAR_OP_RAND:
        return ngx_stream_var_exec_rand(s, v, rule);

    case NGX_STREAM_VAR_OP_HEXRAND:
        return ngx_stream_var_exec_hexrand(s, v, rule);

    case NGX_STREAM_VAR_OP_HEX_ENCODE:
        return ngx_stream_var_exec_hex_encode(s, v, rule);

    case NGX_STREAM_VAR_OP_DEC_TO_HEX:
        return ngx_stream_var_exec_dec_to_hex(s, v, rule);

    case NGX_STREAM_VAR_OP_HEX_TO_DEC:
        return ngx_stream_var_exec_hex_to_dec(s, v, rule);

    case NGX_STREAM_VAR_OP_HEX_DECODE:
        return ngx_stream_var_exec_hex_decode(s, v, rule);

    case NGX_STREAM_VAR_OP_ESCAPE_URI:
        return ngx_stream_var_exec_escape_uri(s, v, rule);

    case NGX_STREAM_VAR_OP_ESCAPE_ARGS:
        return ngx_stream_var_exec_escape_args(s, v, rule);

    case NGX_STREAM_VAR_OP_ESCAPE_URI_COMPONENT:
        return ngx_stream_var_exec_escape_uri_component(s, v, rule);

    case NGX_STREAM_VAR_OP_ESCAPE_HTML:
        return ngx_stream_var_exec_escape_html(s, v, rule);

    case NGX_STREAM_VAR_OP_UNESCAPE_URI:
        return ngx_stream_var_exec_unescape_uri(s, v, rule);

    case NGX_STREAM_VAR_OP_BASE64_ENCODE:
        return ngx_stream_var_exec_base64_encode(s, v, rule);

    case NGX_STREAM_VAR_OP_BASE64URL_ENCODE:
        return ngx_stream_var_exec_base64url_encode(s, v, rule);

    case NGX_STREAM_VAR_OP_BASE64_DECODE:
        return ngx_stream_var_exec_base64_decode(s, v, rule);

    case NGX_STREAM_VAR_OP_BASE64URL_DECODE:
        return ngx_stream_var_exec_base64url_decode(s, v, rule);

    case NGX_STREAM_VAR_OP_CRC32:
        return ngx_stream_var_exec_crc32(s, v, rule);

    case NGX_STREAM_VAR_OP_MD5:
        return ngx_stream_var_exec_md5(s, v, rule);

    case NGX_STREAM_VAR_OP_SHA1:
        return ngx_stream_var_exec_sha1(s, v, rule);

#if (NGX_STREAM_SSL)
    case NGX_STREAM_VAR_OP_SHA224:
        return ngx_stream_var_exec_sha224(s, v, rule);

    case NGX_STREAM_VAR_OP_SHA256:
        return ngx_stream_var_exec_sha256(s, v, rule);

    case NGX_STREAM_VAR_OP_SHA384:
        return ngx_stream_var_exec_sha384(s, v, rule);

    case NGX_STREAM_VAR_OP_SHA512:
        return ngx_stream_var_exec_sha512(s, v, rule);

    case NGX_STREAM_VAR_OP_HMAC_MD5:
        return ngx_stream_var_exec_hmac_md5(s, v, rule);

    case NGX_STREAM_VAR_OP_HMAC_SHA1:
        return ngx_stream_var_exec_hmac_sha1(s, v, rule);

    case NGX_STREAM_VAR_OP_HMAC_SHA224:
        return ngx_stream_var_exec_hmac_sha224(s, v, rule);

    case NGX_STREAM_VAR_OP_HMAC_SHA256:
        return ngx_stream_var_exec_hmac_sha256(s, v, rule);

    case NGX_STREAM_VAR_OP_HMAC_SHA384:
        return ngx_stream_var_exec_hmac_sha384(s, v, rule);

    case NGX_STREAM_VAR_OP_HMAC_SHA512:
        return ngx_stream_var_exec_hmac_sha512(s, v, rule);
#endif

    case NGX_STREAM_VAR_OP_GMT_TIME:
        return ngx_stream_var_exec_gmt_time(s, v, rule);

    case NGX_STREAM_VAR_OP_LOCAL_TIME:
        return ngx_stream_var_exec_local_time(s, v, rule);

    case NGX_STREAM_VAR_OP_UNIX_TIME:
        return ngx_stream_var_exec_unix_time(s, v, rule);

    case NGX_STREAM_VAR_OP_CIDR:
        return ngx_stream_var_exec_cidr(s, v, rule);

    default:
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "var: unknown operator");
        return NGX_ERROR;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_stream_var_variable_handler(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    ngx_stream_var_conf_t        *vcf;
    ngx_stream_var_variable_t    *var, *vars;
    ngx_stream_var_rule_t        *rule;
    ngx_int_t                     index;
    ngx_int_t                     rc;
    ngx_uint_t                    i;

    vcf = ngx_stream_get_module_srv_conf(s, ngx_stream_var_module);

    if (vcf == NULL || vcf->vars == NULL || vcf->vars->nelts == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "var: not variable defined");
        v->not_found = 1;
        return NGX_OK;
    }

    index = *(ngx_int_t *) data;

    var = NULL;
    vars = vcf->vars->elts;

    for (i = 0; i < vcf->vars->nelts; i++) {

        if (vars[i].index != index) {
            continue;
        }

        /* found the variable */
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "var: variable \"%V\" definition found",
                       &vars[i].name);

        var = &vars[i];
        break;
    }

    if (var == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    rc = ngx_stream_var_find_rule(s, var, &rule);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "var: evaluating the expression of variable \"%V\"",
                   &var->name);

    /* acquire lock for variable to avoid loopback exception */
    if (ngx_stream_variable_acquire_lock(s, var->index) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    /* evaluate the variable expression */
    rc = ngx_stream_var_evaluate_rule(s, v, rule);

    /* evaluation is complete, release the lock */
    ngx_stream_variable_release_lock(s, var->index);

    if (rc != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "var: evaluated variable \"%V\", "
                   "length: %uz, value: \"%*s\"",
                   &var->name, v->len, v->len, v->data);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_utils_check_str_is_num(ngx_str_t val)
{
    ngx_str_t    val_abs;
    ngx_int_t    num;
    ngx_uint_t   decimal_places;
    ngx_uint_t   i;

    val_abs = val;
    decimal_places = 0;

    if (val_abs.len > 0 && val_abs.data[0] == '-') {
        val_abs.data++;
        val_abs.len--;
    }

    if (val_abs.len == 0) {
        return NGX_ERROR;
    }

    for (i = 0; i < val_abs.len; i++) {

        if (val_abs.data[i] == '.') {
            decimal_places = val_abs.len - i - 1;
            break;
        }
    }

    if (decimal_places == 0) {
        num = ngx_atoi(val_abs.data, val_abs.len);

    } else {
        num = ngx_atofp(val_abs.data, val_abs.len, decimal_places);
    }

    if (num == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_utils_auto_atoi(ngx_str_t val, ngx_int_t *int_val)
{
    ngx_int_t  is_negative;

    is_negative = 0;

    if (val.len == 0) {
        return NGX_ERROR;
    }

    if (val.data[0] == '-') {

        if (val.len == 1) {
            return NGX_ERROR;
        }

        *int_val = ngx_atoi(val.data + 1, val.len - 1);
        is_negative = 1;

    } else {
        *int_val = ngx_atoi(val.data, val.len);
    }

    if (*int_val == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (is_negative) {
        *int_val = -*int_val;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_utils_auto_atofp(ngx_str_t val1, ngx_str_t val2,
    ngx_int_t *int_val1, ngx_int_t *int_val2)
{
    ngx_uint_t   decimal_places1, decimal_places2, max_decimal_places;
    ngx_uint_t   is_negative1, is_negative2;
    ngx_uint_t   i;

    decimal_places1 = 0;
    decimal_places2 = 0;
    is_negative1 = 0;
    is_negative2 = 0;

    if (val1.len == 0 || val2.len == 0) {
        return NGX_ERROR;
    }

    if (val1.data[0] == '-') {

        if (val1.len == 1) {
            return NGX_ERROR;
        }

        is_negative1 = 1;
        val1.data++;
        val1.len--;
    }

    if (val2.data[0] == '-') {

        if (val2.len == 1) {
            return NGX_ERROR;
        }

        is_negative2 = 1;
        val2.data++;
        val2.len--;
    }

    for (i = 0; i < val1.len; i++) {

        if (val1.data[i] == '.') {
            decimal_places1 = val1.len - i - 1;
            break;
        }
    }

    for (i = 0; i < val2.len; i++) {

        if (val2.data[i] == '.') {
            decimal_places2 = val2.len - i - 1;
            break;
        }
    }

    max_decimal_places = ngx_max(decimal_places1, decimal_places2);

    if (max_decimal_places == 0) {
        *int_val1 = ngx_atoi(val1.data, val1.len);
        *int_val2 = ngx_atoi(val2.data, val2.len);

    } else {
        *int_val1 = ngx_atofp(val1.data, val1.len, max_decimal_places);
        *int_val2 = ngx_atofp(val2.data, val2.len, max_decimal_places);
    }

    if (*int_val1 == NGX_ERROR || *int_val2 == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (is_negative1 == 1) {
        *int_val1 = -*int_val1;
    }

    if (is_negative2 == 1) {
        *int_val2 = -*int_val2;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_utils_escape_uri(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule,
    ngx_uint_t type)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    size_t                       len;
    uintptr_t                    escape;
    u_char                      *src, *dst;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    src = val.data;

    escape = 2 * ngx_escape_uri(NULL, src, val.len, type);
    len = val.len + escape;

    dst = ngx_pnalloc(s->connection->pool, len);
    if (dst == NULL) {
        return NGX_ERROR;
    }

    if (escape == 0) {
        ngx_memcpy(dst, src, val.len);

    } else {
        ngx_escape_uri(dst, src, val.len, type);
    }

    v->len = len;
    v->data = dst;

    return NGX_OK;
}


/*
 * same as ngx_strlcasestrn(), but case-sensitive.
 * ngx_stream_var_utils_strlstrn() is intended to search for static substring
 * with known length in string until the argument last. The argument n
 * must be length of the second substring - 1.
 */
static u_char *
ngx_stream_var_utils_strlstrn(u_char *s1, u_char *last, u_char *s2, size_t n)
{
    ngx_uint_t  c1, c2;

    c2 = (ngx_uint_t) *s2++;

    last -= n;

    do {
        do {
            if (s1 >= last) {
                return NULL;
            }

            c1 = (ngx_uint_t) *s1++;

        } while (c1 != c2);

    } while (ngx_strncmp(s1, s2, n) != 0);

    return --s1;
}


static ngx_int_t
ngx_stream_var_utils_filter_params(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule,
    ngx_uint_t keep)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_str_t                   *key_elts;
    u_char                      *p, *last, *eq, *next_sep;
    ngx_uint_t                   j, found, first;
    size_t                       len;
    u_char                      *result, *dst;
    ngx_str_t                    key;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Evaluate all args */
    key_elts = ngx_palloc(s->connection->pool,
                          rule->args->nelts * sizeof(ngx_str_t));
    if (key_elts == NULL) {
        return NGX_ERROR;
    }

    for (j = 0; j < rule->args->nelts; j++) {
        if (ngx_stream_complex_value(s, &args[j], &key_elts[j]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* separator and delimiter are required */
    if (key_elts[1].len != 1) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid separator: \"%V\"",
                      &key_elts[1]);
        goto return_original;
    }

    if (key_elts[2].len != 1) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid delimiter: \"%V\"",
                      &key_elts[2]);
        goto return_original;
    }

    if (val.len == 0) {
        goto return_original;
    }

    /* First pass: calculate result length */
    len = 0;
    first = 1;
    p = val.data;
    last = val.data + val.len;

    while (p < last) {
        /* Find next separator */
        next_sep = ngx_strlchr(p, last, key_elts[1].data[0]);
        if (next_sep == NULL) {
            next_sep = last;
        }

        /* Skip empty segments */
        if (p == next_sep) {
            p = next_sep + 1;
            continue;
        }

        /* Find delimiter in this segment */
        eq = ngx_strlchr(p, next_sep, key_elts[2].data[0]);

        /* Extract param name (trim spaces) */
        key.data = p;
        if (eq == NULL) {
            key.len = next_sep - p;

        } else {
            key.len = eq - p;
        }

        while (key.len && ngx_stream_var_isspace(key.data[0])) {
            key.data++;
            key.len--;
        }

        while (key.len && ngx_stream_var_isspace(key.data[key.len - 1])) {
            key.len--;
        }

        if (key.len == 0) {
            p = next_sep + 1;
            continue;
        }

        /* Check if key is in the list */
        found = 0;
        for (j = 3; j < rule->args->nelts; j++) {
            if (key.len == key_elts[j].len) {
                if (rule->ignore_case) {
                    if (ngx_strncasecmp(key.data, key_elts[j].data, key.len)
                        == 0)
                    {
                        found = 1;
                        break;
                    }

                } else {
                    if (ngx_strncmp(key.data, key_elts[j].data, key.len)
                        == 0)
                    {
                        found = 1;
                        break;
                    }
                }
            }
        }

        if ((keep && found) || (!keep && !found)) {
            if (!first) {
                len += 1; /* separator */
            }

            len += next_sep - p;
            first = 0;
        }

        if (next_sep == last) {
            break;
        }

        p = next_sep + 1;
    }

    if (first) {
        /* No params matched */
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    /* Second pass: build result */
    result = ngx_pnalloc(s->connection->pool, len);
    if (result == NULL) {
        return NGX_ERROR;
    }

    dst = result;
    first = 1;
    p = val.data;
    last = val.data + val.len;

    while (p < last) {
        next_sep = ngx_strlchr(p, last, key_elts[1].data[0]);
        if (next_sep == NULL) {
            next_sep = last;
        }

        if (p == next_sep) {
            p = next_sep + 1;
            continue;
        }

        eq = ngx_strlchr(p, next_sep, key_elts[2].data[0]);

        key.data = p;
        if (eq == NULL) {
            key.len = next_sep - p;

        } else {
            key.len = eq - p;
        }

        while (key.len && ngx_stream_var_isspace(key.data[0])) {
            key.data++;
            key.len--;
        }

        while (key.len && ngx_stream_var_isspace(key.data[key.len - 1])) {
            key.len--;
        }

        if (key.len == 0) {
            p = next_sep + 1;
            continue;
        }

        found = 0;
        for (j = 3; j < rule->args->nelts; j++) {
            if (key.len == key_elts[j].len) {
                if (rule->ignore_case) {
                    if (ngx_strncasecmp(key.data, key_elts[j].data, key.len)
                        == 0)
                    {
                        found = 1;
                        break;
                    }

                } else {
                    if (ngx_strncmp(key.data, key_elts[j].data, key.len)
                        == 0)
                    {
                        found = 1;
                        break;
                    }
                }
            }
        }

        if ((keep && found) || (!keep && !found)) {
            if (!first) {
                *dst++ = key_elts[1].data[0];
            }

            ngx_memcpy(dst, p, next_sep - p);
            dst += next_sep - p;
            first = 0;
        }

        if (next_sep == last) {
            break;
        }

        p = next_sep + 1;
    }

    v->len = dst - result;
    v->data = result;

    return NGX_OK;

return_original:

    v->len = val.len;
    v->data = val.data;

    return NGX_OK;
}


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_var_utils_sha(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule,
    const EVP_MD *evp_md, size_t hash_len)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    EVP_MD_CTX                  *md;
    u_char                       hash[EVP_MAX_MD_SIZE];

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestInit_ex(md, evp_md, NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "EVP_DigestInit_ex() failed");
        goto failed;
    }

    if (EVP_DigestUpdate(md, val.data, val.len) == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "EVP_DigestUpdate() failed");
        goto failed;
    }

    if (EVP_DigestFinal_ex(md, hash, NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "EVP_DigestFinal_ex() failed");
        goto failed;
    }

    EVP_MD_CTX_destroy(md);

    v->data = ngx_pnalloc(s->connection->pool, hash_len * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, hash, hash_len);
    v->len = hash_len * 2;

    return NGX_OK;

failed:

    EVP_MD_CTX_destroy(md);

    return NGX_ERROR;
}


static ngx_int_t
ngx_stream_var_utils_hmac(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule,
    const EVP_MD *evp_md)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val_src, val_secret;
    unsigned int                 md_len;
    unsigned char                md[EVP_MAX_MD_SIZE];

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val_src) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_stream_complex_value(s, &args[1], &val_secret) != NGX_OK) {
        return NGX_ERROR;
    }

    md_len = 0;

    HMAC(evp_md, val_secret.data, val_secret.len,
         val_src.data, val_src.len, md, &md_len);

    if (md_len == 0 || md_len > EVP_MAX_MD_SIZE) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(s->connection->pool, md_len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, &md, md_len);
    v->len = md_len;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_stream_var_exec_set(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;
    v->data = val.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_len(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%uz", val.len) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_upper(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_uint_t                   i;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;

    if (v->len == 0) {
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->data = ngx_pnalloc(s->connection->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < v->len; i++) {
        v->data[i] = ngx_toupper(val.data[i]);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_lower(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_uint_t                   i;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;

    if (v->len == 0) {
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->data = ngx_pnalloc(s->connection->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < v->len; i++) {
        v->data[i] = ngx_tolower(val.data[i]);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_initcap(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_uint_t                   i, in_word;
    u_char                       c;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;

    if (v->len == 0) {
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->data = ngx_pnalloc(s->connection->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    in_word = 0;

    for (i = 0; i < v->len; i++) {
        c = val.data[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9'))
        {
            if (in_word) {
                v->data[i] = ngx_tolower(c);

            } else {
                v->data[i] = ngx_toupper(c);
                in_word = 1;
            }

        } else {
            v->data[i] = c;
            in_word = 0;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_trim(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, str;
    u_char                      *start, *end;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    start = val.data;
    end = val.data + val.len - 1;

    if (rule->args->nelts == 2) {

        if (ngx_stream_complex_value(s, &args[1], &str) != NGX_OK) {
            return NGX_ERROR;
        }

        if (str.len != 1) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid trim char");
            return NGX_ERROR;
        }

        while (start <= end && *start == str.data[0]) {
            start++;
        }

        while (end >= start && *end == str.data[0]) {
            end--;
        }

    } else {

        while (start <= end && ngx_stream_var_isspace(*start)) {
            start++;
        }

        while (end >= start && ngx_stream_var_isspace(*end)) {
            end--;
        }
    }

    v->data = start;
    v->len = (end >= start) ? (size_t) (end - start + 1) : 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_ltrim(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, str;
    u_char                      *start, *end;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    start = val.data;
    end = val.data + val.len - 1;

    if (rule->args->nelts == 2) {

        if (ngx_stream_complex_value(s, &args[1], &str) != NGX_OK) {
            return NGX_ERROR;
        }

        if (str.len != 1) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid trim char");
            return NGX_ERROR;
        }

        while (start <= end && *start == str.data[0]) {
            start++;
        }

    } else {

        while (start <= end && ngx_stream_var_isspace(*start)) {
            start++;
        }
    }

    v->data = start;
    v->len = (end >= start) ? (size_t) (end - start + 1) : 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_rtrim(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, str;
    u_char                      *start, *end;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    start = val.data;
    end = val.data + val.len - 1;

    if (rule->args->nelts == 2) {

        if (ngx_stream_complex_value(s, &args[1], &str) != NGX_OK) {
            return NGX_ERROR;
        }

        if (str.len != 1) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid trim char");
            return NGX_ERROR;
        }

        while (end >= start && *end == str.data[0]) {
            end--;
        }

    } else {

        while (end >= start && ngx_stream_var_isspace(*end)) {
            end--;
        }
    }

    v->data = start;
    v->len = (end >= start) ? (size_t) (end - start + 1) : 0;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_reverse(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    u_char                      *p, *q;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;

    if (v->len == 0) {
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->data = ngx_pnalloc(s->connection->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    /* Reverse the string */
    p = v->data;
    q = val.data + val.len - 1;

    while (q >= val.data) {
        *p++ = *q--;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_position(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, sub;
    u_char                      *p, *found;
    ngx_int_t                    pos;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &sub) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Empty substring is found at position 1 */
    if (sub.len == 0) {
        pos = 1;
        goto covert_pos;
    }

    /* Non-empty substring not found in empty string */
    if (val.len == 0 || sub.len > val.len) {
        pos = 0;
        goto covert_pos;
    }

    /* Search for substring */
    if (rule->ignore_case) {
        found = ngx_strlcasestrn(val.data, val.data + val.len,
                                 sub.data, sub.len - 1);

    } else {
        found = ngx_stream_var_utils_strlstrn(val.data, val.data + val.len,
                                              sub.data, sub.len - 1);
    }

    if (found != NULL) {
        pos = (ngx_int_t) (found - val.data) + 1;

    } else {
        pos = 0;
    }

covert_pos:

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", pos) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_repeat(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, str;
    ngx_int_t                    times;
    u_char                      *p;
    ngx_uint_t                   i;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &str) != NGX_OK)
    {
        return NGX_ERROR;
    }

    times = ngx_atoi(str.data, str.len);
    if (times == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid repeat times \"%V\"", &str);
        return NGX_ERROR;
    }

    if (times == 0 || val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    p = ngx_pnalloc(s->connection->pool, val.len * times);
    if (p == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < (ngx_uint_t) times; i++) {
        ngx_memcpy(p + i * val.len, val.data, val.len);
    }

    v->len = val.len * (ngx_uint_t) times;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_substr(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, val_start, val_len;
    ngx_int_t                    start, len;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val_start) != NGX_OK)
    {
        return NGX_ERROR;
    }

    start = ngx_atoi(val_start.data, val_start.len);
    if (start == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid start \"%V\" in substr", &val_start);
        return NGX_ERROR;
    }

    if ((ngx_uint_t) start >= val.len) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    if (rule->args->nelts == 3
        && ngx_stream_complex_value(s, &args[2], &val_len) == NGX_OK)
    {
        len = ngx_atoi(val_len.data, val_len.len);
        if (len == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid length \"%V\" in substr",
                          &val_len);
            return NGX_ERROR;
        }

        /* adjust len if it exceeds the remaining string length */
        if ((ngx_uint_t) (start + len) > val.len) {
            len = val.len - start;
        }

    } else {
        /* default len to the remaining string length */
        len = val.len - start;
    }

    v->len = len;
    v->data = val.data + start;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_replace(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, val_search, val_replace;
    u_char                      *p, *q;
    size_t                       count, new_len;
    ngx_uint_t                   i;
    ngx_int_t                    rc;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val_search) != NGX_OK
        || ngx_stream_complex_value(s, &args[2], &val_replace) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (val_search.len == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: search string is empty in replace");
        return NGX_ERROR;
    }

    /* count occurrences */
    count = 0;
    p = val.data;

    for (i = 0; i <= val.len - val_search.len; /* void */ ) {

        if (rule->ignore_case) {
            rc = ngx_strncasecmp(p + i, val_search.data, val_search.len);

        } else {
            rc = ngx_strncmp(p + i, val_search.data, val_search.len);
        }

        if (rc == 0) {
            count++;
            i += val_search.len;

        } else {
            i++;
        }
    }

    /* no replacements needed */
    if (count == 0) {
        v->len = val.len;
        v->data = val.data;
        return NGX_OK;
    }

    /* calculate new length */
    new_len = val.len + count * (val_replace.len - val_search.len);

    if (new_len > NGX_MAX_SIZE_T_VALUE) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: replacement result too large");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(s->connection->pool, new_len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    /* perform replacement */
    q = p;
    i = 0;

    while (i < val.len) {

        if (i <= val.len - val_search.len) {

            if (rule->ignore_case) {
                rc = ngx_strncasecmp(val.data + i, val_search.data,
                                     val_search.len);

            } else {
                rc = ngx_strncmp(val.data + i, val_search.data,
                                 val_search.len);
            }

            if (rc == 0) {
                ngx_memcpy(q, val_replace.data, val_replace.len);
                q += val_replace.len;
                i += val_search.len;
                continue;
            }
        }

        *q++ = val.data[i++];
    }

    v->len = q - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_extract_param(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    name, val, separator, delimiter;
    u_char                      *p, *back, *last, sep, del;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    while (val.len && ngx_stream_var_isspace(val.data[0])) {
        val.data++;
        val.len--;
    }

    while (val.len && ngx_stream_var_isspace(val.data[val.len - 1])) {
        val.len--;
    }

    if (val.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_stream_complex_value(s, &args[1], &separator) != NGX_OK) {
        return NGX_ERROR;
    }

    if (separator.len != 1) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid separator: \"%V\"",
                      &separator);
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_stream_complex_value(s, &args[2], &delimiter) != NGX_OK) {
        return NGX_ERROR;
    }

    if (delimiter.len != 1) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid delimiter: \"%V\"",
                      &delimiter);
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_stream_complex_value(s, &args[3], &name) != NGX_OK) {
        return NGX_ERROR;
    }

    while (name.len && ngx_stream_var_isspace(name.data[0])) {
        name.data++;
        name.len--;
    }

    while (name.len && ngx_stream_var_isspace(name.data[name.len - 1])) {
        name.len--;
    }

    if (name.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    sep = separator.data[0];
    del = delimiter.data[0];

    p = val.data;
    last = p + val.len;

    for ( /* void */ ; p < last; p++) {

        /* we need separator after name, so drop one char from last */

        if (rule->ignore_case) {
            p = ngx_strlcasestrn(p, last - 1, name.data, name.len - 1);

        } else {
            p = ngx_stream_var_utils_strlstrn(p, last - 1, name.data,
                                              name.len - 1);
        }

        if (p == NULL) {
            v->not_found = 1;
            return NGX_OK;
        }

        if (*(p + name.len) != del) {
            continue;
        }

        if (p > val.data) {
            back = p - 1;

            while (back > val.data && *back == ' ') {
                back--;
            }

            if (*back != sep) {
                continue;
            }
        }

        p += name.len + 1;

        back = ngx_strlchr(p, last, sep);

        if (back) {
            last = back;
        }

        while (p < last && *p == ' ') {
            p++;
        }

        while (last > p && *(last - 1) == ' ') {
            last--;
        }

        v->data = p;
        v->len = last - p;

        return NGX_OK;
    }

    v->not_found = 1;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_keep_params(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_filter_params(s, v, rule, 1);
}


static ngx_int_t
ngx_stream_var_exec_remove_params(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_filter_params(s, v, rule, 0);
}


#if (NGX_CJSON)

static ngx_int_t
ngx_stream_var_exec_extract_json(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, subkey;
    cJSON                       *json, *current;
    u_char                      *json_data, *key, *result;
    ngx_uint_t                   i;
    ngx_int_t                    index;
    char                        *str;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    while (val.len && ngx_stream_var_isspace(val.data[0])) {
        val.data++;
        val.len--;
    }

    while (val.len && ngx_stream_var_isspace(val.data[val.len - 1])) {
        val.len--;
    }

    if (val.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    json_data = ngx_pnalloc(s->connection->pool, val.len + 1);
    if (json_data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(json_data, val.data, val.len);
    json_data[val.len] = '\0';

    json = cJSON_Parse((char *) json_data);
    if (json == NULL) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid json string");
        return NGX_ERROR;
    }

    current = json;

    for (i = 1; i < rule->args->nelts; i++) {

        if (ngx_stream_complex_value(s, &args[i], &subkey) != NGX_OK) {
            goto failed;
        }

        while (subkey.len && ngx_stream_var_isspace(subkey.data[0])) {
            subkey.data++;
            subkey.len--;
        }

        while (subkey.len
               && ngx_stream_var_isspace(subkey.data[subkey.len - 1]))
        {
            subkey.len--;
        }

        /* check if it's an array index like [0] or [1] */
        if (subkey.len >= 3 && subkey.data[0] == '['
            && subkey.data[subkey.len - 1] == ']')
        {
            index = ngx_atoi(subkey.data + 1, subkey.len - 2);

            if (index == NGX_ERROR) {
                goto failed;
            }

            /* check if current node is an array */
            if (!cJSON_IsArray(current)) {
                goto not_found;
            }

            /* get array item by index */
            current = cJSON_GetArrayItem(current, (int) index);
            if (current == NULL) {
                goto not_found;
            }

        } else {

            if (!cJSON_IsObject(current)) {
                goto not_found;
            }

            key = ngx_pnalloc(s->connection->pool, subkey.len + 1);
            if (key == NULL) {
                goto failed;
            }

            ngx_memcpy(key, subkey.data, subkey.len);
            key[subkey.len] = '\0';

            current = cJSON_GetObjectItem(current, (char *) key);
            if (current == NULL) {
                goto not_found;
            }
        }
    }

    /* extract the value based on type */
    if (cJSON_IsString(current)) {
        str = cJSON_GetStringValue(current);
        if (str == NULL) {
            goto not_found;
        }

        v->len = ngx_strlen(str);
        result = ngx_pnalloc(s->connection->pool, v->len);
        if (result == NULL) {
            goto failed;
        }

        ngx_memcpy(result, str, v->len);
        v->data = result;

    } else if (cJSON_IsBool(current)) {

        /* convert boolean to string */
        if (cJSON_IsTrue(current)) {
            v->len = 4;
            v->data = (u_char *) "true";

        } else {
            v->len = 5;
            v->data = (u_char *) "false";
        }

    } else if (cJSON_IsNull(current)) {

        /* null value */
        v->len = 4;
        v->data = (u_char *) "null";

    } else {

        /* for numbers, arrays, and objects */
        str = cJSON_PrintUnformatted(current);
        if (str == NULL) {
            goto failed;
        }

        v->len = ngx_strlen(str);

        result = ngx_pnalloc(s->connection->pool, v->len);
        if (result == NULL) {
            cJSON_free(str);
            goto failed;
        }

        ngx_memcpy(result, str, v->len);
        v->data = result;

        cJSON_free(str);
    }

    cJSON_Delete(json);

    return NGX_OK;

not_found:

    cJSON_Delete(json);

    v->not_found = 1;

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                  "var: extract json string failed");

    cJSON_Delete(json);

    return NGX_ERROR;
}

#endif


#if (NGX_PCRE)

static ngx_int_t
ngx_stream_var_exec_regex_capture(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t    *args;
    ngx_str_t                      val, assign_val;
    ngx_int_t                      rc;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_stream_regex_exec(s, rule->regex, &val);

    if (rc == NGX_DECLINED) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: regex match failed");
        return NGX_ERROR;
    }

    if (ngx_stream_complex_value(s, &args[1], &assign_val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = assign_val.len;
    v->data = assign_val.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_regex_sub(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t    *args;
    ngx_str_t                      val, replacement;
    ngx_int_t                      rc;
    u_char                        *p;
    ngx_uint_t                     start, end, len;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_stream_regex_exec(s, rule->regex, &val);

    if (rc == NGX_DECLINED) {
        v->len = val.len;
        v->data = val.data;
        return NGX_OK;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: regex substitution failed");
        return NGX_ERROR;
    }

    /* ensure captures are available */
    if (s->ncaptures < 2) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: insufficient captures");
        return NGX_ERROR;
    }

    if (ngx_stream_complex_value(s, &args[1], &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    start = s->captures[0];
    end = s->captures[1];

    len = start + replacement.len + (val.len - end);

    p = ngx_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    p = ngx_cpymem(p, val.data, start);
    p = ngx_cpymem(p, replacement.data, replacement.len);
    p = ngx_cpymem(p, val.data + end, val.len - end);

    v->len = p - v->data;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_stream_var_exec_abs(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_check_str_is_num(val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len > 0 && val.data[0] == '-') {
        val.data++;
        val.len--;
    }

    v->len = val.len;
    v->data = val.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_max(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    fp_val1, fp_val2;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atofp(val1, val2, &fp_val1, &fp_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: \"max\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (fp_val1 >= fp_val2) {
        v->len = val1.len;
        v->data = val1.data;

    } else {
        v->len = val2.len;
        v->data = val2.data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_min(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    fp_val1, fp_val2;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atofp(val1, val2, &fp_val1, &fp_val2)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: \"min\" failed to convert "
                      "values to fixed point");
        return NGX_ERROR;
    }

    if (fp_val1 <= fp_val2) {
        v->len = val1.len;
        v->data = val1.data;

    } else {
        v->len = val2.len;
        v->data = val2.data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_add(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val1, int_val2, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_stream_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value for \"add\" operator");
        return NGX_ERROR;
    }

    if (int_val2 > 0 && int_val1 > NGX_MAX_INT_T_VALUE - int_val2) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: integer overflow in \"add\" operator");
        return NGX_ERROR;
    }

    if (int_val2 < 0 && int_val1 < -NGX_MAX_INT_T_VALUE - int_val2) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: integer underflow in \"add\" operator");
        return NGX_ERROR;
    }

    result = int_val1 + int_val2;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_sub(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val1, int_val2, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_stream_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value for \"sub\" operator");
        return NGX_ERROR;
    }

    if (int_val2 < 0 && int_val1 > NGX_MAX_INT_T_VALUE + int_val2) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: integer overflow in \"sub\" operator");
        return NGX_ERROR;
    }

    if (int_val2 > 0 && int_val1 < -NGX_MAX_INT_T_VALUE + int_val2) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: integer underflow in \"sub\" operator");
        return NGX_ERROR;
    }

    result = int_val1 - int_val2;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_mul(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val1, int_val2, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_stream_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value for \"mul\" operator");
        return NGX_ERROR;
    }

    /* Check for multiplication overflow */
    if (int_val1 > 0) {

        if (int_val2 > 0 && int_val1 > NGX_MAX_INT_T_VALUE / int_val2) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: integer overflow in \"mul\" operator");
            return NGX_ERROR;
        }

        if (int_val2 < 0 && int_val2 < -NGX_MAX_INT_T_VALUE / int_val1) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: integer underflow in \"mul\" operator");
            return NGX_ERROR;
        }

    } else if (int_val1 < 0) {

        if (int_val2 > 0 && int_val1 < -NGX_MAX_INT_T_VALUE / int_val2) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: integer underflow in \"mul\" operator");
            return NGX_ERROR;
        }

        if (int_val2 < 0 && int_val1 < NGX_MAX_INT_T_VALUE / int_val2) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: integer overflow in \"mul\" operator");
            return NGX_ERROR;
        }
    }

    result = int_val1 * int_val2;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_div(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val1, int_val2, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_stream_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value for \"div\" operator");
        return NGX_ERROR;
    }

    /* Check for division by zero */
    if (int_val2 == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: division by zero in \"div\" operator");
        return NGX_ERROR;
    }

    result = int_val1 / int_val2;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_mod(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val1, int_val2, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_stream_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value for \"mod\" operator");
        return NGX_ERROR;
    }

    /* Check for modulo by zero */
    if (int_val2 == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: modulo by zero in \"mod\" operator");
        return NGX_ERROR;
    }

    result = int_val1 % int_val2;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_bitwise_and(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val1, int_val2, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_stream_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value");
        return NGX_ERROR;
    }

    result = int_val1 & int_val2;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_bitwise_not(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_int_t                    int_val, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val, &int_val) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value");
        return NGX_ERROR;
    }

    result = ~int_val;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_bitwise_or(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val1, int_val2, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_stream_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value");
        return NGX_ERROR;
    }

    result = int_val1 | int_val2;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_bitwise_xor(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val1, int_val2, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val1) != NGX_OK
        || ngx_stream_var_utils_auto_atoi(val2, &int_val2) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value");
        return NGX_ERROR;
    }

    result = int_val1 ^ int_val2;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_lshift(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val, shift_bits, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value");
        return NGX_ERROR;
    }

    shift_bits = ngx_atoi(val2.data, val2.len);
    if (shift_bits == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid shift bits");
        return NGX_ERROR;
    }

    if (shift_bits >= (ngx_int_t) (sizeof(ngx_int_t) * 8)) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: shift bits too large");
        return NGX_ERROR;
    }

    result = int_val << shift_bits;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_rshift(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val, shift_bits, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value");
        return NGX_ERROR;
    }

    shift_bits = ngx_atoi(val2.data, val2.len);
    if (shift_bits == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid shift bits");
        return NGX_ERROR;
    }

    if (shift_bits >= (ngx_int_t) (sizeof(ngx_int_t) * 8)) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: shift bits too large");
        return NGX_ERROR;
    }

    result = int_val >> shift_bits;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_urshift(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val1, val2;
    ngx_int_t                    int_val, shift_bits;
    ngx_uint_t                   unsigned_val, result;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val1) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val2) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_stream_var_utils_auto_atoi(val1, &int_val) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid integer value");
        return NGX_ERROR;
    }

    shift_bits = ngx_atoi(val2.data, val2.len);
    if (shift_bits == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid shift bits");
        return NGX_ERROR;
    }

    if (shift_bits >= (ngx_int_t) (sizeof(ngx_int_t) * 8)) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: shift bits too large");
        return NGX_ERROR;
    }

    unsigned_val = (ngx_uint_t) int_val;
    result = unsigned_val >> shift_bits;

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%ui", result) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_round(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, val_precision;
    ngx_int_t                    precision, i, decimal_point;
    u_char                      *num_data, *result, *p;
    size_t                       num_len, int_len, frac_len;
    ngx_int_t                    is_negative;
    u_char                      *int_part, *frac_part;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK
        || ngx_stream_complex_value(s, &args[1], &val_precision) != NGX_OK)
    {
        return NGX_ERROR;
    }

    precision = ngx_atoi(val_precision.data, val_precision.len);
    if (precision == NGX_ERROR || precision < 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid precision value for "
                      "\"round\" operator");
        return NGX_ERROR;
    }

    num_data = val.data;
    num_len = val.len;

    if (num_len == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: empty input for \"round\" operator");
        return NGX_ERROR;
    }

    /* check for negative sign */
    is_negative = 0;
    if (num_data[0] == '-') {
        is_negative = 1;
        num_data++;
        num_len--;
    }

    if (num_len == 0 || num_data[0] == '.') {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid number format");
        return NGX_ERROR;
    }

    /* find decimal point and validate */
    decimal_point = -1;

    for (i = 0; i < (ngx_int_t) num_len; i++) {

        if (num_data[i] == '.') {

            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                              "var: multiple decimal points found");
                return NGX_ERROR;
            }

            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid character in number");
            return NGX_ERROR;
        }
    }

    if (decimal_point == -1) {
        int_len = num_len;
        int_part = num_data;
        frac_len = 0;
        frac_part = NULL;

    } else {

        if (decimal_point == (ngx_int_t) (num_len - 1)) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: decimal point at the end of number");
            return NGX_ERROR;
        }

        int_len = decimal_point;
        int_part = num_data;
        frac_len = num_len - decimal_point - 1;
        frac_part = num_data + decimal_point + 1;
    }

    if (frac_len == (size_t) precision) {
        v->data = val.data;
        v->len = val.len;
        return NGX_OK;
    }

    /* truncate without rounding */
    if (frac_len > (size_t) precision && frac_part[precision] < '5') {
        v->data = val.data;
        v->len = (is_negative ? 1 : 0) + int_len
                 + (precision > 0 ? 1 + precision : 0);
        return NGX_OK;
    }

    /* pad with zeros */
    if (frac_len < (size_t) precision) {
        /* calculate how many characters to add */
        i = (decimal_point == -1)
            ? (1 + precision) : (precision - (ngx_int_t) frac_len);

        result = ngx_palloc(s->connection->pool, val.len + i + 1);
        if (result == NULL) {
            return NGX_ERROR;
        }

        p = ngx_cpymem(result, val.data, val.len);

        if (decimal_point == -1) {
            *p++ = '.';
        }

        ngx_memset(p, '0', precision - frac_len);

        v->len = val.len + i;
        v->data = result;
        return NGX_OK;
    }

    /* need to round up */
    result = ngx_palloc(s->connection->pool, val.len + 2);
    if (result == NULL) {
        return NGX_ERROR;
    }

    /* reserve first byte for potential '1', build starting at result + 1 */
    p = result + 1;
    if (is_negative) {
        *p++ = '-';
    }

    p = ngx_cpymem(p, int_part, int_len);

    if (precision > 0) {
        *p++ = '.';
        p = ngx_cpymem(p, frac_part, precision);
    }

    /* remember the end position */
    i = p - result;

    /* apply carry from right to left */
    p--;
    while (p > result) {
        if (*p == '.' || *p == '-') {
            p--;
            continue;
        }

        if (*p < '9') {
            (*p)++;
            v->data = result + 1;
            v->len = i - 1;
            return NGX_OK;
        }

        *p = '0';
        p--;
    }

    /* overflow: prepend '1' */
    if (is_negative) {
        /* for negative: copy '-' to reserved byte, insert '1' after */
        result[0] = result[1];  /* copy '-' */
        result[1] = '1';
        v->data = result;
        v->len = i;

    } else {
        /* for positive: use reserved byte */
        result[0] = '1';
        v->data = result;
        v->len = i;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_int(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_int_t                    i, decimal_point;
    u_char                      *num_data;
    size_t                       num_len;
    ngx_int_t                    is_negative;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    num_data = val.data;
    num_len = val.len;

    if (num_len == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: empty input");
        return NGX_ERROR;
    }

    /* check for negative sign */
    is_negative = 0;
    if (num_data[0] == '-') {
        is_negative = 1;
        num_data++;
        num_len--;
    }

    if (num_len == 0 || num_data[0] == '.') {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid number format");
        return NGX_ERROR;
    }

    /* find decimal point and validate */
    decimal_point = -1;

    for (i = 0; i < (ngx_int_t) num_len; i++) {

        if (num_data[i] == '.') {

            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                              "var: multiple decimal points found");
                return NGX_ERROR;
            }

            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid character in number");
            return NGX_ERROR;
        }
    }

    /* no decimal point, return as is */
    if (decimal_point == -1) {
        v->data = val.data;
        v->len = val.len;
        return NGX_OK;
    }

    /* truncate decimal part */
    v->data = val.data;
    v->len = (is_negative ? 1 : 0) + decimal_point;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_floor(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_int_t                    i, decimal_point;
    u_char                      *num_data, *result, *p;
    size_t                       num_len, int_len, frac_len;
    ngx_int_t                    is_negative;
    u_char                      *int_part, *frac_part;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    num_data = val.data;
    num_len = val.len;

    if (num_len == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: empty input for \"floor\" operator");
        return NGX_ERROR;
    }

    /* check for negative sign */
    is_negative = 0;
    if (num_data[0] == '-') {
        is_negative = 1;
        num_data++;
        num_len--;
    }

    if (num_len == 0 || num_data[0] == '.') {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid number format");
        return NGX_ERROR;
    }

    /* find decimal point and validate */
    decimal_point = -1;

    for (i = 0; i < (ngx_int_t) num_len; i++) {

        if (num_data[i] == '.') {

            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                              "var: multiple decimal points found");
                return NGX_ERROR;
            }

            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid character in number");
            return NGX_ERROR;
        }
    }

    if (decimal_point == -1) {
        v->data = val.data;
        v->len = val.len;
        return NGX_OK;
    }

    if (decimal_point == (ngx_int_t) (num_len - 1)) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: decimal point at the end of number");
        return NGX_ERROR;
    }

    int_len = decimal_point;
    int_part = num_data;
    frac_len = num_len - decimal_point - 1;
    frac_part = num_data + decimal_point + 1;

    /* positive number: truncate decimal part */
    if (!is_negative) {
        v->data = val.data;
        v->len = int_len;
        return NGX_OK;
    }

    /* check if fractional part is all zeros */
    for (i = 0; i < (ngx_int_t) frac_len; i++) {
        if (frac_part[i] != '0') {
            break;
        }
    }

    /* negative with zero fraction: truncate decimal part */
    if (i == (ngx_int_t) frac_len) {
        v->data = val.data;
        v->len = 1 + int_len;
        return NGX_OK;
    }

    /* negative with non-zero fraction: subtract 1 from absolute value */
    result = ngx_palloc(s->connection->pool, val.len + 2);
    if (result == NULL) {
        return NGX_ERROR;
    }

    /* reserve first byte for potential '1', build starting at result + 1 */
    p = result + 1;
    *p++ = '-';
    p = ngx_cpymem(p, int_part, int_len);

    /* remember the end position */
    i = p - result;

    /* add 1 to absolute value (subtract 1 from negative number) */
    p--;
    while (p > result + 1) {
        if (*p < '9') {
            (*p)++;
            v->data = result + 1;
            v->len = i - 1;
            return NGX_OK;
        }

        *p = '0';
        p--;
    }

    /* overflow: prepend '1' after '-' */
    result[0] = result[1];  /* copy '-' */
    result[1] = '1';
    v->data = result;
    v->len = i;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_ceil(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_int_t                    i, decimal_point;
    u_char                      *num_data, *result, *p;
    size_t                       num_len, int_len, frac_len;
    ngx_int_t                    is_negative;
    u_char                      *int_part, *frac_part;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    num_data = val.data;
    num_len = val.len;

    if (num_len == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: empty input for \"ceil\" operator");
        return NGX_ERROR;
    }

    /* check for negative sign */
    is_negative = 0;
    if (num_data[0] == '-') {
        is_negative = 1;
        num_data++;
        num_len--;
    }

    if (num_len == 0 || num_data[0] == '.') {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid number format");
        return NGX_ERROR;
    }

    /* find decimal point and validate */
    decimal_point = -1;

    for (i = 0; i < (ngx_int_t) num_len; i++) {

        if (num_data[i] == '.') {

            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                              "var: multiple decimal points found");
                return NGX_ERROR;
            }

            decimal_point = i;

        } else if (num_data[i] < '0' || num_data[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid character in number");
            return NGX_ERROR;
        }
    }

    if (decimal_point == -1) {
        int_len = num_len;
        int_part = num_data;
        frac_len = 0;
        frac_part = NULL;

    } else {

        if (decimal_point == (ngx_int_t) (num_len - 1)) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: decimal point at the end of number");
            return NGX_ERROR;
        }

        int_len = decimal_point;
        int_part = num_data;
        frac_len = num_len - decimal_point - 1;
        frac_part = num_data + decimal_point + 1;
    }

    /* no fractional part: return as-is */
    if (frac_len == 0) {
        v->data = val.data;
        v->len = val.len;
        return NGX_OK;
    }

    /* negative number: truncate decimal part */
    if (is_negative) {
        v->data = val.data;
        v->len = 1 + int_len;
        return NGX_OK;
    }

    /* check if fractional part is all zeros */
    for (i = 0; i < (ngx_int_t) frac_len; i++) {
        if (frac_part[i] != '0') {
            break;
        }
    }

    /* positive with zero fraction: truncate decimal part */
    if (i == (ngx_int_t) frac_len) {
        v->data = val.data;
        v->len = int_len;
        return NGX_OK;
    }

    /* positive with non-zero fraction: add 1 to absolute value */
    result = ngx_palloc(s->connection->pool, val.len + 2);
    if (result == NULL) {
        return NGX_ERROR;
    }

    /* reserve first byte for potential '1', build starting at result + 1 */
    p = result + 1;
    p = ngx_cpymem(p, int_part, int_len);

    /* remember the end position */
    i = p - result;

    /* add 1 */
    p--;
    while (p > result) {
        if (*p < '9') {
            (*p)++;
            v->data = result + 1;
            v->len = i - 1;
            return NGX_OK;
        }

        *p = '0';
        p--;
    }

    /* overflow: prepend '1' */
    result[0] = '1';
    v->data = result;
    v->len = i;

    return NGX_OK;
}


#if (nginx_version >= 1031003)

static uint64_t
ngx_stream_var_random64(void)
{
    static uint64_t  counter, key[2];

    if (counter == 0) {
#if (NGX_OPENSSL)
        if (RAND_bytes((u_char *) key, 16) != 1)
#endif
        {
            key[0] = ((uint64_t) ngx_random() << 32)
                     | (uint32_t) ngx_random();
            key[1] = ((uint64_t) ngx_random() << 32)
                     | (uint32_t) ngx_random();
            key[0] ^= (uint64_t) ngx_pid << 16;
            key[1] ^= (uint64_t) ngx_time();
        }
    }

    counter++;

    return ngx_siphash(key[0], key[1], (u_char *) &counter,
                       sizeof(counter));
}

#endif


static ngx_int_t
ngx_stream_var_exec_rand(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    str;
    ngx_int_t                    start, end, result;
    ngx_int_t                    rc;
    uint64_t                     random_value;
    u_char                      *p;

    rc = ngx_stream_var_get_cached_random(s, v, rule);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    if (rule->args->nelts == 0) {
        p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

#if (nginx_version >= 1031003)
        random_value = ngx_stream_var_random64()
                       & (uint64_t) NGX_MAX_INT_T_VALUE;
        v->len = ngx_sprintf(p, "%ui", (ngx_uint_t) random_value) - p;
#else
        v->len = ngx_sprintf(p, "%ui", ngx_random()) - p;
#endif
        v->data = p;

        return ngx_stream_var_cache_random(s, v, rule);
    }

    args = rule->args->elts;

    /* Compute the start and end values */
    if (ngx_stream_complex_value(s, &args[0], &str) != NGX_OK) {
        return NGX_ERROR;
    }

    if (str.len == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: empty argument for \"rand\"");
        return NGX_ERROR;
    }

    start = ngx_atoi(str.data, str.len);

    if (start == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid start value for \"rand\"");
        return NGX_ERROR;
    }

    if (rule->args->nelts == 2) {

        if (ngx_stream_complex_value(s, &args[1], &str) != NGX_OK) {
            return NGX_ERROR;
        }

        if (str.len == 0) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: empty argument for \"rand\"");
            return NGX_ERROR;
        }

        end = ngx_atoi(str.data, str.len);

        if (end == NGX_ERROR || start > end) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid end value for \"rand\"");
            return NGX_ERROR;
        }

    } else {
        end = start;
        start = 0;
    }

    if (start == end) {
        p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(p, "%i", start) - p;
        v->data = p;

        return ngx_stream_var_cache_random(s, v, rule);
    }

    /* Generate a random number between start and end (inclusive) */
#if (nginx_version >= 1031003)
    random_value = ngx_stream_var_random64();
#else
    random_value = ngx_random();
#endif

    result = start
             + (ngx_int_t) (random_value % ((uint64_t) end - start + 1));

    /* Allocate memory for the result string */
    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", result) - p;
    v->data = p;

    return ngx_stream_var_cache_random(s, v, rule);
}


static ngx_int_t
ngx_stream_var_exec_hexrand(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    u_char                      *p;
    ngx_str_t                    str;
    ngx_int_t                    n;
    ngx_int_t                    rc;

#if (nginx_version >= 1031003)
    uint64_t                   random_bytes[2];
#elif (NGX_OPENSSL)
    u_char                     random_bytes[16];
#endif

    rc = ngx_stream_var_get_cached_random(s, v, rule);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    if (rule->args->nelts == 0) {
        n = 32;

    } else {
        args = rule->args->elts;

        if (ngx_stream_complex_value(s, &args[0], &str) != NGX_OK) {
            return NGX_ERROR;
        }

        if (str.len == 0) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: empty argument for \"hexrand\"");
            return NGX_ERROR;
        }

        n = ngx_atoi(str.data, str.len);
        if (n == NGX_ERROR || n <= 0 || n > 32) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid length value for \"hexrand\"");
            return NGX_ERROR;
        }
    }

    p = ngx_pnalloc(s->connection->pool, 32);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = (size_t) n;
    v->data = p;

#if (nginx_version >= 1031003)

    random_bytes[0] = ngx_stream_var_random64();
    random_bytes[1] = ngx_stream_var_random64();

    ngx_hex_dump(p, (u_char *) random_bytes, 16);

#else

#if (NGX_OPENSSL)

    if (RAND_bytes(random_bytes, 16) == 1) {
        ngx_hex_dump(p, random_bytes, 16);
        return ngx_stream_var_cache_random(s, v, rule);
    }

    ngx_ssl_error(NGX_LOG_ERR, s->connection->log, 0, "RAND_bytes() failed");

#endif

    ngx_sprintf(p, "%08xD%08xD%08xD%08xD",
                (uint32_t) ngx_random(), (uint32_t) ngx_random(),
                (uint32_t) ngx_random(), (uint32_t) ngx_random());

#endif

    return ngx_stream_var_cache_random(s, v, rule);
}


static ngx_int_t
ngx_stream_var_exec_hex_encode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->len = val.len << 1;
    v->data = ngx_pnalloc(s->connection->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, val.data, val.len);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_hex_decode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    u_char                      *p;
    ngx_int_t                    n;
    size_t                       i;
    size_t                       len;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len % 2 != 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: \"hex_decode\" requires even-length string");
        return NGX_ERROR;
    }

    p = val.data;
    len = val.len >> 1;

    v->data = ngx_palloc(s->connection->pool, len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        n = ngx_hextoi(p, 2);
        if (n == NGX_ERROR || n > 255) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid value in \"hex_decode\"");
            return NGX_ERROR;
        }

        p += 2;
        v->data[i] = (u_char) n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_dec_to_hex(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_int_t                    dec;
    u_char                      *p;
    ngx_flag_t                   is_negative;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: empty input for \"dec_to_hex\"");
        return NGX_ERROR;
    }

    is_negative = 0;
    if (val.data[0] == '-') {
        is_negative = 1;
        val.data++;
        val.len--;
    }

    dec = ngx_atoi(val.data, val.len);
    if (dec == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid decimal value for \"dec_to_hex\"");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (is_negative) {
        v->len = ngx_sprintf(p, "-%xi", dec) - p;

    } else {
        v->len = ngx_sprintf(p, "%xi", dec) - p;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_hex_to_dec(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_int_t                    dec;
    u_char                      *p;
    ngx_flag_t                   is_negative;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: empty input for \"hex_to_dec\"");
        return NGX_ERROR;
    }

    is_negative = 0;
    if (val.data[0] == '-') {
        is_negative = 1;
        val.data++;
        val.len--;
    }

    dec = ngx_hextoi(val.data, val.len);
    if (dec == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid hex value for \"hex_to_dec\"");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(s->connection->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (is_negative) {
        v->len = ngx_sprintf(p, "-%i", dec) - p;

    } else {
        v->len = ngx_sprintf(p, "%i", dec) - p;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_escape_uri(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_escape_uri(s, v, rule, NGX_ESCAPE_URI);
}


static ngx_int_t
ngx_stream_var_exec_escape_args(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_escape_uri(s, v, rule, NGX_ESCAPE_ARGS);
}


static ngx_int_t
ngx_stream_var_exec_escape_uri_component(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_escape_uri(s, v, rule,
                                           NGX_ESCAPE_URI_COMPONENT);
}


static ngx_int_t
ngx_stream_var_exec_escape_html(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_escape_uri(s, v, rule, NGX_ESCAPE_HTML);
}


static ngx_int_t
ngx_stream_var_exec_unescape_uri(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    u_char                      *src, *dst, *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    p = ngx_pnalloc(s->connection->pool, val.len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    src = val.data;
    dst = p;

    ngx_unescape_uri(&dst, &src, val.len, NGX_UNESCAPE_URI);

    v->data = p;
    v->len = dst - p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_base64_encode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, dst;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    dst.len = ngx_base64_encoded_length(val.len);
    dst.data = ngx_pnalloc(s->connection->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(&dst, &val);

    v->len = dst.len;
    v->data = dst.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_base64url_encode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, dst;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    dst.len = ngx_base64_encoded_length(val.len);
    dst.data = ngx_pnalloc(s->connection->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64url(&dst, &val);

    v->len = dst.len;
    v->data = dst.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_base64_decode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, dst;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    dst.len = ngx_base64_decoded_length(val.len);
    dst.data = ngx_pnalloc(s->connection->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(&dst, &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: failed to decode base64 string");
        return NGX_ERROR;
    }

    v->len = dst.len;
    v->data = dst.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_base64url_decode(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, dst;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    dst.len = ngx_base64_decoded_length(val.len);
    dst.data = ngx_pnalloc(s->connection->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&dst, &val) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: failed to decode base64url string");
        return NGX_ERROR;
    }

    v->len = dst.len;
    v->data = dst.data;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_crc32(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    ngx_uint_t                   crc;
    u_char                      *p;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len < 64) {
        crc = ngx_crc32_short(val.data, val.len);

    } else {
        crc = ngx_crc32_long(val.data, val.len);
    }

    p = ngx_pnalloc(s->connection->pool, 8 + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%08xD", crc) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_md5(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    u_char                       hash[16];
    ngx_md5_t                    md5;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(s->connection->pool, 16 * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, val.data, val.len);
    ngx_md5_final(hash, &md5);

    ngx_hex_dump(v->data, hash, 16);
    v->len = 16 * 2;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_sha1(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val;
    u_char                       hash[20];
    ngx_sha1_t                   sha1;

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(s->connection->pool, 20 * 2);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_sha1_init(&sha1);
    ngx_sha1_update(&sha1, val.data, val.len);
    ngx_sha1_final(hash, &sha1);

    ngx_hex_dump(v->data, hash, 20);
    v->len = 20 * 2;

    return NGX_OK;
}


#if (NGX_STREAM_SSL)

static ngx_int_t
ngx_stream_var_exec_sha224(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_sha(s, v, rule, EVP_sha224(), 28);
}


static ngx_int_t
ngx_stream_var_exec_sha256(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_sha(s, v, rule, EVP_sha256(), 32);
}


static ngx_int_t
ngx_stream_var_exec_sha384(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_sha(s, v, rule, EVP_sha384(), 48);
}


static ngx_int_t
ngx_stream_var_exec_sha512(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_sha(s, v, rule, EVP_sha512(), 64);
}


static ngx_int_t
ngx_stream_var_exec_hmac_md5(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_hmac(s, v, rule, EVP_md5());
}


static ngx_int_t
ngx_stream_var_exec_hmac_sha1(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_hmac(s, v, rule, EVP_sha1());
}


static ngx_int_t
ngx_stream_var_exec_hmac_sha224(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_hmac(s, v, rule, EVP_sha224());
}


static ngx_int_t
ngx_stream_var_exec_hmac_sha256(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_hmac(s, v, rule, EVP_sha256());
}


static ngx_int_t
ngx_stream_var_exec_hmac_sha384(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_hmac(s, v, rule, EVP_sha384());
}


static ngx_int_t
ngx_stream_var_exec_hmac_sha512(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    return ngx_stream_var_utils_hmac(s, v, rule, EVP_sha512());
}

#endif


static ngx_int_t
ngx_stream_var_exec_gmt_time(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    str;
    time_t                       ts;
    u_char                      *p;
    struct tm                    tm;
    char                         buf[2048];
    char                         fmt[2048];

    args = rule->args->elts;

    if (rule->args->nelts == 1) {

        if (ngx_stream_complex_value(s, &args[0], &str) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_time();

    } else {

        if (ngx_stream_complex_value(s, &args[0], &str) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_atoi(str.data, str.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid unix_time value");
            return NGX_ERROR;
        }

        if (ngx_stream_complex_value(s, &args[1], &str) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (str.len == 9 && ngx_strncmp(str.data, "http_time", 9) == 0) {
        p = ngx_pnalloc(s->connection->pool,
                        sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_http_time(p, ts) - p;
        v->data = p;

        return NGX_OK;
    }

    if (str.len == 11 && ngx_strncmp(str.data, "cookie_time", 11) == 0) {
        p = ngx_pnalloc(s->connection->pool,
                        sizeof("Thu, 18-Nov-10 11:27:35 GMT") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_http_cookie_time(p, ts) - p;
        v->data = p;

        return NGX_OK;
    }

    if (str.len >= sizeof(fmt)) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: time format too long");
        return NGX_ERROR;
    }

    if (str.len == sizeof("%s") - 1 && str.data[0] == '%'
        && str.data[1] == 's')
    {
        v->data = ngx_pnalloc(s->connection->pool, NGX_TIME_T_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(v->data, "%T", ts) - v->data;
        return NGX_OK;
    }

    ngx_memcpy(fmt, str.data, str.len);
    fmt[str.len] = '\0';

    ngx_libc_gmtime(ts, &tm);

    v->len = strftime(buf, sizeof(buf), fmt, &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: strftime failed");
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(s->connection->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, buf, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_local_time(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    str;
    time_t                       ts;
    struct tm                    tm;
    char                         buf[2048];
    char                         fmt[2048];

    args = rule->args->elts;

    if (rule->args->nelts == 1) {

        if (ngx_stream_complex_value(s, &args[0], &str) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_time();

    } else {

        if (ngx_stream_complex_value(s, &args[0], &str) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_atoi(str.data, str.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid unix_time value");
            return NGX_ERROR;
        }

        if (ngx_stream_complex_value(s, &args[1], &str) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (str.len >= sizeof(fmt)) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: date format too long");
        return NGX_ERROR;
    }

    if (str.len == sizeof("%s") - 1 && str.data[0] == '%'
        && str.data[1] == 's')
    {
        v->data = ngx_pnalloc(s->connection->pool, NGX_TIME_T_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(v->data, "%T", ts) - v->data;

        return NGX_OK;
    }

    ngx_memcpy(fmt, str.data, str.len);
    fmt[str.len] = '\0';

    ngx_libc_localtime(ts, &tm);

    v->len = strftime(buf, sizeof(buf), fmt, &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: strftime failed");
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(s->connection->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, buf, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_unix_time(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    val, timefmt, tz;
    ngx_tm_t                     tm;
    time_t                       ts;
    ngx_int_t                    tz_offset;
    u_char                      *p;
    ngx_uint_t                   i;
    char                         buf[2048];

    args = rule->args->elts;

    if (rule->args->nelts == 0) {
        ts = ngx_time();
        goto set_unix_time;
    }

    if (rule->args->nelts == 1) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: illegal number of parameters");
        return NGX_ERROR;
    }

    if (ngx_stream_complex_value(s, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_stream_complex_value(s, &args[1], &timefmt) != NGX_OK) {
        return NGX_ERROR;
    }

    if (timefmt.len == 9 && ngx_strncmp(timefmt.data, "http_time", 9) == 0) {
        ts = ngx_parse_http_time(val.data, val.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: failed to parse http_time");
            return NGX_ERROR;
        }

        goto set_unix_time;
    }

    tz_offset = 0;

    if (rule->args->nelts == 3) {

        if (ngx_stream_complex_value(s, &args[2], &tz) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_strncasecmp(tz.data, (u_char *) "gmt", 3) != 0) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid timezone format");
            return NGX_ERROR;
        }

        tz.len = tz.len - 3;
        tz.data = tz.data + 3;

        if (tz.len != 0) {

            if (tz.len != 5 || (tz.data[0] != '+' && tz.data[0] != '-')) {
                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                              "var: invalid timezone format");
                return NGX_ERROR;
            }

            for (i = 1; i < tz.len; i++) {

                if (tz.data[i] < '0' || tz.data[i] > '9') {
                    ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                                  "var: invalid timezone offset value");
                    return NGX_ERROR;
                }
            }

            tz_offset = (tz.data[1] - '0') * 10 * 60 * 60;
            tz_offset += (tz.data[2] - '0') * 60 * 60;
            tz_offset += (tz.data[3] - '0') * 10 * 60;
            tz_offset += (tz.data[4] - '0') * 60;

            if (tz.data[0] == '-') {
                tz_offset = -tz_offset;
            }
        }
    }

    if (timefmt.len >= sizeof(buf)) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: date format too long");
        return NGX_ERROR;
    }

    ngx_memcpy(buf, timefmt.data, timefmt.len);
    buf[timefmt.len] = '\0';

    ngx_memzero(&tm, sizeof(ngx_tm_t));

    if (strptime((char *) val.data, buf, &tm) == NULL) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: failed to parse date string");
        return NGX_ERROR;
    }

    ts = timegm(&tm) - tz_offset;

set_unix_time:

    p = ngx_pnalloc(s->connection->pool, NGX_TIME_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%T", ts) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_var_exec_cidr(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, ngx_stream_var_rule_t *rule)
{
    ngx_stream_complex_value_t  *args;
    ngx_str_t                    ip, str;
    ngx_int_t                    ipv4_bits, ipv6_bits;
    in_addr_t                    ipv4_addr, network;
    u_char                      *p;

#if (NGX_HAVE_INET6)
    u_char                     ipv6_buf[16];
    struct in6_addr            ipv6_addr, ipv6_network;
    ngx_uint_t                 i, bytes, bits_in_byte;
    ngx_uint_t                 is_ipv6;
#endif

    args = rule->args->elts;

    if (ngx_stream_complex_value(s, &args[0], &ip) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_stream_complex_value(s, &args[1], &str) != NGX_OK) {
        return NGX_ERROR;
    }

    ipv4_bits = ngx_atoi(str.data, str.len);
    if (ipv4_bits == NGX_ERROR || ipv4_bits == 0 || ipv4_bits > 32) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid IPv4 network bits: \"%V\"", &str);
        return NGX_ERROR;
    }

    if (rule->args->nelts == 3) {

        if (ngx_stream_complex_value(s, &args[2], &str) != NGX_OK) {
            return NGX_ERROR;
        }

        ipv6_bits = ngx_atoi(str.data, str.len);
        if (ipv6_bits == NGX_ERROR || ipv6_bits == 0 || ipv6_bits > 128) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid IPv6 network bits: \"%V\"", &str);
            return NGX_ERROR;
        }

    } else {
        ipv6_bits = ipv4_bits;
    }

    /* try to parse as IPv4 */
    ipv4_addr = ngx_inet_addr(ip.data, ip.len);

#if (NGX_HAVE_INET6)

    is_ipv6 = 0;

    if (ipv4_addr == INADDR_NONE) {
        /* try to parse as IPv6 */
        if (ngx_inet6_addr(ip.data, ip.len, ipv6_buf) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                          "var: invalid IP address: \"%V\"", &ip);
            return NGX_ERROR;
        }

        ngx_memcpy(&ipv6_addr, ipv6_buf, sizeof(struct in6_addr));

        /* check if it's IPv4-mapped IPv6 address */
        if (IN6_IS_ADDR_V4MAPPED(&ipv6_addr)) {
            ipv4_addr = ipv6_addr.s6_addr[12] << 24;
            ipv4_addr += ipv6_addr.s6_addr[13] << 16;
            ipv4_addr += ipv6_addr.s6_addr[14] << 8;
            ipv4_addr += ipv6_addr.s6_addr[15];

        } else {
            is_ipv6 = 1;
        }
    }

    if (is_ipv6) {
        /* apply IPv6 network mask */
        ngx_memzero(&ipv6_network, sizeof(struct in6_addr));

        bytes = ipv6_bits / 8;
        bits_in_byte = ipv6_bits % 8;

        for (i = 0; i < bytes; i++) {
            ipv6_network.s6_addr[i] = ipv6_addr.s6_addr[i];
        }

        if (bits_in_byte > 0) {
            ipv6_network.s6_addr[bytes] = ipv6_addr.s6_addr[bytes]
                                          & (0xFF << (8 - bits_in_byte));
        }

        /* format as IPv6 network address */
        p = ngx_pnalloc(s->connection->pool, NGX_INET6_ADDRSTRLEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_inet6_ntop(ipv6_network.s6_addr, p, NGX_INET6_ADDRSTRLEN);
        if (v->len == 0) {
            return NGX_ERROR;
        }

        v->data = p;

        return NGX_OK;
    }

#else

    if (ipv4_addr == INADDR_NONE) {
        ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                      "var: invalid IP address: \"%V\"", &ip);
        return NGX_ERROR;
    }

#endif

    /* apply IPv4 network mask */
    ipv4_addr = ntohl(ipv4_addr);

    if (ipv4_bits == 32) {
        network = ipv4_addr;

    } else {
        network = ipv4_addr & (0xFFFFFFFF << (32 - ipv4_bits));
    }

    network = htonl(network);

    /* format as IPv4 network address */
    p = ngx_pnalloc(s->connection->pool, NGX_INET_ADDRSTRLEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_inet_ntop(AF_INET, &network, p, NGX_INET_ADDRSTRLEN);
    if (v->len == 0) {
        return NGX_ERROR;
    }

    v->data = p;

    return NGX_OK;
}
