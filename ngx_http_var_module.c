
/*
 * Copyright (C) Hanada
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <ngx_sha1.h>

#if (NGX_CONDITION)
#include <ngx_http_condition_module.h>
#endif

#if (NGX_OPENSSL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

#if (NGX_CJSON)
#include <cjson/cJSON.h>
#endif


#define NGX_HTTP_VAR_NO_ARGS   0
#define NGX_HTTP_VAR_MAX_ARGS  (ngx_uint_t) -1


#define ngx_http_var_isspace(c)                                              \
    ((c) == ' ' || (c) == '\t' || (c) == CR || (c) == LF)


typedef enum {
    NGX_HTTP_VAR_FUNC_SET = 0,
    NGX_HTTP_VAR_FUNC_LEN,
    NGX_HTTP_VAR_FUNC_UPPER,
    NGX_HTTP_VAR_FUNC_LOWER,
    NGX_HTTP_VAR_FUNC_INITCAP,
    NGX_HTTP_VAR_FUNC_TRIM,
    NGX_HTTP_VAR_FUNC_LTRIM,
    NGX_HTTP_VAR_FUNC_RTRIM,
    NGX_HTTP_VAR_FUNC_REVERSE,
    NGX_HTTP_VAR_FUNC_POSITION,
    NGX_HTTP_VAR_FUNC_REPEAT,
    NGX_HTTP_VAR_FUNC_SUBSTR,
    NGX_HTTP_VAR_FUNC_REPLACE,
    NGX_HTTP_VAR_FUNC_EXTRACT_PARAM,
    NGX_HTTP_VAR_FUNC_KEEP_PARAMS,
    NGX_HTTP_VAR_FUNC_REMOVE_PARAMS,

#if (NGX_CJSON)
    NGX_HTTP_VAR_FUNC_EXTRACT_JSON,
#endif

#if (NGX_PCRE)
    NGX_HTTP_VAR_FUNC_REGEX_CAPTURE,
    NGX_HTTP_VAR_FUNC_REGEX_SUB,
#endif

    NGX_HTTP_VAR_FUNC_ABS,
    NGX_HTTP_VAR_FUNC_MAX,
    NGX_HTTP_VAR_FUNC_MIN,
    NGX_HTTP_VAR_FUNC_ADD,
    NGX_HTTP_VAR_FUNC_SUB,
    NGX_HTTP_VAR_FUNC_MUL,
    NGX_HTTP_VAR_FUNC_DIV,
    NGX_HTTP_VAR_FUNC_MOD,
    NGX_HTTP_VAR_FUNC_BITWISE_AND,
    NGX_HTTP_VAR_FUNC_BITWISE_NOT,
    NGX_HTTP_VAR_FUNC_BITWISE_OR,
    NGX_HTTP_VAR_FUNC_BITWISE_XOR,
    NGX_HTTP_VAR_FUNC_LSHIFT,
    NGX_HTTP_VAR_FUNC_RSHIFT,
    NGX_HTTP_VAR_FUNC_URSHIFT,
    NGX_HTTP_VAR_FUNC_ROUND,
    NGX_HTTP_VAR_FUNC_TRUNC,
    NGX_HTTP_VAR_FUNC_FLOOR,
    NGX_HTTP_VAR_FUNC_CEIL,
    NGX_HTTP_VAR_FUNC_RAND,
    NGX_HTTP_VAR_FUNC_HEXRAND,

    NGX_HTTP_VAR_FUNC_HEX_ENCODE,
    NGX_HTTP_VAR_FUNC_HEX_DECODE,
    NGX_HTTP_VAR_FUNC_ITOHEX,
    NGX_HTTP_VAR_FUNC_HEXTOI,
    NGX_HTTP_VAR_FUNC_ESCAPE_URI,
    NGX_HTTP_VAR_FUNC_ESCAPE_ARGS,
    NGX_HTTP_VAR_FUNC_ESCAPE_URI_COMPONENT,
    NGX_HTTP_VAR_FUNC_ESCAPE_HTML,
    NGX_HTTP_VAR_FUNC_UNESCAPE_URI,
    NGX_HTTP_VAR_FUNC_BASE64_ENCODE,
    NGX_HTTP_VAR_FUNC_BASE64URL_ENCODE,
    NGX_HTTP_VAR_FUNC_BASE64_DECODE,
    NGX_HTTP_VAR_FUNC_BASE64URL_DECODE,

    NGX_HTTP_VAR_FUNC_CRC32,
    NGX_HTTP_VAR_FUNC_MD5,
    NGX_HTTP_VAR_FUNC_SHA1,

#if (NGX_OPENSSL)
    NGX_HTTP_VAR_FUNC_SHA224,
    NGX_HTTP_VAR_FUNC_SHA256,
    NGX_HTTP_VAR_FUNC_SHA384,
    NGX_HTTP_VAR_FUNC_SHA512,

    NGX_HTTP_VAR_FUNC_HMAC_MD5,
    NGX_HTTP_VAR_FUNC_HMAC_SHA1,
    NGX_HTTP_VAR_FUNC_HMAC_SHA224,
    NGX_HTTP_VAR_FUNC_HMAC_SHA256,
    NGX_HTTP_VAR_FUNC_HMAC_SHA384,
    NGX_HTTP_VAR_FUNC_HMAC_SHA512,
#endif

    NGX_HTTP_VAR_FUNC_GMT_TIME,
    NGX_HTTP_VAR_FUNC_LOCAL_TIME,
    NGX_HTTP_VAR_FUNC_UNIX_TIME,
    NGX_HTTP_VAR_FUNC_CIDR,

    NGX_HTTP_VAR_FUNC_UNKNOWN
} ngx_http_var_func_e;


typedef struct ngx_http_var_rule_s  ngx_http_var_rule_t;
typedef struct ngx_http_var_func_s  ngx_http_var_func_t;

typedef ngx_int_t (*ngx_http_var_func_pt)(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);


typedef struct {
    ngx_array_t                   *vars;
} ngx_http_var_conf_t;


struct ngx_http_var_rule_s {
    ngx_http_var_func_t           *func;        /* function definition */
    ngx_uint_t                     ignore_case; /* ignore case sensitivity */
    ngx_array_t                   *args;        /* function extra args */
#if (NGX_CONDITION)
    ngx_condition_expr_id_t        expr_id;     /* associated expression */
#else
    ngx_http_complex_value_t      *filter;      /* filter complex value */
    ngx_uint_t                     negative;    /* negative filter */
#endif

#if (NGX_PCRE)
    ngx_http_regex_t              *regex;       /* compiled regex */
#endif
};


typedef struct {
    ngx_str_t                      name;        /* variable name */
    ngx_int_t                      index;       /* variable index */
    ngx_array_t                   *rules;       /* variable rules */
} ngx_http_var_variable_t;


typedef struct {
    ngx_http_var_rule_t           *rule;
    ngx_str_t                      value;
} ngx_http_var_random_value_t;


typedef struct {
    ngx_uint_t                    *locked_vars;
    ngx_array_t                   *random_values;
} ngx_http_var_ctx_t;


struct ngx_http_var_func_s {
    ngx_str_t                      name;        /* function name */
    ngx_http_var_func_pt           handler;     /* function handler */
    ngx_http_var_func_e            type;        /* function type */
    ngx_uint_t                     min_args;    /* min number of arguments */
    ngx_uint_t                     max_args;    /* max number of arguments */
};


static void *ngx_http_var_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_var_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_var(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_var_parser(ngx_conf_t *cf,
    ngx_http_var_func_t *func, ngx_http_var_rule_t *rule);
static ngx_http_var_variable_t *ngx_http_var_add_variable(ngx_conf_t *cf,
    ngx_http_var_conf_t *vcf, ngx_str_t *name);
static ngx_int_t ngx_http_var_compile_value(ngx_conf_t *cf,
    ngx_str_t *value, ngx_http_complex_value_t *cv);
static ngx_int_t ngx_http_var_compile_args(ngx_conf_t *cf,
    ngx_http_var_rule_t *rule, ngx_str_t *value, ngx_uint_t nargs);
#if (NGX_PCRE)
static ngx_int_t ngx_http_var_compile_regex(ngx_conf_t *cf,
    ngx_http_var_rule_t *rule, ngx_str_t *value);
#endif

static ngx_http_var_ctx_t *ngx_http_var_get_ctx(ngx_http_request_t *r);
static ngx_int_t ngx_http_variable_acquire_lock(ngx_http_request_t *r,
    ngx_int_t index);
static void ngx_http_variable_release_lock(ngx_http_request_t *r,
    ngx_int_t index);
static ngx_int_t ngx_http_var_get_cached_random(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_cache_random(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_select_rule(ngx_http_request_t *r,
    ngx_http_var_variable_t *var, ngx_http_var_rule_t **rule);
static ngx_int_t ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_var_helper_check_str_is_num(ngx_str_t val);
static ngx_int_t ngx_http_var_helper_auto_atoi(ngx_str_t val,
    ngx_int_t *int_val);
static ngx_int_t ngx_http_var_helper_auto_atofp(ngx_str_t val1, ngx_str_t val2,
    ngx_int_t *int_val1, ngx_int_t *int_val2);
#if (nginx_version >= 1031003)
static uint64_t ngx_http_var_helper_random64(void);
#endif
static u_char *ngx_http_var_helper_strlstrn(u_char *s1, u_char *last,
    u_char *s2, size_t n);

#if (NGX_OPENSSL)
static ngx_int_t ngx_http_var_helper_sha(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule,
    const EVP_MD *evp_md, size_t len);
static ngx_int_t ngx_http_var_helper_hmac(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule,
    const EVP_MD *evp_md);
#endif

static ngx_int_t ngx_http_var_set_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_len_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_case_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_initcap_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_trim_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_reverse_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_position_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_repeat_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_substr_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_replace_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_extract_param_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_params_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);

#if (NGX_CJSON)
static ngx_int_t ngx_http_var_extract_json_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
#endif

#if (NGX_PCRE)
static ngx_int_t ngx_http_var_regex_capture_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_regex_sub_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
#endif

static ngx_int_t ngx_http_var_abs_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_minmax_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_arith_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_bitwise_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_bitwise_not_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_shift_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_round_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_rand_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_hexrand_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);

static ngx_int_t ngx_http_var_hex_encode_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_hex_decode_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_itohex_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_hextoi_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_escape_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_unescape_uri_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_base64_encode_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_base64_decode_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);

static ngx_int_t ngx_http_var_crc32_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_md5_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_sha1_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);

#if (NGX_OPENSSL)
static ngx_int_t ngx_http_var_sha_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_hmac_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
#endif

static ngx_int_t ngx_http_var_gmt_time_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_local_time_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);
static ngx_int_t ngx_http_var_unix_time_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);

static ngx_int_t ngx_http_var_cidr_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule);


static ngx_http_var_func_t  ngx_http_var_funcs[] = {
    { ngx_string("set"),
      ngx_http_var_set_handler,
      NGX_HTTP_VAR_FUNC_SET,
      1, 1 },

    { ngx_string("len"),
      ngx_http_var_len_handler,
      NGX_HTTP_VAR_FUNC_LEN,
      1, 1 },

    { ngx_string("upper"),
      ngx_http_var_case_handler,
      NGX_HTTP_VAR_FUNC_UPPER,
      1, 1 },

    { ngx_string("lower"),
      ngx_http_var_case_handler,
      NGX_HTTP_VAR_FUNC_LOWER,
      1, 1 },

    { ngx_string("initcap"),
      ngx_http_var_initcap_handler,
      NGX_HTTP_VAR_FUNC_INITCAP,
      1, 1 },

    { ngx_string("trim"),
      ngx_http_var_trim_handler,
      NGX_HTTP_VAR_FUNC_TRIM,
      1, 2 },

    { ngx_string("ltrim"),
      ngx_http_var_trim_handler,
      NGX_HTTP_VAR_FUNC_LTRIM,
      1, 2 },

    { ngx_string("rtrim"),
      ngx_http_var_trim_handler,
      NGX_HTTP_VAR_FUNC_RTRIM,
      1, 2 },

    { ngx_string("reverse"),
      ngx_http_var_reverse_handler,
      NGX_HTTP_VAR_FUNC_REVERSE,
      1, 1 },

    { ngx_string("position"),
      ngx_http_var_position_handler,
      NGX_HTTP_VAR_FUNC_POSITION,
      2, 2 },

    { ngx_string("repeat"),
      ngx_http_var_repeat_handler,
      NGX_HTTP_VAR_FUNC_REPEAT,
      2, 2 },

    { ngx_string("substr"),
      ngx_http_var_substr_handler,
      NGX_HTTP_VAR_FUNC_SUBSTR,
      2, 3 },

    { ngx_string("replace"),
      ngx_http_var_replace_handler,
      NGX_HTTP_VAR_FUNC_REPLACE,
      3, 3 },

    { ngx_string("extract_param"),
      ngx_http_var_extract_param_handler,
      NGX_HTTP_VAR_FUNC_EXTRACT_PARAM,
      4, 4 },

    { ngx_string("keep_params"),
      ngx_http_var_params_handler,
      NGX_HTTP_VAR_FUNC_KEEP_PARAMS,
      4, NGX_HTTP_VAR_MAX_ARGS },

    { ngx_string("remove_params"),
      ngx_http_var_params_handler,
      NGX_HTTP_VAR_FUNC_REMOVE_PARAMS,
      4, NGX_HTTP_VAR_MAX_ARGS },

#if (NGX_CJSON)
    { ngx_string("extract_json"),
      ngx_http_var_extract_json_handler,
      NGX_HTTP_VAR_FUNC_EXTRACT_JSON,
      2, NGX_HTTP_VAR_MAX_ARGS },
#endif

#if (NGX_PCRE)
    { ngx_string("regex_capture"),
      ngx_http_var_regex_capture_handler,
      NGX_HTTP_VAR_FUNC_REGEX_CAPTURE,
      3, 3 },

    { ngx_string("regex_sub"),
      ngx_http_var_regex_sub_handler,
      NGX_HTTP_VAR_FUNC_REGEX_SUB,
      3, 3 },
#endif

    { ngx_string("abs"),
      ngx_http_var_abs_handler,
      NGX_HTTP_VAR_FUNC_ABS,
      1, 1 },

    { ngx_string("max"),
      ngx_http_var_minmax_handler,
      NGX_HTTP_VAR_FUNC_MAX,
      2, 2 },

    { ngx_string("min"),
      ngx_http_var_minmax_handler,
      NGX_HTTP_VAR_FUNC_MIN,
      2, 2 },

    { ngx_string("add"),
      ngx_http_var_arith_handler,
      NGX_HTTP_VAR_FUNC_ADD,
      2, 2 },

    { ngx_string("sub"),
      ngx_http_var_arith_handler,
      NGX_HTTP_VAR_FUNC_SUB,
      2, 2 },

    { ngx_string("mul"),
      ngx_http_var_arith_handler,
      NGX_HTTP_VAR_FUNC_MUL,
      2, 2 },

    { ngx_string("div"),
      ngx_http_var_arith_handler,
      NGX_HTTP_VAR_FUNC_DIV,
      2, 2 },

    { ngx_string("mod"),
      ngx_http_var_arith_handler,
      NGX_HTTP_VAR_FUNC_MOD,
      2, 2 },

    { ngx_string("bitwise_and"),
      ngx_http_var_bitwise_handler,
      NGX_HTTP_VAR_FUNC_BITWISE_AND,
      2, 2 },

    { ngx_string("bitwise_not"),
      ngx_http_var_bitwise_not_handler,
      NGX_HTTP_VAR_FUNC_BITWISE_NOT,
      1, 1 },

    { ngx_string("bitwise_or"),
      ngx_http_var_bitwise_handler,
      NGX_HTTP_VAR_FUNC_BITWISE_OR,
      2, 2 },

    { ngx_string("bitwise_xor"),
      ngx_http_var_bitwise_handler,
      NGX_HTTP_VAR_FUNC_BITWISE_XOR,
      2, 2 },

    { ngx_string("lshift"),
      ngx_http_var_shift_handler,
      NGX_HTTP_VAR_FUNC_LSHIFT,
      2, 2 },

    { ngx_string("rshift"),
      ngx_http_var_shift_handler,
      NGX_HTTP_VAR_FUNC_RSHIFT,
      2, 2 },

    { ngx_string("urshift"),
      ngx_http_var_shift_handler,
      NGX_HTTP_VAR_FUNC_URSHIFT,
      2, 2 },

    { ngx_string("round"),
      ngx_http_var_round_handler,
      NGX_HTTP_VAR_FUNC_ROUND,
      2, 2 },

    { ngx_string("trunc"),
      ngx_http_var_round_handler,
      NGX_HTTP_VAR_FUNC_TRUNC,
      1, 1 },

    { ngx_string("floor"),
      ngx_http_var_round_handler,
      NGX_HTTP_VAR_FUNC_FLOOR,
      1, 1 },

    { ngx_string("ceil"),
      ngx_http_var_round_handler,
      NGX_HTTP_VAR_FUNC_CEIL,
      1, 1 },

    { ngx_string("rand"),
      ngx_http_var_rand_handler,
      NGX_HTTP_VAR_FUNC_RAND,
      NGX_HTTP_VAR_NO_ARGS, 2 },

    { ngx_string("hexrand"),
      ngx_http_var_hexrand_handler,
      NGX_HTTP_VAR_FUNC_HEXRAND,
      NGX_HTTP_VAR_NO_ARGS, 1 },

    { ngx_string("hex_encode"),
      ngx_http_var_hex_encode_handler,
      NGX_HTTP_VAR_FUNC_HEX_ENCODE,
      1, 1 },

    { ngx_string("hex_decode"),
      ngx_http_var_hex_decode_handler,
      NGX_HTTP_VAR_FUNC_HEX_DECODE,
      1, 1 },

    { ngx_string("itohex"),
      ngx_http_var_itohex_handler,
      NGX_HTTP_VAR_FUNC_ITOHEX,
      1, 1 },

    { ngx_string("hextoi"),
      ngx_http_var_hextoi_handler,
      NGX_HTTP_VAR_FUNC_HEXTOI,
      1, 1 },

    { ngx_string("escape_uri"),
      ngx_http_var_escape_handler,
      NGX_HTTP_VAR_FUNC_ESCAPE_URI,
      1, 1 },

    { ngx_string("escape_args"),
      ngx_http_var_escape_handler,
      NGX_HTTP_VAR_FUNC_ESCAPE_ARGS,
      1, 1 },

    { ngx_string("escape_uri_component"),
      ngx_http_var_escape_handler,
      NGX_HTTP_VAR_FUNC_ESCAPE_URI_COMPONENT,
      1, 1 },

    { ngx_string("escape_html"),
      ngx_http_var_escape_handler,
      NGX_HTTP_VAR_FUNC_ESCAPE_HTML,
      1, 1 },

    { ngx_string("unescape_uri"),
      ngx_http_var_unescape_uri_handler,
      NGX_HTTP_VAR_FUNC_UNESCAPE_URI,
      1, 1 },

    { ngx_string("base64_encode"),
      ngx_http_var_base64_encode_handler,
      NGX_HTTP_VAR_FUNC_BASE64_ENCODE,
      1, 1 },

    { ngx_string("base64url_encode"),
      ngx_http_var_base64_encode_handler,
      NGX_HTTP_VAR_FUNC_BASE64URL_ENCODE,
      1, 1 },

    { ngx_string("base64_decode"),
      ngx_http_var_base64_decode_handler,
      NGX_HTTP_VAR_FUNC_BASE64_DECODE,
      1, 1 },

    { ngx_string("base64url_decode"),
      ngx_http_var_base64_decode_handler,
      NGX_HTTP_VAR_FUNC_BASE64URL_DECODE,
      1, 1 },

    { ngx_string("crc32"),
      ngx_http_var_crc32_handler,
      NGX_HTTP_VAR_FUNC_CRC32,
      1, 1 },

    { ngx_string("md5"),
      ngx_http_var_md5_handler,
      NGX_HTTP_VAR_FUNC_MD5,
      1, 1 },

    { ngx_string("sha1"),
      ngx_http_var_sha1_handler,
      NGX_HTTP_VAR_FUNC_SHA1,
      1, 1 },

#if (NGX_OPENSSL)
    { ngx_string("sha224"),
      ngx_http_var_sha_handler,
      NGX_HTTP_VAR_FUNC_SHA224,
      1, 1 },

    { ngx_string("sha256"),
      ngx_http_var_sha_handler,
      NGX_HTTP_VAR_FUNC_SHA256,
      1, 1 },

    { ngx_string("sha384"),
      ngx_http_var_sha_handler,
      NGX_HTTP_VAR_FUNC_SHA384,
      1, 1 },

    { ngx_string("sha512"),
      ngx_http_var_sha_handler,
      NGX_HTTP_VAR_FUNC_SHA512,
      1, 1 },

    { ngx_string("hmac_md5"),
      ngx_http_var_hmac_handler,
      NGX_HTTP_VAR_FUNC_HMAC_MD5,
      2, 2 },

    { ngx_string("hmac_sha1"),
      ngx_http_var_hmac_handler,
      NGX_HTTP_VAR_FUNC_HMAC_SHA1,
      2, 2 },

    { ngx_string("hmac_sha224"),
      ngx_http_var_hmac_handler,
      NGX_HTTP_VAR_FUNC_HMAC_SHA224,
      2, 2 },

    { ngx_string("hmac_sha256"),
      ngx_http_var_hmac_handler,
      NGX_HTTP_VAR_FUNC_HMAC_SHA256,
      2, 2 },

    { ngx_string("hmac_sha384"),
      ngx_http_var_hmac_handler,
      NGX_HTTP_VAR_FUNC_HMAC_SHA384,
      2, 2 },

    { ngx_string("hmac_sha512"),
      ngx_http_var_hmac_handler,
      NGX_HTTP_VAR_FUNC_HMAC_SHA512,
      2, 2 },
#endif

    { ngx_string("gmt_time"),
      ngx_http_var_gmt_time_handler,
      NGX_HTTP_VAR_FUNC_GMT_TIME,
      1, 2 },

    { ngx_string("local_time"),
      ngx_http_var_local_time_handler,
      NGX_HTTP_VAR_FUNC_LOCAL_TIME,
      1, 2 },

    { ngx_string("unix_time"),
      ngx_http_var_unix_time_handler,
      NGX_HTTP_VAR_FUNC_UNIX_TIME,
      NGX_HTTP_VAR_NO_ARGS, 3 },

    { ngx_string("cidr"),
      ngx_http_var_cidr_handler,
      NGX_HTTP_VAR_FUNC_CIDR,
      2, 3 },

    { ngx_null_string,
      NULL,
      NGX_HTTP_VAR_FUNC_UNKNOWN,
      NGX_HTTP_VAR_NO_ARGS, NGX_HTTP_VAR_NO_ARGS }
};


static ngx_command_t  ngx_http_var_commands[] = {

    { ngx_string("var"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
#if (NGX_CONDITION)
                        |NGX_HTTP_MAIN_WHEN_CONF|NGX_HTTP_SRV_WHEN_CONF
                        |NGX_HTTP_LOC_WHEN_CONF
#endif
                        |NGX_CONF_2MORE,
      ngx_http_var,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_var_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_var_create_loc_conf,          /* create location configuration */
    ngx_http_var_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_var_module = {
    NGX_MODULE_V1,
    &ngx_http_var_module_ctx,              /* module context */
    ngx_http_var_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
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
ngx_http_var_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_var_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_var_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->vars = NULL;

    return conf;
}


static char *
ngx_http_var_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_var_conf_t      *prev = parent;
    ngx_http_var_conf_t      *conf = child;
    ngx_http_var_variable_t  *var, *prev_var, *conf_var;
    ngx_http_var_rule_t      *rule;
    ngx_uint_t                i, j, found;

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
                           * sizeof(ngx_http_var_rule_t));

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
ngx_http_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_var_conf_t      *vcf = conf;

    ngx_str_t                *value;
    ngx_http_var_variable_t  *var;
    ngx_http_var_rule_t       parsed_rule, *rule;
    ngx_http_var_func_t      *func;

    value = cf->args->elts;

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

    for (func = ngx_http_var_funcs; func->name.len > 0; func++) {

        if (value[2].len == func->name.len
            && ngx_strncmp(value[2].data,
                           func->name.data, value[2].len) == 0)
        {
            break;
        }
    }

    if (func->name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "var: unsupported function \"%V\"",
                           &value[2]);
        return NGX_CONF_ERROR;
    }

    if (ngx_http_var_parser(cf, func, &parsed_rule) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    var = ngx_http_var_add_variable(cf, vcf, &value[1]);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    rule = ngx_array_push(var->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    *rule = parsed_rule;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_var_parser(ngx_conf_t *cf, ngx_http_var_func_t *func,
    ngx_http_var_rule_t *rule)
{
    ngx_str_t                  *value;
    ngx_uint_t                  first, last, nargs;
#if !(NGX_CONDITION)
    ngx_str_t                   filter_value;
    ngx_http_complex_value_t   *filter;
    ngx_uint_t                  negative;
#endif

    value = cf->args->elts;
    last = cf->args->nelts - 1;

#if (NGX_CONDITION)

    if (cf->args->nelts > 3
        && ((value[last].len >= 3
             && ngx_strncmp(value[last].data, "if=", 3) == 0)
            || (value[last].len >= 4
                && ngx_strncmp(value[last].data, "if!=", 4) == 0)))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[last]);
        return NGX_ERROR;
    }

    nargs = cf->args->nelts - 3;

#else

    filter = NULL;
    negative = 0;

    if (cf->args->nelts > 3
        && ((value[last].len >= 3
             && ngx_strncmp(value[last].data, "if=", 3) == 0)
            || (value[last].len >= 4
                && ngx_strncmp(value[last].data, "if!=", 4) == 0)))
    {
        if (value[last].data[2] == '=') {
            filter_value.len = value[last].len - 3;
            filter_value.data = value[last].data + 3;

        } else {
            filter_value.len = value[last].len - 4;
            filter_value.data = value[last].data + 4;
            negative = 1;
        }

        filter = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (filter == NULL) {
            return NGX_ERROR;
        }

        if (ngx_http_var_compile_value(cf, &filter_value, filter)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        nargs = cf->args->nelts - 4;
        last--;

    } else {
        nargs = cf->args->nelts - 3;
    }

#endif

    first = 3;

    ngx_memzero(rule, sizeof(ngx_http_var_rule_t));

    rule->func = func;

    if (first <= last && value[first].len == 2
        && value[first].data[0] == '-' && value[first].data[1] == 'i')
    {
        rule->ignore_case = 1;
        nargs--;
        first++;
    }

    if (nargs < func->min_args || nargs > func->max_args) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "var: invalid number of arguments "
                           "for function \"%V\"", &func->name);
        return NGX_ERROR;
    }

#if (NGX_CONDITION)
    rule->expr_id = ngx_condition_get_associated_expr_id(cf);
#else
    rule->filter = filter;
    rule->negative = negative;
#endif

#if (NGX_PCRE)

    if (func->type == NGX_HTTP_VAR_FUNC_REGEX_CAPTURE
        || func->type == NGX_HTTP_VAR_FUNC_REGEX_SUB)
    {
        return ngx_http_var_compile_regex(cf, rule, &value[first]);
    }

#endif

    return ngx_http_var_compile_args(cf, rule, &value[first], nargs);
}


static ngx_http_var_variable_t *
ngx_http_var_add_variable(ngx_conf_t *cf, ngx_http_var_conf_t *vcf,
    ngx_str_t *name)
{
    ngx_http_variable_t      *v;
    ngx_http_var_variable_t  *var;
    ngx_int_t                 index;
    ngx_uint_t                i;

    v = ngx_http_add_variable(cf, name,
                              NGX_HTTP_VAR_CHANGEABLE
                              |NGX_HTTP_VAR_NOCACHEABLE);
    if (v == NULL) {
        return NULL;
    }

    if (v->get_handler && v->get_handler != ngx_http_var_variable_handler) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "var: variable \"%V\" already "
                           "has other handler", name);
        return NULL;
    }

    index = ngx_http_get_variable_index(cf, name);
    if (index == NGX_ERROR) {
        return NULL;
    }

    if (vcf->vars == NULL) {
        vcf->vars = ngx_array_create(cf->pool, 4,
                                     sizeof(ngx_http_var_variable_t));
        if (vcf->vars == NULL) {
            return NULL;
        }
    }

    var = vcf->vars->elts;

    for (i = 0; i < vcf->vars->nelts; i++) {
        if (var[i].index == index) {
            var = &var[i];
            goto found;
        }
    }

    var = ngx_array_push(vcf->vars);
    if (var == NULL) {
        return NULL;
    }

    var->name = *name;
    var->index = index;
    var->rules = ngx_array_create(cf->pool, 4,
                                  sizeof(ngx_http_var_rule_t));
    if (var->rules == NULL) {
        return NULL;
    }

found:

    v->data = (uintptr_t) &var->index;
    v->get_handler = ngx_http_var_variable_handler;

    return var;
}


static ngx_int_t
ngx_http_var_compile_value(ngx_conf_t *cf, ngx_str_t *value,
    ngx_http_complex_value_t *cv)
{
    ngx_http_compile_complex_value_t  ccv;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ngx_memzero(cv, sizeof(ngx_http_complex_value_t));

    ccv.cf = cf;
    ccv.value = value;
    ccv.complex_value = cv;

    return ngx_http_compile_complex_value(&ccv);
}


static ngx_int_t
ngx_http_var_compile_args(ngx_conf_t *cf, ngx_http_var_rule_t *rule,
    ngx_str_t *value, ngx_uint_t nargs)
{
    ngx_http_complex_value_t  *cv;
    ngx_uint_t                 i;

    rule->args = ngx_array_create(cf->pool, ngx_max(nargs, 1),
                                  sizeof(ngx_http_complex_value_t));
    if (rule->args == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < nargs; i++) {
        cv = ngx_array_push(rule->args);
        if (cv == NULL) {
            return NGX_ERROR;
        }

        if (ngx_http_var_compile_value(cf, &value[i], cv)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


#if (NGX_PCRE)

static ngx_int_t
ngx_http_var_compile_regex(ngx_conf_t *cf,
    ngx_http_var_rule_t *rule, ngx_str_t *value)
{
    ngx_http_complex_value_t  *cv;
    ngx_regex_compile_t        rc;
    ngx_str_t                  regex;
    u_char                     errstr[NGX_MAX_CONF_ERRSTR];

    rule->args = ngx_array_create(cf->pool, 2,
                                  sizeof(ngx_http_complex_value_t));
    if (rule->args == NULL) {
        return NGX_ERROR;
    }

    cv = ngx_array_push(rule->args);
    if (cv == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_var_compile_value(cf, &value[0], cv)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (rule->func->type == NGX_HTTP_VAR_FUNC_REGEX_SUB) {
        regex.len = value[1].len + 2;
        regex.data = ngx_pnalloc(cf->pool, regex.len);
        if (regex.data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(regex.data, value[1].data, value[1].len);
        ngx_memcpy(regex.data + value[1].len, "()", 2);

    } else {
        regex = value[1];
    }

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern = regex;
    rc.pool = cf->pool;
    rc.err.len = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (rule->ignore_case) {
        rc.options = NGX_REGEX_CASELESS;
    }

    rule->regex = ngx_http_regex_compile(cf, &rc);
    if (rule->regex == NULL) {
        return NGX_ERROR;
    }

    cv = ngx_array_push(rule->args);
    if (cv == NULL) {
        return NGX_ERROR;
    }

    return ngx_http_var_compile_value(cf, &value[2], cv);
}

#endif


static ngx_http_var_ctx_t *
ngx_http_var_get_ctx(ngx_http_request_t *r)
{
    ngx_http_core_main_conf_t  *cmcf;

    ngx_http_var_ctx_t  *ctx;

    /* attempt to get the current request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_var_module);
    if (ctx != NULL) {
        return ctx;
    }

    /* if the context does not exist, create and attach it to the request */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_var_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    /* initialize the variable lock array */
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    ctx->locked_vars = ngx_pcalloc(r->pool,
        cmcf->variables.nelts * sizeof(ngx_uint_t));
    if (ctx->locked_vars == NULL) {
        return NULL;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_var_module);

    return ctx;
}


static ngx_int_t
ngx_http_variable_acquire_lock(ngx_http_request_t *r, ngx_int_t index)
{
    ngx_http_var_ctx_t       *ctx;

    /* get or create the context */
    ctx = ngx_http_var_get_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    /* check if it is already locked */
    if (ctx->locked_vars[index] == 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "var: circular reference detected "
                      "for variable index %ui", index);
        return NGX_ERROR;
    }

    /* mark the variable as locked */
    ctx->locked_vars[index] = 1;

    return NGX_OK;
}


static void
ngx_http_variable_release_lock(ngx_http_request_t *r, ngx_int_t index)
{
    ngx_http_var_ctx_t       *ctx;

    /* get the current request context */
    ctx = ngx_http_get_module_ctx(r, ngx_http_var_module);
    if (ctx == NULL) {
        return;
    }

    /* clear the lock mark */
    ctx->locked_vars[index] = 0;
}


static ngx_int_t
ngx_http_var_get_cached_random(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_uint_t                     i;
    ngx_http_var_ctx_t            *ctx;
    ngx_http_var_random_value_t   *values;

    ctx = ngx_http_var_get_ctx(r);
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
ngx_http_var_cache_random(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_var_ctx_t           *ctx;
    ngx_http_var_random_value_t  *value;

    ctx = ngx_http_var_get_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->random_values == NULL) {
        ctx->random_values = ngx_array_create(r->pool, 2,
                                      sizeof(ngx_http_var_random_value_t));
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
ngx_http_var_select_rule(ngx_http_request_t *r,
    ngx_http_var_variable_t *var, ngx_http_var_rule_t **rule)
{
    ngx_http_var_rule_t        *rules;
    ngx_uint_t                  i;
#if !(NGX_CONDITION)
    ngx_str_t                   val;
#endif

    rules = var->rules->elts;

    for (i = 0; i < var->rules->nelts; i++) {

#if (NGX_CONDITION)
        if (ngx_http_condition_get_expr_result(r, rules[i].expr_id)
            != NGX_CONDITION_EXPR_HIT)
        {
            continue;
        }
#else
        if (rules[i].filter) {

            if (ngx_http_complex_value(r, rules[i].filter, &val)
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
ngx_http_var_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_var_conf_t          *vcf;
    ngx_http_var_variable_t      *var, *vars;
    ngx_http_var_rule_t          *rule;
    ngx_int_t                     index;
    ngx_int_t                     rc;
    ngx_uint_t                    i;

    vcf = ngx_http_get_module_loc_conf(r, ngx_http_var_module);

    if (vcf == NULL || vcf->vars == NULL || vcf->vars->nelts == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
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
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "var: variable \"%V\" definition found",
                       &vars[i].name);

        var = &vars[i];
        break;
    }

    if (var == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    rc = ngx_http_var_select_rule(r, var, &rule);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "var: evaluating the expression of variable \"%V\"",
                   &var->name);

    /* acquire lock for variable to avoid loopback exception */
    if (ngx_http_variable_acquire_lock(r, var->index) != NGX_OK) {
        v->not_found = 1;
        return NGX_ERROR;
    }

    /* evaluate the variable expression */
    rc = rule->func->handler(r, v, rule);

    /* evaluation is complete, release the lock */
    ngx_http_variable_release_lock(r, var->index);

    if (rc != NGX_OK) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "var: evaluated variable \"%V\", "
                   "length: %uz, value: \"%*s\"",
                   &var->name, v->len, v->len, v->data);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_helper_check_str_is_num(ngx_str_t val)
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
ngx_http_var_helper_auto_atoi(ngx_str_t val, ngx_int_t *int_val)
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
ngx_http_var_helper_auto_atofp(ngx_str_t val1, ngx_str_t val2,
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


#if (nginx_version >= 1031003)

static uint64_t
ngx_http_var_helper_random64(void)
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


/*
 * same as ngx_strlcasestrn(), but case-sensitive.
 * ngx_http_var_helper_strlstrn() is intended to search for static substring
 * with known length in string until the argument last. The argument n
 * must be length of the second substring - 1.
 */
static u_char *
ngx_http_var_helper_strlstrn(u_char *s1, u_char *last, u_char *s2, size_t n)
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


#if (NGX_OPENSSL)

static ngx_int_t
ngx_http_var_helper_sha(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule,
    const EVP_MD *evp_md, size_t hash_len)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    EVP_MD_CTX                *md;
    u_char                     hash[EVP_MAX_MD_SIZE];

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    md = EVP_MD_CTX_create();
    if (md == NULL) {
        return NGX_ERROR;
    }

    if (EVP_DigestInit_ex(md, evp_md, NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestInit_ex() failed");
        goto failed;
    }

    if (EVP_DigestUpdate(md, val.data, val.len) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestUpdate() failed");
        goto failed;
    }

    if (EVP_DigestFinal_ex(md, hash, NULL) == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "EVP_DigestFinal_ex() failed");
        goto failed;
    }

    EVP_MD_CTX_destroy(md);

    v->data = ngx_pnalloc(r->pool, hash_len * 2);
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
ngx_http_var_helper_hmac(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule,
    const EVP_MD *evp_md)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val_src, val_secret;
    unsigned int               md_len;
    unsigned char              md[EVP_MAX_MD_SIZE];

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val_src) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &val_secret) != NGX_OK) {
        return NGX_ERROR;
    }

    md_len = 0;

    HMAC(evp_md, val_secret.data, val_secret.len,
         val_src.data, val_src.len, md, &md_len);

    if (md_len == 0 || md_len > EVP_MAX_MD_SIZE) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, md_len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, &md, md_len);
    v->len = md_len;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_var_set_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;
    v->data = val.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_len_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *p;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%uz", val.len) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_case_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_uint_t                 i;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;

    if (v->len == 0) {
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    if (rule->func->type == NGX_HTTP_VAR_FUNC_UPPER) {
        for (i = 0; i < v->len; i++) {
            v->data[i] = ngx_toupper(val.data[i]);
        }

    } else {
        for (i = 0; i < v->len; i++) {
            v->data[i] = ngx_tolower(val.data[i]);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_initcap_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_uint_t                 i, in_word;
    u_char                     c;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;

    if (v->len == 0) {
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
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
ngx_http_var_trim_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, trim;
    u_char                    *start, *end;
    ngx_uint_t                 trim_left, trim_right;

    switch (rule->func->type) {

    case NGX_HTTP_VAR_FUNC_TRIM:
        trim_left = 1;
        trim_right = 1;
        break;

    case NGX_HTTP_VAR_FUNC_LTRIM:
        trim_left = 1;
        trim_right = 0;
        break;

    case NGX_HTTP_VAR_FUNC_RTRIM:
        trim_left = 0;
        trim_right = 1;
        break;

    default:
        return NGX_ERROR;
    }

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
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

        if (ngx_http_complex_value(r, &args[1], &trim) != NGX_OK) {
            return NGX_ERROR;
        }

        if (trim.len != 1) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid trim char");
            return NGX_ERROR;
        }

        if (trim_left) {
            while (start <= end && *start == trim.data[0]) {
                start++;
            }
        }

        if (trim_right) {
            while (end >= start && *end == trim.data[0]) {
                end--;
            }
        }

    } else {

        if (trim_left) {
            while (start <= end && ngx_http_var_isspace(*start)) {
                start++;
            }
        }

        if (trim_right) {
            while (end >= start && ngx_http_var_isspace(*end)) {
                end--;
            }
        }
    }

    v->data = start;
    v->len = (end >= start) ? (size_t) (end - start + 1) : 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_reverse_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *p, *q;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = val.len;

    if (v->len == 0) {
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
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
ngx_http_var_position_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, needle;
    u_char                    *p, *found;
    ngx_int_t                  pos;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &needle) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Empty substring is found at position 1 */
    if (needle.len == 0) {
        pos = 1;
        goto format_position;
    }

    /* Non-empty substring not found in empty string */
    if (val.len == 0 || needle.len > val.len) {
        pos = 0;
        goto format_position;
    }

    /* Search for substring */
    if (rule->ignore_case) {
        found = ngx_strlcasestrn(val.data, val.data + val.len,
                                 needle.data, needle.len - 1);

    } else {
        found = ngx_http_var_helper_strlstrn(val.data, val.data + val.len,
                                             needle.data, needle.len - 1);
    }

    if (found != NULL) {
        pos = (ngx_int_t) (found - val.data) + 1;

    } else {
        pos = 0;
    }

format_position:

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", pos) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_repeat_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, count;
    ngx_int_t                  n;
    u_char                    *p;
    ngx_uint_t                 i;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &count) != NGX_OK)
    {
        return NGX_ERROR;
    }

    n = ngx_atoi(count.data, count.len);
    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid repeat times \"%V\"", &count);
        return NGX_ERROR;
    }

    if (n == 0 || val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, val.len * n);
    if (p == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < (ngx_uint_t) n; i++) {
        ngx_memcpy(p + i * val.len, val.data, val.len);
    }

    v->len = val.len * (ngx_uint_t) n;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_substr_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, start_arg, length_arg;
    ngx_int_t                  start, len;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &start_arg) != NGX_OK)
    {
        return NGX_ERROR;
    }

    start = ngx_atoi(start_arg.data, start_arg.len);
    if (start == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid start \"%V\" in substr", &start_arg);
        return NGX_ERROR;
    }

    if ((ngx_uint_t) start >= val.len) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    if (rule->args->nelts == 3
        && ngx_http_complex_value(r, &args[2], &length_arg) == NGX_OK)
    {
        len = ngx_atoi(length_arg.data, length_arg.len);
        if (len == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid length \"%V\" in substr",
                          &length_arg);
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
ngx_http_var_replace_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, search, replacement;
    u_char                    *p, *q;
    size_t                     count, new_len;
    ngx_uint_t                 i;
    ngx_int_t                  rc;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &search) != NGX_OK
        || ngx_http_complex_value(r, &args[2], &replacement) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (search.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: search string is empty in replace");
        return NGX_ERROR;
    }

    /* count occurrences */
    count = 0;
    p = val.data;

    for (i = 0; i <= val.len - search.len; /* void */ ) {

        if (rule->ignore_case) {
            rc = ngx_strncasecmp(p + i, search.data, search.len);

        } else {
            rc = ngx_strncmp(p + i, search.data, search.len);
        }

        if (rc == 0) {
            count++;
            i += search.len;

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
    new_len = val.len + count * (replacement.len - search.len);

    if (new_len > NGX_MAX_SIZE_T_VALUE) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: replacement result too large");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, new_len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    /* perform replacement */
    q = p;
    i = 0;

    while (i < val.len) {

        if (i <= val.len - search.len) {

            if (rule->ignore_case) {
                rc = ngx_strncasecmp(val.data + i, search.data, search.len);

            } else {
                rc = ngx_strncmp(val.data + i, search.data, search.len);
            }

            if (rc == 0) {
                ngx_memcpy(q, replacement.data, replacement.len);
                q += replacement.len;
                i += search.len;
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
ngx_http_var_extract_param_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  name, val, separator, delimiter;
    u_char                    *p, *boundary, *last;
    u_char                     separator_char, delimiter_char;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    while (val.len && ngx_http_var_isspace(val.data[0])) {
        val.data++;
        val.len--;
    }

    while (val.len && ngx_http_var_isspace(val.data[val.len - 1])) {
        val.len--;
    }

    if (val.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, &args[1], &separator) != NGX_OK) {
        return NGX_ERROR;
    }

    if (separator.len != 1) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid separator: \"%V\"",
                      &separator);
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, &args[2], &delimiter) != NGX_OK) {
        return NGX_ERROR;
    }

    if (delimiter.len != 1) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid delimiter: \"%V\"",
                      &delimiter);
        v->not_found = 1;
        return NGX_OK;
    }

    if (ngx_http_complex_value(r, &args[3], &name) != NGX_OK) {
        return NGX_ERROR;
    }

    while (name.len && ngx_http_var_isspace(name.data[0])) {
        name.data++;
        name.len--;
    }

    while (name.len && ngx_http_var_isspace(name.data[name.len - 1])) {
        name.len--;
    }

    if (name.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    separator_char = separator.data[0];
    delimiter_char = delimiter.data[0];

    p = val.data;
    last = p + val.len;

    for ( /* void */ ; p < last; p++) {

        /* we need separator after name, so drop one char from last */

        if (rule->ignore_case) {
            p = ngx_strlcasestrn(p, last - 1, name.data, name.len - 1);

        } else {
            p = ngx_http_var_helper_strlstrn(p, last - 1, name.data,
                                            name.len - 1);
        }

        if (p == NULL) {
            v->not_found = 1;
            return NGX_OK;
        }

        if (*(p + name.len) != delimiter_char) {
            continue;
        }

        if (p > val.data) {
            boundary = p - 1;

            while (boundary > val.data && *boundary == ' ') {
                boundary--;
            }

            if (*boundary != separator_char) {
                continue;
            }
        }

        p += name.len + 1;

        boundary = ngx_strlchr(p, last, separator_char);

        if (boundary) {
            last = boundary;
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
ngx_http_var_params_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_str_t                 *key_elts;
    u_char                    *p, *last, *eq, *next_sep;
    ngx_uint_t                 j, found, first, keep;
    size_t                     len;
    u_char                    *result, *dst;
    ngx_str_t                  key;

    if (rule->func->type == NGX_HTTP_VAR_FUNC_KEEP_PARAMS) {
        keep = 1;

    } else {
        keep = 0;
    }

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Evaluate all args */
    key_elts = ngx_palloc(r->pool, rule->args->nelts * sizeof(ngx_str_t));
    if (key_elts == NULL) {
        return NGX_ERROR;
    }

    for (j = 0; j < rule->args->nelts; j++) {
        if (ngx_http_complex_value(r, &args[j], &key_elts[j]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* separator and delimiter are required */
    if (key_elts[1].len != 1) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid separator: \"%V\"",
                      &key_elts[1]);
        goto return_original;
    }

    if (key_elts[2].len != 1) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
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

        while (key.len && ngx_http_var_isspace(key.data[0])) {
            key.data++;
            key.len--;
        }

        while (key.len && ngx_http_var_isspace(key.data[key.len - 1])) {
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
    result = ngx_pnalloc(r->pool, len);
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

        while (key.len && ngx_http_var_isspace(key.data[0])) {
            key.data++;
            key.len--;
        }

        while (key.len && ngx_http_var_isspace(key.data[key.len - 1])) {
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


#if (NGX_CJSON)

static ngx_int_t
ngx_http_var_extract_json_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, path;
    cJSON                     *json, *current;
    u_char                    *json_data, *key, *result;
    ngx_uint_t                 i;
    ngx_int_t                  index;
    char                      *text;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    while (val.len && ngx_http_var_isspace(val.data[0])) {
        val.data++;
        val.len--;
    }

    while (val.len && ngx_http_var_isspace(val.data[val.len - 1])) {
        val.len--;
    }

    if (val.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    json_data = ngx_pnalloc(r->pool, val.len + 1);
    if (json_data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(json_data, val.data, val.len);
    json_data[val.len] = '\0';

    json = cJSON_Parse((char *) json_data);
    if (json == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid json string");
        return NGX_ERROR;
    }

    current = json;

    for (i = 1; i < rule->args->nelts; i++) {

        if (ngx_http_complex_value(r, &args[i], &path) != NGX_OK) {
            goto failed;
        }

        while (path.len && ngx_http_var_isspace(path.data[0])) {
            path.data++;
            path.len--;
        }

        while (path.len && ngx_http_var_isspace(path.data[path.len - 1])) {
            path.len--;
        }

        /* check if it's an array index like [0] or [1] */
        if (path.len >= 3 && path.data[0] == '['
            && path.data[path.len - 1] == ']')
        {

            index = ngx_atoi(path.data + 1, path.len - 2);

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

            key = ngx_pnalloc(r->pool, path.len + 1);
            if (key == NULL) {
                goto failed;
            }

            ngx_memcpy(key, path.data, path.len);
            key[path.len] = '\0';

            current = cJSON_GetObjectItem(current, (char *) key);
            if (current == NULL) {
                goto not_found;
            }
        }
    }

    /* extract the value based on type */
    if (cJSON_IsString(current)) {
        text = cJSON_GetStringValue(current);
        if (text == NULL) {
            goto not_found;
        }

        v->len = ngx_strlen(text);
        result = ngx_pnalloc(r->pool, v->len);
        if (result == NULL) {
            goto failed;
        }

        ngx_memcpy(result, text, v->len);
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
        text = cJSON_PrintUnformatted(current);
        if (text == NULL) {
            goto failed;
        }

        v->len = ngx_strlen(text);

        result = ngx_pnalloc(r->pool, v->len);
        if (result == NULL) {
            cJSON_free(text);
            goto failed;
        }

        ngx_memcpy(result, text, v->len);
        v->data = result;

        cJSON_free(text);
    }

    cJSON_Delete(json);

    return NGX_OK;

not_found:

    cJSON_Delete(json);

    v->not_found = 1;

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "var: extract json string failed");

    cJSON_Delete(json);

    return NGX_ERROR;
}

#endif


#if (NGX_PCRE)

static ngx_int_t
ngx_http_var_regex_capture_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t    *args;
    ngx_str_t                    val, assignment;
    ngx_int_t                    rc;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_regex_exec(r, rule->regex, &val);

    if (rc == NGX_DECLINED) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: regex match failed");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &assignment) != NGX_OK) {
        return NGX_ERROR;
    }

    v->len = assignment.len;
    v->data = assignment.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_regex_sub_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t    *args;
    ngx_str_t                    val, replacement;
    ngx_int_t                    rc;
    u_char                      *p;
    ngx_uint_t                   start, end, len;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    rc = ngx_http_regex_exec(r, rule->regex, &val);

    if (rc == NGX_DECLINED) {
        v->len = val.len;
        v->data = val.data;
        return NGX_OK;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: regex substitution failed");
        return NGX_ERROR;
    }

    /* ensure captures are available */
    if (r->ncaptures < 2) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: insufficient captures");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &replacement) != NGX_OK) {
        return NGX_ERROR;
    }

    start = r->captures[0];
    end = r->captures[1];

    len = start + replacement.len + (val.len - end);

    p = ngx_pnalloc(r->pool, len);
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
ngx_http_var_abs_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_var_helper_check_str_is_num(val) != NGX_OK) {
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
ngx_http_var_minmax_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  a, b, *result;
    ngx_int_t                  fp_a, fp_b;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &a) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &b) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_helper_auto_atofp(a, b, &fp_a, &fp_b)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: \"%V\" failed to convert values to fixed point",
                      &rule->func->name);
        return NGX_ERROR;
    }

    if (rule->func->type == NGX_HTTP_VAR_FUNC_MAX) {
        result = (fp_a >= fp_b) ? &a : &b;

    } else {
        result = (fp_a <= fp_b) ? &a : &b;
    }

    v->len = result->len;
    v->data = result->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_arith_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  left, right;
    ngx_int_t                  a, b, n;
    u_char                    *p;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &left) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &right) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_helper_auto_atoi(left, &a) != NGX_OK
        || ngx_http_var_helper_auto_atoi(right, &b) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid integer value for \"%V\" function",
                      &rule->func->name);
        return NGX_ERROR;
    }

    switch (rule->func->type) {

    case NGX_HTTP_VAR_FUNC_ADD:
        if (b > 0 && a > NGX_MAX_INT_T_VALUE - b) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: integer overflow in \"%V\" function",
                          &rule->func->name);
            return NGX_ERROR;
        }

        if (b < 0
            && a < -NGX_MAX_INT_T_VALUE - b)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: integer underflow in \"%V\" function",
                          &rule->func->name);
            return NGX_ERROR;
        }

        n = a + b;
        break;

    case NGX_HTTP_VAR_FUNC_SUB:
        if (b < 0 && a > NGX_MAX_INT_T_VALUE + b) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: integer overflow in \"%V\" function",
                          &rule->func->name);
            return NGX_ERROR;
        }

        if (b > 0
            && a < -NGX_MAX_INT_T_VALUE + b)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: integer underflow in \"%V\" function",
                          &rule->func->name);
            return NGX_ERROR;
        }

        n = a - b;
        break;

    case NGX_HTTP_VAR_FUNC_MUL:
        if (a > 0) {

            if (b > 0
                && a > NGX_MAX_INT_T_VALUE / b)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "var: integer overflow in \"%V\" function",
                              &rule->func->name);
                return NGX_ERROR;
            }

            if (b < 0
                && b < -NGX_MAX_INT_T_VALUE / a)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "var: integer underflow in \"%V\" function",
                              &rule->func->name);
                return NGX_ERROR;
            }

        } else if (a < 0) {

            if (b > 0
                && a < -NGX_MAX_INT_T_VALUE / b)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "var: integer underflow in \"%V\" function",
                              &rule->func->name);
                return NGX_ERROR;
            }

            if (b < 0
                && a < NGX_MAX_INT_T_VALUE / b)
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "var: integer overflow in \"%V\" function",
                              &rule->func->name);
                return NGX_ERROR;
            }
        }

        n = a * b;
        break;

    case NGX_HTTP_VAR_FUNC_DIV:
        if (b == 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: division by zero in \"%V\" function",
                          &rule->func->name);
            return NGX_ERROR;
        }

        n = a / b;
        break;

    case NGX_HTTP_VAR_FUNC_MOD:
        if (b == 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: modulo by zero in \"%V\" function",
                          &rule->func->name);
            return NGX_ERROR;
        }

        n = a % b;
        break;

    default:
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", n) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_bitwise_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  left, right;
    ngx_int_t                  a, b, n;
    u_char                    *p;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &left) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &right) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_helper_auto_atoi(left, &a) != NGX_OK
        || ngx_http_var_helper_auto_atoi(right, &b) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid integer value");
        return NGX_ERROR;
    }

    switch (rule->func->type) {

    case NGX_HTTP_VAR_FUNC_BITWISE_AND:
        n = a & b;
        break;

    case NGX_HTTP_VAR_FUNC_BITWISE_OR:
        n = a | b;
        break;

    case NGX_HTTP_VAR_FUNC_BITWISE_XOR:
        n = a ^ b;
        break;

    default:
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", n) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_bitwise_not_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_int_t                  n;
    u_char                    *p;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_var_helper_auto_atoi(val, &n) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid integer value");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", ~n) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_shift_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, shift;
    ngx_int_t                  n, bits;
    u_char                    *p;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK
        || ngx_http_complex_value(r, &args[1], &shift) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_var_helper_auto_atoi(val, &n) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid integer value");
        return NGX_ERROR;
    }

    bits = ngx_atoi(shift.data, shift.len);
    if (bits == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid shift bits");
        return NGX_ERROR;
    }

    if (bits >= (ngx_int_t) (sizeof(ngx_int_t) * 8)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: shift bits too large");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    switch (rule->func->type) {

    case NGX_HTTP_VAR_FUNC_LSHIFT:
        v->len = ngx_sprintf(p, "%i", n << bits) - p;
        break;

    case NGX_HTTP_VAR_FUNC_RSHIFT:
        v->len = ngx_sprintf(p, "%i", n >> bits) - p;
        break;

    case NGX_HTTP_VAR_FUNC_URSHIFT:
        v->len = ngx_sprintf(p, "%ui",
                             (ngx_uint_t) n >> bits)
                 - p;
        break;

    default:
        return NGX_ERROR;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_round_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, precision_arg;
    ngx_int_t                  precision, i, decimal_point;
    ngx_uint_t                 is_negative, fraction_is_zero;
    u_char                    *number, *result, *p;
    size_t                     number_len, integer_len, fraction_len;
    u_char                    *integer, *fraction;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    precision = 0;

    if (rule->func->type == NGX_HTTP_VAR_FUNC_ROUND) {

        if (ngx_http_complex_value(r, &args[1], &precision_arg) != NGX_OK) {
            return NGX_ERROR;
        }

        precision = ngx_atoi(precision_arg.data, precision_arg.len);
        if (precision == NGX_ERROR || precision < 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid precision value for "
                          "\"round\" function");
            return NGX_ERROR;
        }
    }

    number = val.data;
    number_len = val.len;

    if (number_len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: empty input for \"%V\" function",
                      &rule->func->name);
        return NGX_ERROR;
    }

    is_negative = 0;

    if (number[0] == '-') {
        is_negative = 1;
        number++;
        number_len--;
    }

    if (number_len == 0 || number[0] == '.') {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid number format");
        return NGX_ERROR;
    }

    decimal_point = -1;

    for (i = 0; i < (ngx_int_t) number_len; i++) {

        if (number[i] == '.') {

            if (decimal_point != -1) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "var: multiple decimal points found");
                return NGX_ERROR;
            }

            decimal_point = i;

        } else if (number[i] < '0' || number[i] > '9') {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid character in number");
            return NGX_ERROR;
        }
    }

    if (decimal_point == -1) {
        integer_len = number_len;
        integer = number;
        fraction_len = 0;
        fraction = NULL;

    } else {

        if (decimal_point == (ngx_int_t) (number_len - 1)
            && rule->func->type != NGX_HTTP_VAR_FUNC_TRUNC)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: decimal point at the end of number");
            return NGX_ERROR;
        }

        integer_len = decimal_point;
        integer = number;
        fraction_len = number_len - decimal_point - 1;
        fraction = number + decimal_point + 1;
    }

    if (rule->func->type == NGX_HTTP_VAR_FUNC_TRUNC) {

        if (decimal_point == -1) {
            v->data = val.data;
            v->len = val.len;

        } else {
            v->data = val.data;
            v->len = (is_negative ? 1 : 0) + integer_len;
        }

        return NGX_OK;
    }

    if (rule->func->type == NGX_HTTP_VAR_FUNC_ROUND) {

        if (fraction_len == (size_t) precision) {
            v->data = val.data;
            v->len = val.len;
            return NGX_OK;
        }

        if (fraction_len > (size_t) precision && fraction[precision] < '5') {
            v->data = val.data;
            v->len = (is_negative ? 1 : 0) + integer_len
                     + (precision > 0 ? 1 + precision : 0);
            return NGX_OK;
        }

        if (fraction_len < (size_t) precision) {
            i = (decimal_point == -1)
                ? (1 + precision) : (precision - (ngx_int_t) fraction_len);

            result = ngx_palloc(r->pool, val.len + i + 1);
            if (result == NULL) {
                return NGX_ERROR;
            }

            p = ngx_cpymem(result, val.data, val.len);

            if (decimal_point == -1) {
                *p++ = '.';
            }

            ngx_memset(p, '0', precision - fraction_len);

            v->len = val.len + i;
            v->data = result;
            return NGX_OK;
        }

        result = ngx_palloc(r->pool, val.len + 2);
        if (result == NULL) {
            return NGX_ERROR;
        }

        p = result + 1;

        if (is_negative) {
            *p++ = '-';
        }

        p = ngx_cpymem(p, integer, integer_len);

        if (precision > 0) {
            *p++ = '.';
            p = ngx_cpymem(p, fraction, precision);
        }

        i = p - result;
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

        if (is_negative) {
            result[0] = result[1];
            result[1] = '1';
            v->data = result;
            v->len = i;

        } else {
            result[0] = '1';
            v->data = result;
            v->len = i;
        }

        return NGX_OK;
    }

    if (rule->func->type != NGX_HTTP_VAR_FUNC_FLOOR
        && rule->func->type != NGX_HTTP_VAR_FUNC_CEIL)
    {
        return NGX_ERROR;
    }

    if (fraction_len == 0) {
        v->data = val.data;
        v->len = val.len;
        return NGX_OK;
    }

    fraction_is_zero = 1;

    for (i = 0; i < (ngx_int_t) fraction_len; i++) {

        if (fraction[i] != '0') {
            fraction_is_zero = 0;
            break;
        }
    }

    if (fraction_is_zero
        || (rule->func->type == NGX_HTTP_VAR_FUNC_FLOOR && !is_negative)
        || (rule->func->type == NGX_HTTP_VAR_FUNC_CEIL && is_negative))
    {
        v->data = val.data;
        v->len = (is_negative ? 1 : 0) + integer_len;
        return NGX_OK;
    }

    result = ngx_palloc(r->pool, val.len + 2);
    if (result == NULL) {
        return NGX_ERROR;
    }

    p = result + 1;

    if (is_negative) {
        *p++ = '-';
    }

    p = ngx_cpymem(p, integer, integer_len);
    i = p - result;
    p--;

    while (p > result + (is_negative ? 1 : 0)) {

        if (*p < '9') {
            (*p)++;
            v->data = result + 1;
            v->len = i - 1;
            return NGX_OK;
        }

        *p = '0';
        p--;
    }

    if (is_negative) {
        result[0] = result[1];
        result[1] = '1';
        v->data = result;
        v->len = i;

    } else {
        result[0] = '1';
        v->data = result;
        v->len = i;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_rand_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  range;
    ngx_int_t                  start, end, n;
    ngx_int_t                  rc;
    uint64_t                   random_value;
    u_char                    *p;

    rc = ngx_http_var_get_cached_random(r, v, rule);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    if (rule->args->nelts == 0) {
        p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

#if (nginx_version >= 1031003)
        random_value = ngx_http_var_helper_random64()
                       & (uint64_t) NGX_MAX_INT_T_VALUE;
        v->len = ngx_sprintf(p, "%ui", (ngx_uint_t) random_value) - p;
#else
        v->len = ngx_sprintf(p, "%ui", ngx_random()) - p;
#endif
        v->data = p;

        return ngx_http_var_cache_random(r, v, rule);
    }

    args = rule->args->elts;

    /* Compute the start and end values */
    if (ngx_http_complex_value(r, &args[0], &range) != NGX_OK) {
        return NGX_ERROR;
    }

    if (range.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: empty argument for \"rand\"");
        return NGX_ERROR;
    }

    start = ngx_atoi(range.data, range.len);

    if (start == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid start value for \"rand\"");
        return NGX_ERROR;
    }

    if (rule->args->nelts == 2) {

        if (ngx_http_complex_value(r, &args[1], &range) != NGX_OK) {
            return NGX_ERROR;
        }

        if (range.len == 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: empty argument for \"rand\"");
            return NGX_ERROR;
        }

        end = ngx_atoi(range.data, range.len);

        if (end == NGX_ERROR || start > end) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid end value for \"rand\"");
            return NGX_ERROR;
        }

    } else {
        end = start;
        start = 0;
    }

    if (start == end) {
        p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(p, "%i", start) - p;
        v->data = p;

        return ngx_http_var_cache_random(r, v, rule);
    }

    /* Generate a random number between start and end (inclusive) */
#if (nginx_version >= 1031003)
    random_value = ngx_http_var_helper_random64();
#else
    random_value = ngx_random();
#endif

    n = start
        + (ngx_int_t) (random_value % ((uint64_t) end - start + 1));

    /* Allocate memory for the result string */
    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%i", n) - p;
    v->data = p;

    return ngx_http_var_cache_random(r, v, rule);
}


static ngx_int_t
ngx_http_var_hexrand_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    u_char                    *p;
    ngx_str_t                  length;
    ngx_int_t                  n;
    ngx_int_t                  rc;

#if (nginx_version >= 1031003)
    uint64_t                   random_bytes[2];
#elif (NGX_OPENSSL)
    u_char                     random_bytes[16];
#endif

    rc = ngx_http_var_get_cached_random(r, v, rule);
    if (rc != NGX_DECLINED) {
        return rc;
    }

    if (rule->args->nelts == 0) {
        n = 32;

    } else {
        args = rule->args->elts;

        if (ngx_http_complex_value(r, &args[0], &length) != NGX_OK) {
            return NGX_ERROR;
        }

        if (length.len == 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: empty argument for \"hexrand\"");
            return NGX_ERROR;
        }

        n = ngx_atoi(length.data, length.len);
        if (n == NGX_ERROR || n <= 0 || n > 32) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid length value for \"hexrand\"");
            return NGX_ERROR;
        }
    }

    p = ngx_pnalloc(r->pool, 32);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = (size_t) n;
    v->data = p;

#if (nginx_version >= 1031003)

    random_bytes[0] = ngx_http_var_helper_random64();
    random_bytes[1] = ngx_http_var_helper_random64();

    ngx_hex_dump(p, (u_char *) random_bytes, 16);

#else

#if (NGX_OPENSSL)

    if (RAND_bytes(random_bytes, 16) == 1) {
        ngx_hex_dump(p, random_bytes, 16);
        return ngx_http_var_cache_random(r, v, rule);
    }

    ngx_ssl_error(NGX_LOG_ERR, r->connection->log, 0, "RAND_bytes() failed");

#endif

    ngx_sprintf(p, "%08xD%08xD%08xD%08xD",
                (uint32_t) ngx_random(), (uint32_t) ngx_random(),
                (uint32_t) ngx_random(), (uint32_t) ngx_random());

#endif

    return ngx_http_var_cache_random(r, v, rule);
}


static ngx_int_t
ngx_http_var_hex_encode_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    v->len = val.len << 1;
    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(v->data, val.data, val.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_hex_decode_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *p;
    ngx_int_t                  byte;
    size_t                     i;
    size_t                     len;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len % 2 != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: \"hex_decode\" requires even-length string");
        return NGX_ERROR;
    }

    p = val.data;
    len = val.len >> 1;

    v->data = ngx_palloc(r->pool, len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        byte = ngx_hextoi(p, 2);
        if (byte == NGX_ERROR || byte > 255) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid value in \"hex_decode\"");
            return NGX_ERROR;
        }

        p += 2;
        v->data[i] = (u_char) byte;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_itohex_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_int_t                  n;
    u_char                    *p;
    ngx_flag_t                 is_negative;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: empty input for \"itohex\"");
        return NGX_ERROR;
    }

    is_negative = 0;
    if (val.data[0] == '-') {
        is_negative = 1;
        val.data++;
        val.len--;
    }

    n = ngx_atoi(val.data, val.len);
    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid decimal value for \"itohex\"");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (is_negative) {
        v->len = ngx_sprintf(p, "-%xi", n) - p;

    } else {
        v->len = ngx_sprintf(p, "%xi", n) - p;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_hextoi_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_int_t                  n;
    u_char                    *p;
    ngx_flag_t                 is_negative;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: empty input for \"hextoi\"");
        return NGX_ERROR;
    }

    is_negative = 0;
    if (val.data[0] == '-') {
        is_negative = 1;
        val.data++;
        val.len--;
    }

    n = ngx_hextoi(val.data, val.len);
    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid hex value for \"hextoi\"");
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (is_negative) {
        v->len = ngx_sprintf(p, "-%i", n) - p;

    } else {
        v->len = ngx_sprintf(p, "%i", n) - p;
    }

    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_escape_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    size_t                     len;
    uintptr_t                  escape;
    ngx_uint_t                 type;
    u_char                    *src, *dst;

    switch (rule->func->type) {

    case NGX_HTTP_VAR_FUNC_ESCAPE_URI:
        type = NGX_ESCAPE_URI;
        break;

    case NGX_HTTP_VAR_FUNC_ESCAPE_ARGS:
        type = NGX_ESCAPE_ARGS;
        break;

    case NGX_HTTP_VAR_FUNC_ESCAPE_URI_COMPONENT:
        type = NGX_ESCAPE_URI_COMPONENT;
        break;

    case NGX_HTTP_VAR_FUNC_ESCAPE_HTML:
        type = NGX_ESCAPE_HTML;
        break;

    default:
        return NGX_ERROR;
    }

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
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

    dst = ngx_pnalloc(r->pool, len);
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


static ngx_int_t
ngx_http_var_unescape_uri_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                    *src, *dst, *p;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, val.len);
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
ngx_http_var_base64_encode_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, dst;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    dst.len = ngx_base64_encoded_length(val.len);
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    if (rule->func->type == NGX_HTTP_VAR_FUNC_BASE64_ENCODE) {
        ngx_encode_base64(&dst, &val);

    } else {
        ngx_encode_base64url(&dst, &val);
    }

    v->len = dst.len;
    v->data = dst.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_base64_decode_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_int_t                  rc;
    ngx_str_t                  val, dst;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        v->len = 0;
        v->data = (u_char *) "";
        return NGX_OK;
    }

    dst.len = ngx_base64_decoded_length(val.len);
    dst.data = ngx_pnalloc(r->pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    if (rule->func->type == NGX_HTTP_VAR_FUNC_BASE64_DECODE) {
        rc = ngx_decode_base64(&dst, &val);

    } else {
        rc = ngx_decode_base64url(&dst, &val);
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: failed to decode string in \"%V\" function",
                      &rule->func->name);
        return NGX_ERROR;
    }

    v->len = dst.len;
    v->data = dst.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_crc32_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    ngx_uint_t                 crc;
    u_char                    *p;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len < 64) {
        crc = ngx_crc32_short(val.data, val.len);

    } else {
        crc = ngx_crc32_long(val.data, val.len);
    }

    p = ngx_pnalloc(r->pool, 8 + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%08xD", crc) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_md5_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                     hash[16];
    ngx_md5_t                  md5;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, 16 * 2);
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
ngx_http_var_sha1_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val;
    u_char                     hash[20];
    ngx_sha1_t                 sha1;

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, 20 * 2);
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


#if (NGX_OPENSSL)

static ngx_int_t
ngx_http_var_sha_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    const EVP_MD  *evp_md;
    size_t         hash_len;

    switch (rule->func->type) {

    case NGX_HTTP_VAR_FUNC_SHA224:
        evp_md = EVP_sha224();
        hash_len = 28;
        break;

    case NGX_HTTP_VAR_FUNC_SHA256:
        evp_md = EVP_sha256();
        hash_len = 32;
        break;

    case NGX_HTTP_VAR_FUNC_SHA384:
        evp_md = EVP_sha384();
        hash_len = 48;
        break;

    case NGX_HTTP_VAR_FUNC_SHA512:
        evp_md = EVP_sha512();
        hash_len = 64;
        break;

    default:
        return NGX_ERROR;
    }

    return ngx_http_var_helper_sha(r, v, rule, evp_md, hash_len);
}


static ngx_int_t
ngx_http_var_hmac_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    const EVP_MD  *evp_md;

    switch (rule->func->type) {

    case NGX_HTTP_VAR_FUNC_HMAC_MD5:
        evp_md = EVP_md5();
        break;

    case NGX_HTTP_VAR_FUNC_HMAC_SHA1:
        evp_md = EVP_sha1();
        break;

    case NGX_HTTP_VAR_FUNC_HMAC_SHA224:
        evp_md = EVP_sha224();
        break;

    case NGX_HTTP_VAR_FUNC_HMAC_SHA256:
        evp_md = EVP_sha256();
        break;

    case NGX_HTTP_VAR_FUNC_HMAC_SHA384:
        evp_md = EVP_sha384();
        break;

    case NGX_HTTP_VAR_FUNC_HMAC_SHA512:
        evp_md = EVP_sha512();
        break;

    default:
        return NGX_ERROR;
    }

    return ngx_http_var_helper_hmac(r, v, rule, evp_md);
}

#endif


static ngx_int_t
ngx_http_var_gmt_time_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, format;
    time_t                     ts;
    u_char                    *p;
    struct tm                  tm;
    char                       buf[2048];
    char                       fmt[2048];

    args = rule->args->elts;

    if (rule->args->nelts == 1) {

        if (ngx_http_complex_value(r, &args[0], &format) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_time();

    } else {

        if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_atoi(val.data, val.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid unix_time value");
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &args[1], &format) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (format.len == 9
        && ngx_strncmp(format.data, "http_time", 9) == 0)
    {
        p = ngx_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_http_time(p, ts) - p;
        v->data = p;

        return NGX_OK;
    }

    if (format.len == 11
        && ngx_strncmp(format.data, "cookie_time", 11) == 0)
    {
        p = ngx_pnalloc(r->pool, sizeof("Thu, 18-Nov-10 11:27:35 GMT") - 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_http_cookie_time(p, ts) - p;
        v->data = p;

        return NGX_OK;
    }

    if (format.len >= sizeof(fmt)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: time format too long");
        return NGX_ERROR;
    }

    if (format.len == sizeof("%s") - 1
        && format.data[0] == '%' && format.data[1] == 's')
    {
        v->data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(v->data, "%T", ts) - v->data;
        return NGX_OK;
    }

    ngx_memcpy(fmt, format.data, format.len);
    fmt[format.len] = '\0';

    ngx_libc_gmtime(ts, &tm);

    v->len = strftime(buf, sizeof(buf), fmt, &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: strftime failed");
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, buf, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_local_time_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, format;
    time_t                     ts;
    struct tm                  tm;
    char                       buf[2048];
    char                       fmt[2048];

    args = rule->args->elts;

    if (rule->args->nelts == 1) {

        if (ngx_http_complex_value(r, &args[0], &format) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_time();

    } else {

        if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
            return NGX_ERROR;
        }

        ts = ngx_atoi(val.data, val.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid unix_time value");
            return NGX_ERROR;
        }

        if (ngx_http_complex_value(r, &args[1], &format) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (format.len >= sizeof(fmt)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: date format too long");
        return NGX_ERROR;
    }

    if (format.len == sizeof("%s") - 1
        && format.data[0] == '%' && format.data[1] == 's')
    {
        v->data = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
        if (v->data == NULL) {
            return NGX_ERROR;
        }

        v->len = ngx_sprintf(v->data, "%T", ts) - v->data;

        return NGX_OK;
    }

    ngx_memcpy(fmt, format.data, format.len);
    fmt[format.len] = '\0';

    ngx_libc_localtime(ts, &tm);

    v->len = strftime(buf, sizeof(buf), fmt, &tm);
    if (v->len == 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: strftime failed");
        return NGX_ERROR;
    }

    v->data = ngx_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, buf, v->len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_unix_time_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  val, format, timezone;
    ngx_tm_t                   tm;
    time_t                     ts;
    ngx_int_t                  timezone_offset;
    u_char                    *p;
    ngx_uint_t                 i;
    char                       buf[2048];

    args = rule->args->elts;

    if (rule->args->nelts == 0) {
        ts = ngx_time();
        goto set_unix_time;
    }

    if (rule->args->nelts == 1) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: illegal number of parameters");
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &format) != NGX_OK) {
        return NGX_ERROR;
    }

    if (format.len == 9
        && ngx_strncmp(format.data, "http_time", 9) == 0)
    {
        ts = ngx_parse_http_time(val.data, val.len);
        if (ts == NGX_ERROR) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: failed to parse http_time");
            return NGX_ERROR;
        }

        goto set_unix_time;
    }

    timezone_offset = 0;

    if (rule->args->nelts == 3) {

        if (ngx_http_complex_value(r, &args[2], &timezone) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_strncasecmp(timezone.data, (u_char *) "gmt", 3) != 0) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid timezone format");
            return NGX_ERROR;
        }

        timezone.len = timezone.len - 3;
        timezone.data = timezone.data + 3;

        if (timezone.len != 0) {

            if (timezone.len != 5
                || (timezone.data[0] != '+' && timezone.data[0] != '-'))
            {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "var: invalid timezone format");
                return NGX_ERROR;
            }

            for (i = 1; i < timezone.len; i++) {

                if (timezone.data[i] < '0' || timezone.data[i] > '9') {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "var: invalid timezone offset value");
                    return NGX_ERROR;
                }
            }

            timezone_offset = (timezone.data[1] - '0') * 10 * 60 * 60;
            timezone_offset += (timezone.data[2] - '0') * 60 * 60;
            timezone_offset += (timezone.data[3] - '0') * 10 * 60;
            timezone_offset += (timezone.data[4] - '0') * 60;

            if (timezone.data[0] == '-') {
                timezone_offset = -timezone_offset;
            }
        }
    }

    if (format.len >= sizeof(buf)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: date format too long");
        return NGX_ERROR;
    }

    ngx_memcpy(buf, format.data, format.len);
    buf[format.len] = '\0';

    ngx_memzero(&tm, sizeof(ngx_tm_t));

    if (strptime((char *) val.data, buf, &tm) == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: failed to parse date string");
        return NGX_ERROR;
    }

    ts = timegm(&tm) - timezone_offset;

set_unix_time:

    p = ngx_pnalloc(r->pool, NGX_TIME_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%T", ts) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_var_cidr_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, ngx_http_var_rule_t *rule)
{
    ngx_http_complex_value_t  *args;
    ngx_str_t                  ip, bits;
    ngx_int_t                  ipv4_bits, ipv6_bits;
    in_addr_t                  ipv4_addr, network;
    u_char                    *p;

#if (NGX_HAVE_INET6)
    u_char                     ipv6_buf[16];
    struct in6_addr            ipv6_addr, ipv6_network;
    ngx_uint_t                 i, bytes, bits_in_byte;
    ngx_uint_t                 is_ipv6;
#endif

    args = rule->args->elts;

    if (ngx_http_complex_value(r, &args[0], &ip) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, &args[1], &bits) != NGX_OK) {
        return NGX_ERROR;
    }

    ipv4_bits = ngx_atoi(bits.data, bits.len);
    if (ipv4_bits == NGX_ERROR || ipv4_bits == 0 || ipv4_bits > 32) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "var: invalid IPv4 network bits: \"%V\"", &bits);
        return NGX_ERROR;
    }

    if (rule->args->nelts == 3) {

        if (ngx_http_complex_value(r, &args[2], &bits) != NGX_OK) {
            return NGX_ERROR;
        }

        ipv6_bits = ngx_atoi(bits.data, bits.len);
        if (ipv6_bits == NGX_ERROR || ipv6_bits == 0 || ipv6_bits > 128) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "var: invalid IPv6 network bits: \"%V\"", &bits);
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
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
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
        p = ngx_pnalloc(r->pool, NGX_INET6_ADDRSTRLEN);
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
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
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
    p = ngx_pnalloc(r->pool, NGX_INET_ADDRSTRLEN);
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
