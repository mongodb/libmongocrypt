/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "test-mongocrypt-assert-match-bson.h"
#include "test-mongocrypt-assert.h"

#ifndef _WIN32
#define MONGOCRYPT_PRINTF_FORMAT(a, b) __attribute__ ((format (__printf__, a, b)))
#else
#define MONGOCRYPT_PRINTF_FORMAT(a, b) /* no-op */
#endif

/* string comparison functions for Windows */
#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

/* The following matching logic is copied from libmongoc. */
bool
bson_init_from_value (bson_t *b, const bson_value_t *v);

char *
single_quotes_to_double (const char *str);

/* match_action_t determines if default check for a field is overridden. */
typedef enum {
   MATCH_ACTION_SKIP,    /* do not use the default check. */
   MATCH_ACTION_ABORT,   /* an error occurred, stop checking. */
   MATCH_ACTION_CONTINUE /* use the default check. */
} match_action_t;

struct _match_ctx_t;
/* doc_iter may be null if the pattern field is not found. */
typedef match_action_t (*match_visitor_fn) (struct _match_ctx_t *ctx,
                                            bson_iter_t *pattern_iter,
                                            bson_iter_t *doc_iter);

typedef struct _match_ctx_t {
   char errmsg[1000];
   bool strict_numeric_types;
   /* if retain_dots_in_keys is true, then don't consider a path with dots to
    * indicate recursing into a sub document. */
   bool retain_dots_in_keys;
   /* if allow_placeholders is true, treats 42 and "42" as placeholders. I.e.
    * comparing 42 to anything is ok. */
   bool allow_placeholders;
   /* path is the dot separated breadcrumb trail of keys. */
   char path[1000];
   /* if visitor_fn is not NULL, this is called on for every key in the pattern.
    * The returned match_action_t can override the default match behavior. */
   match_visitor_fn visitor_fn;
   void *visitor_ctx;
   /* if is_command is true, then compare the first key case insensitively. */
   bool is_command;
} match_ctx_t;

void
assert_match_bson (const bson_t *doc, const bson_t *pattern, bool is_command);

bool
match_bson (const bson_t *doc, const bson_t *pattern, bool is_command);

int64_t
bson_value_as_int64 (const bson_value_t *value);

bool
match_bson_value (const bson_value_t *doc,
                  const bson_value_t *pattern,
                  match_ctx_t *ctx);

bool
match_bson_with_ctx (const bson_t *doc,
                     const bson_t *pattern,
                     match_ctx_t *ctx);

bool
match_json (const bson_t *doc,
            bool is_command,
            const char *filename,
            int lineno,
            const char *funcname,
            const char *json_pattern,
            ...);

#define ASSERT_MATCH(doc, ...)                                                 \
   do {                                                                        \
      BSON_ASSERT (                                                            \
         match_json (doc, false, __FILE__, __LINE__, BSON_FUNC, __VA_ARGS__)); \
   } while (0)

const char *
_mongoc_bson_type_to_str (bson_type_t t);

static bool
get_exists_operator (const bson_value_t *value, bool *exists);

static bool
get_empty_operator (const bson_value_t *value, bool *exists);

static bool
get_type_operator (const bson_value_t *value, bson_type_t *out);

static bool
is_empty_doc_or_array (const bson_value_t *value);

static bool
find (bson_iter_t *iter,
      const bson_t *doc,
      const char *key,
      bool is_command,
      bool is_first,
      bool retain_dots_in_keys);


/*--------------------------------------------------------------------------
 *
 * single_quotes_to_double --
 *
 *       Copy str with single-quotes replaced by double.
 *
 * Returns:
 *       A string you must bson_free.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

char *
single_quotes_to_double (const char *str)
{
   char *result = bson_strdup (str);
   char *p;

   for (p = result; *p; p++) {
      if (*p == '\'') {
         *p = '"';
      }
   }

   return result;
}


/*--------------------------------------------------------------------------
 *
 * match_json --
 *
 *       Call match_bson on "doc" and "json_pattern".
 *       For convenience, single-quotes are synonymous with double-quotes.
 *
 *       A NULL doc or NULL json_pattern means "{}".
 *
 * Returns:
 *       True or false.
 *
 * Side effects:
 *       Logs if no match. Aborts if json is malformed.
 *
 *--------------------------------------------------------------------------
 */

MONGOCRYPT_PRINTF_FORMAT (6, 7)
bool
match_json (const bson_t *doc,
            bool is_command,
            const char *filename,
            int lineno,
            const char *funcname,
            const char *json_pattern,
            ...)
{
   va_list args;
   char *json_pattern_formatted;
   char *double_quoted;
   bson_error_t error;
   bson_t *pattern;
   match_ctx_t ctx = {{0}};
   bool matches;

   va_start (args, json_pattern);
   json_pattern_formatted =
      bson_strdupv_printf (json_pattern ? json_pattern : "{}", args);
   va_end (args);

   double_quoted = single_quotes_to_double (json_pattern_formatted);
   pattern = bson_new_from_json ((const uint8_t *) double_quoted, -1, &error);

   if (!pattern) {
      fprintf (stderr, "couldn't parse JSON: %s\n", error.message);
      abort ();
   }

   ctx.is_command = is_command;
   matches = match_bson_with_ctx (doc, pattern, &ctx);

   if (!matches) {
      char *as_string =
         doc ? bson_as_canonical_extended_json (doc, NULL) : NULL;
      fprintf (stderr,
               "ASSERT_MATCH failed with document:\n\n"
               "%s\n"
               "pattern:\n%s\n"
               "%s\n"
               "%s:%d %s()\n",
               as_string ? as_string : "{}",
               double_quoted,
               ctx.errmsg,
               filename,
               lineno,
               funcname);
      bson_free (as_string);
   }

   bson_destroy (pattern);
   bson_free (json_pattern_formatted);
   bson_free (double_quoted);

   return matches;
}


/*--------------------------------------------------------------------------
 *
 * match_bson --
 *
 *       Does "doc" match "pattern"?
 *
 *       See match_bson_with_ctx for details.
 *
 * Returns:
 *       True or false.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

bool
match_bson (const bson_t *doc, const bson_t *pattern, bool is_command)
{
   match_ctx_t ctx = {{0}};

   ctx.strict_numeric_types = true;
   ctx.is_command = is_command;

   return match_bson_with_ctx (doc, pattern, &ctx);
}


MONGOCRYPT_PRINTF_FORMAT (2, 3)
void
match_err (match_ctx_t *ctx, const char *fmt, ...)
{
   va_list args;
   char *formatted;

   BSON_ASSERT (ctx);

   va_start (args, fmt);
   formatted = bson_strdupv_printf (fmt, args);
   va_end (args);

   bson_snprintf (
      ctx->errmsg, sizeof ctx->errmsg, "%s: %s", ctx->path, formatted);

   bson_free (formatted);
}


/* When matching two docs, and preparing to recurse to match two subdocs with
 * the given key, derive context for matching them from the current context. */
static void
derive (match_ctx_t *ctx, match_ctx_t *derived, const char *key)
{
   BSON_ASSERT (ctx);
   BSON_ASSERT (derived);
   BSON_ASSERT (key);

   derived->strict_numeric_types = ctx->strict_numeric_types;

   if (strlen (ctx->path) > 0) {
      bson_snprintf (
         derived->path, sizeof derived->path, "%s.%s", ctx->path, key);
   } else {
      bson_snprintf (derived->path, sizeof derived->path, "%s", key);
   }
   derived->retain_dots_in_keys = ctx->retain_dots_in_keys;
   derived->allow_placeholders = ctx->allow_placeholders;
   derived->visitor_ctx = ctx->visitor_ctx;
   derived->visitor_fn = ctx->visitor_fn;
   derived->is_command = false;
   derived->errmsg[0] = 0;
}


/*--------------------------------------------------------------------------
 *
 * match_bson_with_ctx --
 *
 *       Does "doc" match "pattern"?
 *
 *       mongoc_matcher_t prohibits $-prefixed keys, which is something
 *       we need to test in e.g. test_mongoc_client_read_prefs, so this
 *       does *not* use mongoc_matcher_t. Instead, "doc" matches "pattern"
 *       if its key-value pairs are a simple superset of pattern's. Order
 *       matters.
 *
 *       The only special pattern syntaxes are:
 *         "field": {"$exists": true/false}
 *         "field": {"$empty": true/false}
 *         "field": {"$$type": "type string"}
 *
 *       The first key matches case-insensitively if ctx->is_command.
 *
 *       An optional match visitor (match_visitor_fn and match_visitor_ctx)
 *       can be set in ctx to provide custom matching behavior.
 *
 *       A NULL doc or NULL pattern means "{}".
 *
 * Returns:
 *       True or false.
 *
 * Side effects:
 *       None.
 *
 *--------------------------------------------------------------------------
 */

bool
match_bson_with_ctx (const bson_t *doc, const bson_t *pattern, match_ctx_t *ctx)
{
   bson_iter_t pattern_iter;
   const char *key;
   const bson_value_t *value;
   bool is_first = true;
   bool is_exists_operator;
   bool is_empty_operator;
   bool is_type_operator;
   bool exists;
   bool empty = false;
   bson_type_t bson_type = (bson_type_t) 0;
   bool found;
   bson_iter_t doc_iter;
   bson_value_t doc_value;
   match_ctx_t derived;

   if (bson_empty0 (pattern)) {
      /* matches anything */
      return true;
   }

   BSON_ASSERT (bson_iter_init (&pattern_iter, pattern));

   while (bson_iter_next (&pattern_iter)) {
      key = bson_iter_key (&pattern_iter);
      value = bson_iter_value (&pattern_iter);

      found = find (&doc_iter,
                    doc,
                    key,
                    ctx->is_command,
                    is_first,
                    ctx->retain_dots_in_keys);
      if (found) {
         bson_value_copy (bson_iter_value (&doc_iter), &doc_value);
      }

      /* is value {"$exists": true} or {"$exists": false} ? */
      is_exists_operator = get_exists_operator (value, &exists);

      /* is value {"$empty": true} or {"$empty": false} ? */
      is_empty_operator = get_empty_operator (value, &empty);

      /* is value {"$$type": "string" } ? */
      is_type_operator = get_type_operator (value, &bson_type);

      derive (ctx, &derived, key);

      if (ctx->visitor_fn) {
         match_action_t action =
            ctx->visitor_fn (ctx, &pattern_iter, found ? &doc_iter : NULL);
         if (action == MATCH_ACTION_ABORT) {
            goto fail;
         } else if (action == MATCH_ACTION_SKIP) {
            goto next;
         }
      }

      if (value->value_type == BSON_TYPE_NULL && found) {
         /* pattern has "key": null, and "key" is in doc */
         if (doc_value.value_type != BSON_TYPE_NULL) {
            match_err (&derived, "%s should be null or absent", key);
            goto fail;
         }
      } else if (is_exists_operator) {
         if (exists != found) {
            match_err (&derived, "%s found", found ? "" : "not");
            goto fail;
         }
      } else if (!found) {
         match_err (&derived, "not found");
         goto fail;
      } else if (is_empty_operator) {
         if (empty != is_empty_doc_or_array (&doc_value)) {
            match_err (&derived, "%s found", empty ? "" : " not");
            goto fail;
         }
      } else if (is_type_operator) {
         if (doc_value.value_type != bson_type) {
            match_err (&derived, "incorrect type");
            goto fail;
         }
      } else if (!match_bson_value (&doc_value, value, &derived)) {
         goto fail;
      }

   next:
      is_first = false;
      if (found) {
         bson_value_destroy (&doc_value);
      }
   }

   return true;

fail:
   if (found) {
      bson_value_destroy (&doc_value);
   }

   if (strlen (derived.errmsg) > 0) {
      memcpy (ctx->errmsg, derived.errmsg, sizeof (derived.errmsg));
   }

   return false;
}


/*--------------------------------------------------------------------------
 *
 * find --
 *
 *       Find the value for a key.
 *
 * Returns:
 *       Whether the key was found.
 *
 * Side effects:
 *       Copies the found value into "iter_out".
 *
 *--------------------------------------------------------------------------
 */

static bool
find (bson_iter_t *iter_out,
      const bson_t *doc,
      const char *key,
      bool is_command,
      bool is_first,
      bool retain_dots_in_keys)
{
   bson_iter_t iter;
   bson_iter_t descendent;

   bson_iter_init (&iter, doc);

   if (!retain_dots_in_keys && strchr (key, '.')) {
      if (!bson_iter_find_descendant (&iter, key, &descendent)) {
         return false;
      }

      memcpy (iter_out, &descendent, sizeof (bson_iter_t));
      return true;
   } else if (is_command && is_first) {
      if (!bson_iter_find_case (&iter, key)) {
         return false;
      }
   } else if (!bson_iter_find (&iter, key)) {
      return false;
   }

   memcpy (iter_out, &iter, sizeof (bson_iter_t));
   return true;
}


bool
bson_init_from_value (bson_t *b, const bson_value_t *v)
{
   BSON_ASSERT (v->value_type == BSON_TYPE_ARRAY ||
                v->value_type == BSON_TYPE_DOCUMENT);

   return bson_init_static (b, v->value.v_doc.data, v->value.v_doc.data_len);
}


static bool
_is_operator (const char *op_name, const bson_value_t *value, bool *op_val)
{
   bson_t bson;
   bson_iter_t iter;

   if (value->value_type == BSON_TYPE_DOCUMENT &&
       bson_init_from_value (&bson, value) &&
       bson_iter_init_find (&iter, &bson, op_name)) {
      *op_val = bson_iter_as_bool (&iter);
      return true;
   }

   return false;
}


/*--------------------------------------------------------------------------
 *
 * get_exists_operator --
 *
 *       Is value a subdocument like {"$exists": bool}?
 *
 * Returns:
 *       True if the value is a subdocument with the first key "$exists",
 *       or if value is BSON null.
 *
 * Side effects:
 *       If the function returns true, *exists is set to true or false,
 *       the value of the bool.
 *
 *--------------------------------------------------------------------------
 */

static bool
get_exists_operator (const bson_value_t *value, bool *exists)
{
   if (_is_operator ("$exists", value, exists)) {
      return true;
   }

   if (value->value_type == BSON_TYPE_NULL) {
      *exists = false;
      return true;
   }

   return false;
}


/*--------------------------------------------------------------------------
 *
 * get_empty_operator --
 *
 *       Is value a subdocument like {"$empty": bool}?
 *
 * Returns:
 *       True if the value is a subdocument with the first key "$empty".
 *
 * Side effects:
 *       If the function returns true, *empty is set to true or false,
 *       the value of the bool.
 *
 *--------------------------------------------------------------------------
 */

bool
get_empty_operator (const bson_value_t *value, bool *empty)
{
   return _is_operator ("$empty", value, empty);
}


/*--------------------------------------------------------------------------
 *
 * get_type_operator --
 *
 *       Is value a subdocument like {"$$type": "BSON type string"}?
 *
 * Returns:
 *       True if the value is a subdocument with the first key "$$type",
 *       and sets the @bson_type.
 *
 * Side effects:
 *       If the function returns true, *@bson_type is set.
 *
 *--------------------------------------------------------------------------
 */

static bool
get_type_operator (const bson_value_t *value, bson_type_t *out)
{
   bson_t bson;
   bson_iter_t iter;
   const char *value_string;

   /* See list of aliases on this page:
    * https://docs.mongodb.com/manual/reference/bson-types/ */
   if (value->value_type == BSON_TYPE_DOCUMENT &&
       bson_init_from_value (&bson, value) &&
       bson_iter_init_find (&iter, &bson, "$$type")) {
      value_string = bson_iter_utf8 (&iter, NULL);
      if (0 == strcasecmp ("double", value_string)) {
         *out = BSON_TYPE_DOUBLE;
      } else if (0 == strcasecmp ("string", value_string)) {
         *out = BSON_TYPE_UTF8;
      } else if (0 == strcasecmp ("object", value_string)) {
         *out = BSON_TYPE_DOCUMENT;
      } else if (0 == strcasecmp ("array", value_string)) {
         *out = BSON_TYPE_ARRAY;
      } else if (0 == strcasecmp ("binData", value_string)) {
         *out = BSON_TYPE_BINARY;
      } else if (0 == strcasecmp ("undefined", value_string)) {
         *out = BSON_TYPE_UNDEFINED;
      } else if (0 == strcasecmp ("objectId", value_string)) {
         *out = BSON_TYPE_OID;
      } else if (0 == strcasecmp ("bool", value_string)) {
         *out = BSON_TYPE_BOOL;
      } else if (0 == strcasecmp ("date", value_string)) {
         *out = BSON_TYPE_DATE_TIME;
      } else if (0 == strcasecmp ("null", value_string)) {
         *out = BSON_TYPE_NULL;
      } else if (0 == strcasecmp ("regex", value_string)) {
         *out = BSON_TYPE_REGEX;
      } else if (0 == strcasecmp ("dbPointer", value_string)) {
         *out = BSON_TYPE_DBPOINTER;
      } else if (0 == strcasecmp ("javascript", value_string)) {
         *out = BSON_TYPE_CODE;
      } else if (0 == strcasecmp ("symbol", value_string)) {
         *out = BSON_TYPE_SYMBOL;
      } else if (0 == strcasecmp ("javascriptWithScope", value_string)) {
         *out = BSON_TYPE_CODEWSCOPE;
      } else if (0 == strcasecmp ("int", value_string)) {
         *out = BSON_TYPE_INT32;
      } else if (0 == strcasecmp ("timestamp", value_string)) {
         *out = BSON_TYPE_TIMESTAMP;
      } else if (0 == strcasecmp ("long", value_string)) {
         *out = BSON_TYPE_INT64;
      } else if (0 == strcasecmp ("decimal", value_string)) {
         *out = BSON_TYPE_DECIMAL128;
      } else if (0 == strcasecmp ("minKey", value_string)) {
         *out = BSON_TYPE_MINKEY;
      } else if (0 == strcasecmp ("maxKey", value_string)) {
         *out = BSON_TYPE_MAXKEY;
      } else {
         fprintf (stderr, "unrecognized $$type value: %s\n", value_string);
         abort ();
      }
      return true;
   }

   return false;
}


/*--------------------------------------------------------------------------
 *
 * is_empty_doc_or_array --
 *
 *       Is value the subdocument {} or the array []?
 *
 *--------------------------------------------------------------------------
 */

static bool
is_empty_doc_or_array (const bson_value_t *value)
{
   bson_t doc;

   if (!(value->value_type == BSON_TYPE_ARRAY ||
         value->value_type == BSON_TYPE_DOCUMENT)) {
      return false;
   }
   BSON_ASSERT (bson_init_static (
      &doc, value->value.v_doc.data, value->value.v_doc.data_len));

   return bson_count_keys (&doc) == 0;
}


static bool
match_bson_arrays (const bson_t *array, const bson_t *pattern, match_ctx_t *ctx)
{
   uint32_t array_count;
   uint32_t pattern_count;
   bson_iter_t array_iter;
   bson_iter_t pattern_iter;
   const bson_value_t *array_value;
   const bson_value_t *pattern_value;
   match_ctx_t derived;

   array_count = bson_count_keys (array);
   pattern_count = bson_count_keys (pattern);

   if (array_count != pattern_count) {
      match_err (ctx,
                 "expected %" PRIu32 " keys, not %" PRIu32,
                 pattern_count,
                 array_count);
      return false;
   }

   BSON_ASSERT (bson_iter_init (&array_iter, array));
   BSON_ASSERT (bson_iter_init (&pattern_iter, pattern));

   while (bson_iter_next (&array_iter)) {
      BSON_ASSERT (bson_iter_next (&pattern_iter));
      array_value = bson_iter_value (&array_iter);
      pattern_value = bson_iter_value (&pattern_iter);

      derive (ctx, &derived, bson_iter_key (&array_iter));

      if (!match_bson_value (array_value, pattern_value, &derived)) {
         return false;
      }
   }

   return true;
}


static bool
is_number_type (bson_type_t t)
{
   if (t == BSON_TYPE_DOUBLE || t == BSON_TYPE_INT32 || t == BSON_TYPE_INT64) {
      return true;
   }

   return false;
}


int64_t
bson_value_as_int64 (const bson_value_t *value)
{
   if (value->value_type == BSON_TYPE_DOUBLE) {
      return (int64_t) value->value.v_double;
   } else if (value->value_type == BSON_TYPE_INT32) {
      return (int64_t) value->value.v_int32;
   } else if (value->value_type == BSON_TYPE_INT64) {
      return value->value.v_int64;
   } else {
      return -123;
   }
}


bool
match_bson_value (const bson_value_t *doc,
                  const bson_value_t *pattern,
                  match_ctx_t *ctx)
{
   bson_t subdoc;
   bson_t pattern_subdoc;
   int64_t doc_int64;
   int64_t pattern_int64;
   bool ret = false;

   if (ctx && ctx->allow_placeholders) {
      /* The change streams spec tests use the value 42 as a placeholder. */
      bool is_placeholder = false;
      if (is_number_type (pattern->value_type) &&
          bson_value_as_int64 (pattern) == 42) {
         is_placeholder = true;
      }
      if (pattern->value_type == BSON_TYPE_UTF8 &&
          !strcmp (pattern->value.v_utf8.str, "42")) {
         is_placeholder = true;
      }
      if (is_placeholder) {
         return true;
      }
   }

   if (is_number_type (doc->value_type) &&
       is_number_type (pattern->value_type) && ctx &&
       !ctx->strict_numeric_types) {
      doc_int64 = bson_value_as_int64 (doc);
      pattern_int64 = bson_value_as_int64 (pattern);

      if (doc_int64 != pattern_int64) {
         match_err (ctx,
                    "expected %" PRId64 ", got %" PRId64,
                    pattern_int64,
                    doc_int64);
         return false;
      }

      return true;
   }

   if (doc->value_type != pattern->value_type) {
      match_err (ctx,
                 "expected type %s, got %s",
                 _mongoc_bson_type_to_str (pattern->value_type),
                 _mongoc_bson_type_to_str (doc->value_type));
      return false;
   }

   switch (doc->value_type) {
   case BSON_TYPE_ARRAY:
   case BSON_TYPE_DOCUMENT:

      if (!bson_init_from_value (&subdoc, doc)) {
         return false;
      }

      if (!bson_init_from_value (&pattern_subdoc, pattern)) {
         bson_destroy (&subdoc);
         return false;
      }

      if (doc->value_type == BSON_TYPE_ARRAY) {
         ret = match_bson_arrays (&subdoc, &pattern_subdoc, ctx);
      } else {
         ret = match_bson_with_ctx (&subdoc, &pattern_subdoc, ctx);
      }

      bson_destroy (&subdoc);
      bson_destroy (&pattern_subdoc);

      return ret;

   case BSON_TYPE_BINARY:
      ret = doc->value.v_binary.data_len == pattern->value.v_binary.data_len &&
            !memcmp (doc->value.v_binary.data,
                     pattern->value.v_binary.data,
                     doc->value.v_binary.data_len);
      break;

   case BSON_TYPE_BOOL:
      ret = doc->value.v_bool == pattern->value.v_bool;

      if (!ret) {
         match_err (ctx,
                    "expected %d, got %d",
                    pattern->value.v_bool,
                    doc->value.v_bool);
      }

      return ret;

   case BSON_TYPE_CODE:
      ret = doc->value.v_code.code_len == pattern->value.v_code.code_len &&
            !memcmp (doc->value.v_code.code,
                     pattern->value.v_code.code,
                     doc->value.v_code.code_len);

      break;

   case BSON_TYPE_CODEWSCOPE:
      ret = doc->value.v_codewscope.code_len ==
               pattern->value.v_codewscope.code_len &&
            !memcmp (doc->value.v_codewscope.code,
                     pattern->value.v_codewscope.code,
                     doc->value.v_codewscope.code_len) &&
            doc->value.v_codewscope.scope_len ==
               pattern->value.v_codewscope.scope_len &&
            !memcmp (doc->value.v_codewscope.scope_data,
                     pattern->value.v_codewscope.scope_data,
                     doc->value.v_codewscope.scope_len);

      break;

   case BSON_TYPE_DATE_TIME:
      ret = doc->value.v_datetime == pattern->value.v_datetime;

      if (!ret) {
         match_err (ctx,
                    "expected %" PRId64 ", got %" PRId64,
                    pattern->value.v_datetime,
                    doc->value.v_datetime);
      }

      return ret;

   case BSON_TYPE_DOUBLE:
      ret = doc->value.v_double == pattern->value.v_double;

      if (!ret) {
         match_err (ctx,
                    "expected %f, got %f",
                    pattern->value.v_double,
                    doc->value.v_double);
      }

      return ret;

   case BSON_TYPE_INT32:
      ret = doc->value.v_int32 == pattern->value.v_int32;

      if (!ret) {
         match_err (ctx,
                    "expected %" PRId32 ", got %" PRId32,
                    pattern->value.v_int32,
                    doc->value.v_int32);
      }

      return ret;

   case BSON_TYPE_INT64:
      ret = doc->value.v_int64 == pattern->value.v_int64;

      if (!ret) {
         match_err (ctx,
                    "expected %" PRId64 ", got %" PRId64,
                    pattern->value.v_int64,
                    doc->value.v_int64);
      }

      return ret;

   case BSON_TYPE_OID:
      ret = bson_oid_equal (&doc->value.v_oid, &pattern->value.v_oid);
      break;

   case BSON_TYPE_REGEX:
      ret =
         !strcmp (doc->value.v_regex.regex, pattern->value.v_regex.regex) &&
         !strcmp (doc->value.v_regex.options, pattern->value.v_regex.options);

      break;

   case BSON_TYPE_SYMBOL:
      ret = doc->value.v_symbol.len == pattern->value.v_symbol.len &&
            !strncmp (doc->value.v_symbol.symbol,
                      pattern->value.v_symbol.symbol,
                      doc->value.v_symbol.len);

      break;

   case BSON_TYPE_TIMESTAMP:
      ret = doc->value.v_timestamp.timestamp ==
               pattern->value.v_timestamp.timestamp &&
            doc->value.v_timestamp.increment ==
               pattern->value.v_timestamp.increment;

      break;

   case BSON_TYPE_UTF8:
      ret = doc->value.v_utf8.len == pattern->value.v_utf8.len &&
            !strncmp (doc->value.v_utf8.str,
                      pattern->value.v_utf8.str,
                      doc->value.v_utf8.len);

      if (!ret) {
         match_err (ctx,
                    "expected \"%s\", got \"%s\"",
                    pattern->value.v_utf8.str,
                    doc->value.v_utf8.str);
      }

      return ret;


   /* these are empty types, if "a" and "b" are the same type they're equal */
   case BSON_TYPE_EOD:
   case BSON_TYPE_MAXKEY:
   case BSON_TYPE_MINKEY:
   case BSON_TYPE_NULL:
   case BSON_TYPE_UNDEFINED:
      return true;

   case BSON_TYPE_DBPOINTER:
      ret = (0 == strcmp (doc->value.v_dbpointer.collection,
                          pattern->value.v_dbpointer.collection) &&
             bson_oid_equal (&doc->value.v_dbpointer.oid,
                             &pattern->value.v_dbpointer.oid));
      break;

   case BSON_TYPE_DECIMAL128:
      ret = (doc->value.v_decimal128.low == pattern->value.v_decimal128.low &&
             doc->value.v_decimal128.high == pattern->value.v_decimal128.high);
      if (!ret) {
         match_err (ctx,
                    "Decimal128 is not an exact binary match (though "
                    "numeric values may be equal)");
      }
      break;
   default:
      match_err (ctx, "unexpected value type %d: %s",
                  doc->value_type,
                  _mongoc_bson_type_to_str (doc->value_type));
   }

   if (!ret) {
      match_err (ctx,
                 "%s values mismatch",
                 _mongoc_bson_type_to_str (pattern->value_type));
   }

   return ret;
}

const char *
_mongoc_bson_type_to_str (bson_type_t t)
{
   switch (t) {
   case BSON_TYPE_EOD:
      return "EOD";
   case BSON_TYPE_DOUBLE:
      return "DOUBLE";
   case BSON_TYPE_UTF8:
      return "UTF8";
   case BSON_TYPE_DOCUMENT:
      return "DOCUMENT";
   case BSON_TYPE_ARRAY:
      return "ARRAY";
   case BSON_TYPE_BINARY:
      return "BINARY";
   case BSON_TYPE_UNDEFINED:
      return "UNDEFINED";
   case BSON_TYPE_OID:
      return "OID";
   case BSON_TYPE_BOOL:
      return "BOOL";
   case BSON_TYPE_DATE_TIME:
      return "DATE_TIME";
   case BSON_TYPE_NULL:
      return "NULL";
   case BSON_TYPE_REGEX:
      return "REGEX";
   case BSON_TYPE_DBPOINTER:
      return "DBPOINTER";
   case BSON_TYPE_CODE:
      return "CODE";
   case BSON_TYPE_SYMBOL:
      return "SYMBOL";
   case BSON_TYPE_CODEWSCOPE:
      return "CODEWSCOPE";
   case BSON_TYPE_INT32:
      return "INT32";
   case BSON_TYPE_TIMESTAMP:
      return "TIMESTAMP";
   case BSON_TYPE_INT64:
      return "INT64";
   case BSON_TYPE_MAXKEY:
      return "MAXKEY";
   case BSON_TYPE_MINKEY:
      return "MINKEY";
   case BSON_TYPE_DECIMAL128:
      return "DECIMAL128";
   default:
      return "Unknown";
   }
}

void
_assert_match_bson (const bson_t *doc, const bson_t *pattern)
{
   match_ctx_t ctx;

   memset (&ctx, 0, sizeof (match_ctx_t));
   if (!match_bson_with_ctx (doc, pattern, &ctx)) {
      char *doc_str = doc ? bson_as_json (doc, NULL) : NULL;
      char *pattern_str = bson_as_json (pattern, NULL);

      TEST_ERROR ("ASSERT_MATCH failed with document:\n\n"
                  "%s\n"
                  "pattern:\n%s\n"
                  "%s\n",
                  doc_str ? doc_str : "{}",
                  pattern_str,
                  ctx.errmsg);

      bson_free (doc_str);
      bson_free (pattern_str);
   }
}