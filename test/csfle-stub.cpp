/**
 * This file does not contain test cases.
 *
 * This file defines the minimum APIs for csfle to be successfully loaded (but
 * not necessarily fully used) by libmongocrypt. This is only used to test the
 * loading and un-loading of the csfle dynamic library file by libmongocrypt.
 */

#ifdef _WIN32
#define EXPORT_API __declspec(dllexport)
#else
#define EXPORT_API __attribute__ ((visibility ("default")))
#endif

#define CSFLE_SUPPORT_COMPILING

#include <mongo_csfle-v1.h>

#include <cstring>

#ifdef _WIN32
#define MONGO_API_CALL __cdecl
#define MONGO_API_EXPORT __declspec(dllexport)
#else
#define MONGO_API_CALL [[]]
#define MONGO_API_EXPORT __attribute__ ((used, visibility ("default")))
#endif

struct mongo_csfle_v1_status {
};

using status_t = mongo_csfle_v1_status;

status_t *
mongo_csfle_v1_status_create (void)
{
   return new status_t;
}

void
mongo_csfle_v1_status_destroy (status_t *st)
{
   delete st;
}

int
mongo_csfle_v1_status_get_error (const status_t *)
{
   return 0;
}

const char *
mongo_csfle_v1_status_get_explanation (const status_t *)
{
   return "nothing here";
}

int
mongo_csfle_v1_status_get_code (const status_t *)
{
   return 0;
}

struct mongo_csfle_v1_lib {
};

using lib_t = mongo_csfle_v1_lib;

lib_t *
mongo_csfle_v1_lib_create (status_t *)
{
   return new lib_t;
}

int
mongo_csfle_v1_lib_destroy (lib_t *lib, status_t *)
{
   delete lib;
   return MONGO_CSFLE_V1_SUCCESS;
}

uint64_t
mongo_csfle_v1_get_version (void)
{
   return UINT64_C (0x0006'0002'0001'000);
}


const char *
mongo_csfle_v1_get_version_str (void)
{
   return "6.2.1";
}

struct mongo_csfle_v1_query_analyzer {
};

using query_analyzer_t = mongo_csfle_v1_query_analyzer;

query_analyzer_t *
mongo_csfle_v1_query_analyzer_create (lib_t *, status_t *)
{
   return new query_analyzer_t;
}

void
mongo_csfle_v1_query_analyzer_destroy (query_analyzer_t *qa)
{
   delete qa;
}

uint8_t *
mongo_csfle_v1_analyze_query (query_analyzer_t *qa,
                              const uint8_t *doc_bson,
                              const char *ns_str,
                              uint32_t ns_len,
                              uint32_t *bson_len_out,
                              status_t *)
{
   const int size = 512;
   uint8_t *ptr = new uint8_t[size];
   std::memset (ptr, 42, size);
   *bson_len_out = size;
   return ptr;
}

void
mongo_csfle_v1_bson_free (uint8_t *bson)
{
   delete[] bson;
}
