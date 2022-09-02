/*
 * Copyright 2022-present MongoDB, Inc.
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

// mc-range-mincover-generator.template.c is meant to be included in another
// source file.
#ifndef BITS
#error "must be included with BITS defined"
#endif

#ifndef CONCAT
#define CONCAT_1(a, b) a##b
#define CONCAT(a, b) CONCAT_1 (a, b)
#endif
#ifndef CONCAT3
#define CONCAT3(a, b, c) CONCAT (a, CONCAT (b, c))
#endif

#define UINT_T CONCAT3 (uint, BITS, _t)
#define UINT_C CONCAT3 (UINT, BITS, _C)
#define FMT_UINT_T CONCAT (PRId, BITS)
#define T(X) CONCAT3 (X, _u, BITS)


// MinCoverGenerator models the MinCoverGenerator type added in
// SERVER-68600.
typedef struct {
   UINT_T _rangeMin;
   UINT_T _rangeMax;
   size_t _sparsity;
   // _maxlen is the maximum bit length of edges in the mincover.
   size_t _maxlen;
} T (MinCoverGenerator);

static T (MinCoverGenerator) *
   T (MinCoverGenerator_new) (UINT_T rangeMin,
                              UINT_T rangeMax,
                              UINT_T max,
                              size_t sparsity,
                              mongocrypt_status_t *status)
{
   BSON_ASSERT_PARAM (status);

   if (rangeMin > rangeMax) {
      CLIENT_ERR ("Range min (%" FMT_UINT_T
                  ") must be less than or equal to range max (%" FMT_UINT_T
                  ") for range search",
                  rangeMin,
                  rangeMax);
      return NULL;
   }
   if (rangeMax > max) {
      CLIENT_ERR ("Range max (%" FMT_UINT_T
                  ") must be less than or equal to max (%" FMT_UINT_T
                  ") for range search",
                  rangeMax,
                  max);
      return NULL;
   }
   T (MinCoverGenerator) *mcg = bson_malloc0 (sizeof (T (MinCoverGenerator)));
   mcg->_rangeMin = rangeMin;
   mcg->_rangeMax = rangeMax;
   mcg->_maxlen = BITS - T (mc_count_leading_zeros) (max);
   mcg->_sparsity = sparsity;
   return mcg;
}

static void
T (MinCoverGenerator_destroy) (T (MinCoverGenerator) * mcg)
{
   if (!mcg) {
      return;
   }
   bson_free (mcg);
}

// applyMask applies a mask of 1 bits starting from the right.
// Bits 0 to bit-1 are replaced with 1. Other bits are left as-is.
static UINT_T
T (applyMask) (UINT_T value, size_t maskedBits)
{
   const UINT_T ones = ~UINT_C (0);

   BSON_ASSERT (maskedBits <= BITS);
   BSON_ASSERT (maskedBits >= 0);

   if (maskedBits == 0) {
      return value;
   }

   const UINT_T shift = (BITS - (UINT_T) (maskedBits));
   const UINT_T mask = ones >> shift;
   return value | mask;
}

static bool
T (MinCoverGenerator_isLevelStored) (T (MinCoverGenerator) * mcg,
                                     size_t maskedBits)
{
   BSON_ASSERT_PARAM (mcg);
   size_t level = mcg->_maxlen - maskedBits;
   return 0 == maskedBits || 0 == (level % mcg->_sparsity);
}

char *
T (MinCoverGenerator_toString) (T (MinCoverGenerator) * mcg,
                                UINT_T start,
                                size_t maskedBits)
{
   BSON_ASSERT_PARAM (mcg);
   BSON_ASSERT (maskedBits <= mcg->_maxlen);
   BSON_ASSERT (maskedBits <= BITS);
   BSON_ASSERT (maskedBits >= 0);

   if (maskedBits == mcg->_maxlen) {
      return bson_strdup ("root");
   }

   UINT_T shifted = start >> (UINT_T) maskedBits;
   char *valueBin = T (mc_convert_to_bitstring) (shifted);
   char *ret = bson_strndup (valueBin + (BITS - mcg->_maxlen + maskedBits),
                             mcg->_maxlen + maskedBits);
   bson_free (valueBin);
   return ret;
}

static void
T (MinCoverGenerator_minCoverRec) (T (MinCoverGenerator) * mcg,
                                   mc_array_t *c,
                                   UINT_T blockStart,
                                   size_t maskedBits)
{
   BSON_ASSERT_PARAM (mcg);
   BSON_ASSERT_PARAM (c);
   const UINT_T blockEnd = T (applyMask) (blockStart, maskedBits);

   if (blockEnd < mcg->_rangeMin || blockStart > mcg->_rangeMax) {
      return;
   }

   if (blockStart >= mcg->_rangeMin && blockEnd <= mcg->_rangeMax &&
       T (MinCoverGenerator_isLevelStored) (mcg, maskedBits)) {
      char *edge = T (MinCoverGenerator_toString) (mcg, blockStart, maskedBits);
      _mc_array_append_val (c, edge);
      return;
   }

   BSON_ASSERT (maskedBits > 0);

   const size_t newBits = maskedBits - 1;
   T (MinCoverGenerator_minCoverRec) (mcg, c, blockStart, newBits);
   T (MinCoverGenerator_minCoverRec)
   (mcg, c, blockStart | (UINT_T) 1 << (UINT_T) newBits, newBits);
}

static mc_mincover_t *
T (MinCoverGenerator_minCover) (T (MinCoverGenerator) * mcg,
                                UINT_T rangeMin,
                                UINT_T rangeMax,
                                UINT_T max,
                                size_t sparsity)
{
   BSON_ASSERT_PARAM (mcg);
   mc_mincover_t *mc = mc_mincover_new ();
   T (MinCoverGenerator_minCoverRec) (mcg, &mc->mincover, 0, mcg->_maxlen);
   return mc;
}

#undef UINT_T
#undef FMT_UINT_T
#undef T
