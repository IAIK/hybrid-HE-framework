#pragma once

#include "../../common_Zp/seal_kats.h"
#include "he_only_seal.h"

using namespace HE_ONLY;

// build an array of KnownAnswerTests for MASTA_128
SEALKnownAnswerTestZp<HeOnlySEAL> KNOWN_ANSWER_TESTS[] = {
    {{0x00},
     {0x00},
     {0x00},
     65537,
     8192,
     128,
     SEALKnownAnswerTestZp<HeOnlySEAL>::Testcase::PACKED_MAT,
     200,
     true,
     20,
     10},
    {{0x00},
     {0x00},
     {0x00},
     8088322049ULL,
     16384,
     128,
     SEALKnownAnswerTestZp<HeOnlySEAL>::Testcase::PACKED_MAT,
     200,
     true,
     20,
     10},
    {{0x00},
     {0x00},
     {0x00},
     1096486890805657601ULL,
     32768,
     128,
     SEALKnownAnswerTestZp<HeOnlySEAL>::Testcase::PACKED_MAT,
     200,
     true,
     20,
     10},
};
