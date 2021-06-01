#pragma once

#include "../../common_Zp/kats.h"
#include "he_only_plain.h"

using namespace HE_ONLY;

// build an array of KnownAnswerTests for HeOnly
KnownAnswerTestZp<HeOnly> KNOWN_ANSWER_TESTS[] = {
    {
        {0x00},
        {0x00},
        {0x00},
        65537,
        KnownAnswerTestZp<HeOnly>::Testcase::MAT,
        200,
    },
    {
        {0x00},
        {0x00},
        {0x00},
        8088322049ULL,
        KnownAnswerTestZp<HeOnly>::Testcase::MAT,
        200,
    },
    {
        {0x00},
        {0x00},
        {0x00},
        1096486890805657601ULL,
        KnownAnswerTestZp<HeOnly>::Testcase::MAT,
        200,
    },
};
