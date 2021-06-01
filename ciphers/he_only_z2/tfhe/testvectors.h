#pragma once

#include "../../common/tfhe_kats.h"
#include "he_only_z2_tfhe.h"

using namespace HE_ONLY;

// build an array of KnownAnswerTests for FiLIP-1280
TFHEKnownAnswerTest<HeOnlyTFHE> KNOWN_ANSWER_TESTS[] = {{
    {0x00},
    {0x00},
    {0x00},
    128,
    TFHEKnownAnswerTest<HeOnlyTFHE>::Testcase::MAT,
    5,
    16,
}};
