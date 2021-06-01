#pragma once

#include "../../common/kats.h"
#include "he_only_z2_plain.h"

using namespace HE_ONLY;

// build an array of KnownAnswerTests for HeOnlyZ2
KnownAnswerTest<HeOnlyZ2> KNOWN_ANSWER_TESTS[] = {
    {{0x00}, {0x00}, {0x00}, KnownAnswerTest<HeOnlyZ2>::Testcase::MAT, 5, 16},
    {{0x00}, {0x00}, {0x00}, KnownAnswerTest<HeOnlyZ2>::Testcase::MAT, 5, 16},
    {{0x00}, {0x00}, {0x00}, KnownAnswerTest<HeOnlyZ2>::Testcase::MAT, 5, 16},
};
