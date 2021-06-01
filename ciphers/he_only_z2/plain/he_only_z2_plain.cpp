#include "he_only_z2_plain.h"

namespace HE_ONLY {

std::vector<uint8_t> HeOnlyZ2::encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const {
  return plaintext;
}

std::vector<uint8_t> HeOnlyZ2::decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const {
  return ciphertext;
}

void HeOnlyZ2::prep_one_block() const {}

}  // namespace HE_ONLY
