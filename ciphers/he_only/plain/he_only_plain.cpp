#include "he_only_plain.h"

namespace HE_ONLY {

std::vector<uint64_t> HeOnly::encrypt(std::vector<uint64_t> plaintext) const {
  return plaintext;
}

std::vector<uint64_t> HeOnly::decrypt(std::vector<uint64_t> ciphertext) const {
  return ciphertext;
}

void HeOnly::prep_one_block() const {}

}  // namespace HE_ONLY
