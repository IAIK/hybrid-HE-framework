#include "filip_1216_plain.h"

#include "math.h"

namespace FILIP_1216 {

static state convert_key(const std::vector<uint8_t>& key) {
  state k;
  for (size_t i = 0; i < k.size(); i++) {
    k[i] = (key[i / 8] >> (7 - i % 8)) & 1;
  }
  return k;
}

std::vector<uint8_t> FiLIP_1216::encrypt(std::vector<uint8_t> plaintext,
                                         size_t bits) const {
  FiLIP filip(params, convert_key(secret_key));

  std::array<uint8_t, 16> iv = {0xab, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  std::vector<uint8_t> keystream = filip.keystream(iv, bits);
  for (size_t i = 0; i < keystream.size(); i++) keystream[i] ^= plaintext[i];
  return keystream;
}

std::vector<uint8_t> FiLIP_1216::decrypt(std::vector<uint8_t> ciphertext,
                                         size_t bits) const {
  FiLIP filip(params, convert_key(secret_key));

  std::array<uint8_t, 16> iv = {0xab, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  std::vector<uint8_t> keystream = filip.keystream(iv, bits);
  for (size_t i = 0; i < keystream.size(); i++) keystream[i] ^= ciphertext[i];
  return keystream;
}

void FiLIP_1216::prep_one_block() const {}

//------------------------------------------------------------------------
//------------------------------------------------------------------------
// FiLIP CORE
//------------------------------------------------------------------------
//------------------------------------------------------------------------

FiLIP::FiLIP(BlockCipherParams param, state k)
    : params(param), flag(0), key(k) {}

void FiLIP::set_iv(std::array<uint8_t, 16>& iv) {
  aes_random = osuCrypto::toBlock(iv.data());
}

std::vector<uint8_t> FiLIP::keystream(std::array<uint8_t, 16>& iv,
                                      size_t bits) {
  size_t bytes = ceil((double)bits / 8);
  std::vector<uint8_t> out(bytes, 0);

  set_iv(iv);

  std::vector<size_t> ind;
  ind.reserve(params.key_size_bits);
  for (size_t i = 0; i < params.key_size_bits; i++) ind.push_back(i);

  state_whitened whitening;

  for (size_t i = 0; i < bits; i++) {
    shuffle(ind);
    set_whitening(whitening);
    for (size_t j = 0; j < NB_VAR; j++)
      whitening[j] = whitening[j] ^ key[ind[j]];
    bool bit = FLIP(whitening);
    out[i / 8] |= (bit << (7 - i % 8));
  }
  return out;
}

void FiLIP::shuffle(std::vector<size_t>& ind) {
  for (size_t i = params.key_size_bits; i > 0; i--) {
    uint32_t random = aes_forward_secure();
    random = random % i;
    if (random != i - 1) std::swap(ind[random], ind[i - 1]);
  }
}

void FiLIP::set_whitening(state_whitened& whitening) {
  uint32_t random;
  for (size_t i = 0; i < NB_VAR; i++) {
    int rem = i % 32;
    if (rem == 0) random = aes_forward_secure();
    whitening[i] = (random >> rem) & 1;
  }
}

uint8_t FiLIP::FLIP(state_whitened& state) {
  uint8_t out = 0;
  size_t nb = 0;

  // Computation of Linear monomials
  for (size_t i = 0; i < MF[0]; i++) out ^= state[nb++];

  // Computation of higher degree monomials
  for (size_t i = 1; i < SIZE; i++) {
    for (size_t j = 0; j < MF[i]; j++) {
      uint8_t tmp = state[nb++] & state[nb++];
      for (size_t k = 2; k < (i + 1); k++) tmp &= state[nb++];
      out ^= tmp;
    }
  }
  return out;
}

uint32_t FiLIP::aes_forward_secure() {
  uint32_t random;
  uint8_t* pointer = (uint8_t*)(&aes_ctxt);

  if (flag == 0) {
    aes.setKey(aes_random);
    aes_random = aes.ecbEncBlock(osuCrypto::ZeroBlock);
    aes_ctxt = aes.ecbEncBlock(osuCrypto::AllOneBlock);

    random = pointer[0] ^ (pointer[1] << 8) ^ (pointer[2] << 16) ^
             (pointer[3] << 24);
    flag++;
    return random;
  }

  switch (flag) {
    case 1:
      random = pointer[4] ^ (pointer[5] << 8) ^ (pointer[6] << 16) ^
               (pointer[7] << 24);
      flag++;
      break;
    case 2:
      random = pointer[8] ^ (pointer[9] << 8) ^ (pointer[10] << 16) ^
               (pointer[11] << 24);
      flag++;
      break;
    case 3:
      random = pointer[12] ^ (pointer[13] << 8) ^ (pointer[14] << 16) ^
               (pointer[15] << 24);
      flag = 0;
      break;
    default:
      throw std::runtime_error("Invalid AES flag");
  }
  return random;
}

}  // namespace FILIP_1216
