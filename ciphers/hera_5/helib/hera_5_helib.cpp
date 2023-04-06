#include "hera_5_helib.h"

using namespace helib;

namespace HERA_5 {

void HERA_HElib::encrypt_key() {
  secret_key_encrypted.resize(1, Ctxt(*he_pk));
  std::vector<long> p(secret_key.begin(), secret_key.end());
  encrypt(secret_key_encrypted[0], p);
}

std::vector<Ctxt> HERA_HElib::HE_decrypt(std::vector<uint64_t>& ciphertexts) {
  uint64_t nonce = 123456789;
  size_t size = ciphertexts.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Hera hera(plain_mod);
  std::vector<Ctxt> res(num_block, {ZeroCtxtLike, secret_key_encrypted[0]});

  for (uint64_t b = 0; b < num_block; b++) {
    hera.init_shake(nonce, b);
    auto rc = hera.get_random_vector();
    Ctxt state = first_ark(rc);

    for (uint8_t r = 1; r < HERA_R; r++) {
      std::cout << "round " << (int)r << std::endl;
      rc = hera.get_random_vector();
      matmul(state, hera.matrix);
      sbox_cube(state);
      ark(state, rc);
      print_noise(state);
    }

    std::cout << "final add" << std::endl;
    rc = hera.get_random_vector();
    matmul(state, hera.matrix);
    sbox_cube(state);
    matmul(state, hera.matrix);
    ark(state, rc);

    // add cipher
    std::vector<long> cipher_tmp;
    cipher_tmp.insert(
        cipher_tmp.begin(), ciphertexts.begin() + b * params.cipher_size,
        ciphertexts.begin() + std::min((b + 1) * params.cipher_size, size));
    NTL::ZZX p_enc;
    encode(p_enc, cipher_tmp);
    state.negate();
    state.addConstant(p_enc);
    res[b] = state;
  }

  return res;
}

std::vector<uint64_t> HERA_HElib::decrypt_result(
    std::vector<Ctxt>& ciphertext) {
  std::vector<long> res;
  decrypt(ciphertext[0], res);
  res.resize(params.plain_size);
  return std::vector<uint64_t>(res.begin(), res.end());
}

void HERA_HElib::add_gk_indices() {
  gk_indices.emplace(-1);
  gk_indices.emplace(-2);
  if ((!power_of_2_ring && nslots != params.key_size) ||
      (power_of_2_ring && nslots != 2 * params.key_size))
    gk_indices.emplace(params.key_size);
  if (use_bsgs) {
    for (long k = 1; k < BSGS_N2; k++) gk_indices.emplace(-k * BSGS_N1);
    for (uint64_t j = 1; j < BSGS_N1; j++) gk_indices.emplace(-j);
  }
}

void HERA_HElib::sbox_cube(helib::Ctxt& state) {
  Ctxt tmp = state;
  state.multiplyBy(state);  // includes relin
  state.multiplyBy(tmp);    // includes relin
}

void HERA_HElib::matmul(helib::Ctxt& state,
                        std::vector<std::vector<uint64_t>>& mat) {
  if (!power_of_2_ring && USE_HELIB_MATMUL_IMPL)
    helib_matmul(state, mat);
  else if (use_bsgs) {
    set_bsgs_params(BSGS_N1, BSGS_N2);
    babystep_giantstep(state, mat);
  } else {
    diagonal(state, mat);
  }
}

void HERA_HElib::ark(helib::Ctxt& state, std::vector<uint64_t>& rc) {
  std::vector<long> p(rc.begin(), rc.end());
  NTL::ZZX p_enc;
  encode(p_enc, p);
  Ctxt tmp = secret_key_encrypted[0];
  tmp.multByConstant(p_enc);
  state += tmp;
}

helib::Ctxt HERA_HElib::first_ark(std::vector<uint64_t>& rc) {
  std::vector<long> p(rc.begin(), rc.end());
  NTL::ZZX p_enc;
  encode(p_enc, p);
  std::vector<long> init = {1, 2,  3,  4,  5,  6,  7,  8,
                            9, 10, 11, 12, 13, 14, 15, 16};

  Ctxt result = secret_key_encrypted[0];
  result.multByConstant(p_enc);
  encode(p_enc, init);
  result.addConstant(p_enc);
  return result;
}

}  // namespace HERA_5
