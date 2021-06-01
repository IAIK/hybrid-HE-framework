#include "masta_5_helib.h"

using namespace helib;

namespace MASTA_5 {

void MASTA_128_HElib::encrypt_key() {
  secret_key_encrypted.resize(1, Ctxt(*he_pk));
  std::vector<long> p(secret_key.begin(), secret_key.end());
  encrypt(secret_key_encrypted[0], p);
}

std::vector<Ctxt> MASTA_128_HElib::HE_decrypt(
    std::vector<uint64_t>& ciphertexts) {
  uint64_t nonce = 123456789;
  size_t size = ciphertexts.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Masta masta(plain_mod);
  std::vector<Ctxt> res(num_block, {ZeroCtxtLike, secret_key_encrypted[0]});

  for (uint64_t b = 0; b < num_block; b++) {
    masta.init_shake(nonce, b);
    Ctxt state = secret_key_encrypted[0];

    for (uint8_t r = 1; r <= MASTA_R; r++) {
      std::cout << "round " << (int)r << std::endl;
      auto mat = masta.get_random_matrix();
      auto rc = masta.get_random_vector();
      matmul(state, mat);
      add_rc(state, rc);
      sbox(state);
      print_noise(state);
    }

    std::cout << "final add" << std::endl;
    auto mat = masta.get_random_matrix();
    auto rc = masta.get_random_vector();
    matmul(state, mat);
    add_rc(state, rc);
    state += secret_key_encrypted[0];

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

std::vector<uint64_t> MASTA_128_HElib::decrypt_result(
    std::vector<Ctxt>& ciphertext) {
  std::vector<long> res;
  decrypt(ciphertext[0], res);
  res.resize(params.plain_size);
  return std::vector<uint64_t>(res.begin(), res.end());
}

void MASTA_128_HElib::add_gk_indices() {
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

void MASTA_128_HElib::add_rc(helib::Ctxt& state, std::vector<uint64_t>& rc) {
  std::vector<long> p(rc.begin(), rc.end());
  NTL::ZZX p_enc;
  encode(p_enc, p);
  state.addConstant(p_enc);
}

void MASTA_128_HElib::sbox(helib::Ctxt& state) {
  NTL::ZZX p;
  std::vector<long> tmp(params.key_size, 1);
  encode(p, tmp);

  // non-full-packed rotation preparation
  if ((!power_of_2_ring && nslots != params.key_size) ||
      (power_of_2_ring && nslots != 2 * params.key_size)) {
    Ctxt state_rot = state;
    rotate(state_rot, params.key_size);
    state += state_rot;
  }

  Ctxt state_rot1 = state;
  Ctxt state_rot2 = state;
  rotate(state_rot1, -1);
  rotate(state_rot2, -2);

  state_rot1.addConstant(p);
  state_rot1.multiplyBy(state_rot2);  // includes relin
  state += state_rot1;

  if ((!power_of_2_ring && nslots != params.key_size) ||
      (power_of_2_ring && nslots != 2 * params.key_size)) {
    state.multByConstant(p);
  }
}

void MASTA_128_HElib::matmul(helib::Ctxt& state,
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

}  // namespace MASTA_5
