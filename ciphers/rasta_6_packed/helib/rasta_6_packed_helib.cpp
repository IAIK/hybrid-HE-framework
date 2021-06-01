#include "rasta_6_packed_helib.h"

using namespace helib;

namespace RASTA_6_PACKED {

void RASTA_128_HElib::encrypt_key() {
  if (params.key_size_bits > nslots)
    throw std::runtime_error("key does not fit into slots!");

  // if (params.key_size_bits != nslots && params.key_size_bits * 2 > nslots)
  if (params.key_size_bits != nslots && params.key_size_bits > nslots)
    throw std::runtime_error("amount of slots is too small for rotations!");

  secret_key_encrypted.resize(1, Ctxt(*he_pk));
  std::vector<long> p(nslots, 0);
  for (size_t i = 0; i < params.key_size_bits; i++) {
    uint8_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
    p[i] = bit;
  }
  ea.encrypt(secret_key_encrypted[0], *he_pk, p);
}

std::vector<Ctxt> RASTA_128_HElib::HE_decrypt(std::vector<uint8_t>& ciphertexts,
                                              size_t bits) {
  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  Rasta rasta;
  std::vector<Ctxt> result(num_block, {ZeroCtxtLike, secret_key_encrypted[0]});

  for (size_t i = 0; i < num_block; i++) {
    rasta.genInstance(0, i + 1);

    Ctxt state = secret_key_encrypted[0];

    for (unsigned r = 1; r <= rounds; ++r) {
      std::cout << "round " << r << std::endl;
      MultiplyWithGF2Matrix(rasta.LinMatrices_u8[r - 1], state);
      addConstant(state, rasta.roundconstants_u8[r - 1]);
      sboxlayer(state);
      print_noise(state);
    }

    std::cout << "final add" << std::endl;
    MultiplyWithGF2Matrix(rasta.LinMatrices_u8[rounds], state);
    addConstant(state, rasta.roundconstants_u8[rounds]);
    state += secret_key_encrypted[0];

    // add cipher
    NTL::ZZX p;
    std::vector<long> tmp(nslots, 0);
    result[i] = state;
    for (size_t k = 0; k < blocksize && i * blocksize + k < bits; k++) {
      size_t ind = i * blocksize + k;
      int32_t bit = (ciphertexts[ind / 8] >> (7 - ind % 8)) & 1;
      tmp[k] = bit;
    }
    ea.encode(p, tmp);
    result[i].addConstant(p);
  }

  return result;
}

std::vector<uint8_t> RASTA_128_HElib::decrypt_result(
    std::vector<Ctxt>& ciphertexts) {
  std::vector<uint8_t> res(params.plain_size_bytes, 0);
  std::vector<long> p;
  ea.decrypt(ciphertexts[0], he_sk, p);
  for (size_t i = 0; i < params.plain_size_bits; i++) {
    uint8_t bit = p[i] & 0x1;
    res[i / 8] |= (bit << (7 - i % 8));
  }
  return res;
}

void RASTA_128_HElib::addConstant(Ctxt& state,
                                  const std::vector<uint8_t>& constant) {
  std::vector<long> p(constant.begin(), constant.end());
  p.resize(nslots, 0);
  NTL::ZZX p_enc;
  ea.encode(p_enc, p);
  state.addConstant(p_enc);
}

// void RASTA_128_HElib::sboxlayer(helib::Ctxt& state) {
//   NTL::ZZX p;
//   std::vector<long> tmp(params.key_size_bits, 1);
//   tmp.resize(nslots, 0);
//   ea.encode(p, tmp);

//   // non-full-packed rotation preparation
//   if (nslots != params.key_size_bits) {
//     Ctxt state_rot = state;
//     ea.rotate(state_rot, params.key_size_bits);
//     state += state_rot;
//   }

//   Ctxt state_rot1 = state;
//   Ctxt state_rot2 = state;
//   ea.rotate(state_rot1, -1);
//   ea.rotate(state_rot2, -2);

//   state_rot1.addConstant(p);
//   state_rot1.multiplyBy(state_rot2); // includes relin
//   state += state_rot1;

//   if (nslots != params.key_size_bits) {
//     std::vector<long> mask(params.key_size_bits, 1);
//     mask.resize(nslots, 0);
//     NTL::ZZX mask_enc;
//     ea.encode(mask_enc, mask);
//     state.multByConstant(mask_enc);
//   }
// }

void RASTA_128_HElib::sboxlayer(helib::Ctxt& state) {
  NTL::ZZX p;
  std::vector<long> tmp(params.key_size_bits, 1);
  tmp.resize(nslots, 0);
  ea.encode(p, tmp);

  Ctxt state_rot1 = state;
  Ctxt state_rot2 = state;

  if (nslots == params.key_size_bits) {
    ea.rotate(state_rot1, -1);
    ea.rotate(state_rot2, -2);
  } else {
    std::vector<long> mask1(params.key_size_bits, 1);
    mask1.resize(nslots, 0);
    std::vector<long> mask2(nslots, 0);
    NTL::ZZX mask_enc;

    // first rot
    mask1[0] = 0;
    mask2[0] = 1;
    Ctxt tmp = state_rot1;
    ea.encode(mask_enc, mask1);
    state_rot1.multByConstant(mask_enc);
    ea.encode(mask_enc, mask2);
    tmp.multByConstant(mask_enc);

    ea.rotate(state_rot1, -1);
    ea.rotate(tmp, blocksize - 1);
    state_rot1 += tmp;

    // second rot
    mask1[1] = 0;
    mask2[1] = 1;
    tmp = state_rot2;
    ea.encode(mask_enc, mask1);
    state_rot2.multByConstant(mask_enc);
    ea.encode(mask_enc, mask2);
    tmp.multByConstant(mask_enc);

    ea.rotate(state_rot2, -2);
    ea.rotate(tmp, blocksize - 2);
    state_rot2 += tmp;
  }

  state_rot1.addConstant(p);
  state_rot1.multiplyBy(state_rot2);  // includes relin
  state += state_rot1;
}

void RASTA_128_HElib::MultiplyWithGF2Matrix(
    const std::vector<std::vector<uint8_t>>& mat, helib::Ctxt& state) {
  if (USE_HELIB_MATMUL_IMPL)
    helib_matmul(state, mat);
  else if (use_bsgs) {
    set_bsgs_params(BSGS_N1, BSGS_N2);
    babystep_giantstep(state, mat);
  } else {
    diagonal(state, mat);
  }
}

}  // namespace RASTA_6_PACKED
