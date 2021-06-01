#include "lowmc_helib.h"

using namespace helib;

namespace LOWMC {

void LOWMC_256_128_63_14_HElib::encrypt_key() {
  secret_key_encrypted.clear();
  secret_key_encrypted.reserve(params.key_size_bits);
  std::vector<long> p(nslots, 0);
  for (size_t i = 0; i < params.key_size_bits; i++) {
    uint8_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
    Ctxt c(*he_pk);
    p[0] = bit;
    ea.encrypt(c, *he_pk, p);
    secret_key_encrypted.push_back(std::move(c));
  }
}

std::vector<Ctxt> LOWMC_256_128_63_14_HElib::HE_decrypt(
    std::vector<uint8_t>& ciphertexts, size_t bits) {
  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  LowMC lowmc(use_m4ri);
  block iv = 0;
  std::vector<Ctxt> result(bits, {ZeroCtxtLike, secret_key_encrypted[0]});

  for (size_t i = 0; i < num_block; i++) {
    std::cout << "round 0" << std::endl;
    std::vector<Ctxt> state;
    if (use_m4ri) {
      state = secret_key_encrypted;
      MultiplyWithGF2Matrix(lowmc.m4ri_KeyMatrices[0], state);
    } else
      state = MultiplyWithGF2Matrix(lowmc.KeyMatrices[0], secret_key_encrypted);
    addConstant(state, ctr(iv, i + 1));

    for (unsigned r = 1; r <= rounds; ++r) {
      std::cout << "round " << r << std::endl;
      print_noise(state);
      sboxlayer(state);
      if (use_m4ri) {
        MultiplyWithGF2Matrix(lowmc.m4ri_LinMatrices[r - 1], state);
        MultiplyWithGF2MatrixAndAdd(lowmc.m4ri_KeyMatrices[r],
                                    secret_key_encrypted, state);
      } else {
        MultiplyWithGF2Matrix(lowmc.LinMatrices[r - 1], state);
        MultiplyWithGF2MatrixAndAdd(lowmc.KeyMatrices[r], secret_key_encrypted,
                                    state);
      }
      addConstant(state, lowmc.roundconstants[r - 1]);
    }

    // add cipher
    NTL::ZZX p;
    std::vector<long> tmp(nslots, 0);
    for (size_t k = 0; k < blocksize && i * blocksize + k < bits; k++) {
      size_t ind = i * blocksize + k;
      int32_t bit = (ciphertexts[ind / 8] >> (7 - ind % 8)) & 1;
      result[ind] = state[k];
      if (!bit) continue;
      tmp[0] = bit;
      ea.encode(p, tmp);
      result[ind].addConstant(p);
    }
  }
  return result;
}

std::vector<uint8_t> LOWMC_256_128_63_14_HElib::decrypt_result(
    std::vector<Ctxt>& ciphertexts) {
  size_t size = ceil((double)ciphertexts.size() / 8);
  std::vector<uint8_t> res(size, 0);
  std::vector<long> p;
  for (size_t i = 0; i < ciphertexts.size(); i++) {
    ea.decrypt(ciphertexts[i], he_sk, p);
    uint8_t bit = p[0] & 0x1;
    res[i / 8] |= (bit << (7 - i % 8));
  }
  return res;
}

std::vector<Ctxt> LOWMC_256_128_63_14_HElib::MultiplyWithGF2Matrix(
    const std::vector<keyblock>& matrix, const std::vector<Ctxt>& key) {
  std::vector<Ctxt> out;
  out.reserve(params.cipher_size_bits);
  for (unsigned i = 0; i < params.cipher_size_bits; ++i) {
    bool init = false;
    for (unsigned j = 0; j < params.key_size_bits; ++j) {
      if (!matrix[i][j]) continue;
      if (!init) {
        out.push_back(key[j]);
        init = true;
      } else
        out[i] += key[j];
    }
  }
  return out;
}

void LOWMC_256_128_63_14_HElib::MultiplyWithGF2MatrixAndAdd(
    const std::vector<keyblock>& matrix, const std::vector<Ctxt>& key,
    std::vector<Ctxt>& state) {
  for (unsigned i = 0; i < params.cipher_size_bits; ++i) {
    for (unsigned j = 0; j < params.key_size_bits; ++j) {
      if (!matrix[i][j]) continue;
      state[i] += key[j];
    }
  }
}

void LOWMC_256_128_63_14_HElib::MultiplyWithGF2Matrix(
    const std::vector<block>& matrix, std::vector<Ctxt>& state) {
  std::vector<Ctxt> out;
  out.reserve(params.cipher_size_bits);
  for (unsigned i = 0; i < params.cipher_size_bits; ++i) {
    bool init = false;
    for (unsigned j = 0; j < params.cipher_size_bits; ++j) {
      if (!matrix[i][j]) continue;
      if (!init) {
        out.push_back(state[j]);
        init = true;
      } else
        out[i] += state[j];
    }
  }
  state = out;
}

void LOWMC_256_128_63_14_HElib::addConstant(std::vector<Ctxt>& state,
                                            const block& constant) {
  NTL::ZZX p;
  std::vector<long> tmp(nslots, 0);
  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    if (!constant[i]) continue;
    tmp[0] = constant[i];
    ea.encode(p, tmp);
    state[i].addConstant(p);
  }
}

void LOWMC_256_128_63_14_HElib::sboxlayer(std::vector<Ctxt>& state) {
  for (unsigned i = 0; i < numofboxes; i++) {
    // invSbox(state[i * 3], state[i* 3 + 1], state[i * 3 + 2]);
    Sbox(state[i * 3], state[i * 3 + 1], state[i * 3 + 2]);
  }
}

void LOWMC_256_128_63_14_HElib::Sbox(Ctxt& a, Ctxt& b, Ctxt& c) {
  Ctxt r_a = b;
  r_a.multiplyBy(c);  // includes relin
  r_a += a;
  r_a += b;
  r_a += c;

  Ctxt r_b = a;
  r_b.multiplyBy(c);  // includes relin
  r_b += b;
  r_b += c;

  Ctxt r_c = a;
  r_c.multiplyBy(b);  // includes relin
  r_c += c;

  a = r_a;
  b = r_b;
  c = r_c;
}

void LOWMC_256_128_63_14_HElib::invSbox(Ctxt& a, Ctxt& b, Ctxt& c) {
  Ctxt r_a = b;
  r_a.multiplyBy(c);  // includes relin
  r_a += b;
  r_a += c;
  r_a += a;

  Ctxt r_b = a;
  r_b.multiplyBy(c);  // includes relin
  r_b += b;

  Ctxt r_c = a;
  r_c.multiplyBy(b);  // includes relin
  r_c += b;
  r_c += c;

  a = r_a;
  b = r_b;
  c = r_c;
}

void LOWMC_256_128_63_14_HElib::MultiplyWithGF2MatrixAndAdd(
    const mzd_t* matrix, const std::vector<Ctxt>& key,
    std::vector<Ctxt>& state) {
  rci_t k = floor(log2(matrix->ncols)) - 2;
  if (k < 1) k = 1;

  std::vector<rci_t> L(1 << k);
  std::vector<Ctxt> T(1 << k, {ZeroCtxtLike, state[0]});

  L[0] = 0;
  for (rci_t i = 0; i < matrix->ncols; i += k) {
    if (i + k > matrix->ncols) k = matrix->ncols - i;
    for (rci_t j = 1; j < 1 << k; j++) {
      rci_t rowneeded = i + m4ri_codebook[k]->inc[j - 1];
      L[m4ri_codebook[k]->ord[j]] = j;
      T[j] = key[rowneeded];
      T[j] += T[j - 1];
    }

    for (rci_t j = 0; j < matrix->nrows; j++) {
      rci_t x = L[mzd_read_bits_int(matrix, j, i, k)];
      state[j] += T[x];
    }
  }
}

void LOWMC_256_128_63_14_HElib::MultiplyWithGF2Matrix(
    const mzd_t* matrix, std::vector<Ctxt>& state) {
  std::vector<Ctxt> out(matrix->nrows, {ZeroCtxtLike, state[0]});

  rci_t k = floor(log2(matrix->ncols)) - 2;
  if (k < 1) k = 1;

  std::vector<rci_t> L(1 << k);
  std::vector<Ctxt> T(1 << k, {ZeroCtxtLike, state[0]});

  L[0] = 0;
  for (rci_t i = 0; i < matrix->ncols; i += k) {
    if (i + k > matrix->ncols) k = matrix->ncols - i;
    for (rci_t j = 1; j < 1 << k; j++) {
      rci_t rowneeded = i + m4ri_codebook[k]->inc[j - 1];
      L[m4ri_codebook[k]->ord[j]] = j;
      T[j] = state[rowneeded];
      T[j] += T[j - 1];
    }

    for (rci_t j = 0; j < matrix->nrows; j++) {
      rci_t x = L[mzd_read_bits_int(matrix, j, i, k)];
      out[j] += T[x];
    }
  }
  state = out;
}

}  // namespace LOWMC
