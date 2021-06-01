#include "agrasta_helib.h"

using namespace helib;

namespace AGRASTA {

void AGRASTA_128_HElib::encrypt_key() {
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

std::vector<Ctxt> AGRASTA_128_HElib::HE_decrypt(
    std::vector<uint8_t>& ciphertexts, size_t bits) {
  size_t num_block = ceil((double)bits / params.cipher_size_bits);

  Agrasta agrasta;
  std::vector<Ctxt> result(bits, {ZeroCtxtLike, secret_key_encrypted[0]});

  for (size_t i = 0; i < num_block; i++) {
    agrasta.genInstance(0, i + 1, use_m4ri);

    std::vector<Ctxt> state = secret_key_encrypted;

    for (unsigned r = 1; r <= rounds; ++r) {
      std::cout << "round " << r << std::endl;
      if (use_m4ri)
        MultiplyWithGF2Matrix(agrasta.m4ri_LinMatrices[r - 1], state);
      else
        MultiplyWithGF2Matrix(agrasta.LinMatrices[r - 1], state);
      addConstant(state, agrasta.roundconstants[r - 1]);
      sboxlayer(state);
      print_noise(state);
    }

    std::cout << "final add" << std::endl;
    if (use_m4ri)
      MultiplyWithGF2Matrix(agrasta.m4ri_LinMatrices[rounds], state);
    else
      MultiplyWithGF2Matrix(agrasta.LinMatrices[rounds], state);
    addConstant(state, agrasta.roundconstants[rounds]);
    add(state, secret_key_encrypted);

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

std::vector<uint8_t> AGRASTA_128_HElib::decrypt_result(
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

void AGRASTA_128_HElib::MultiplyWithGF2Matrix(const std::vector<block>& matrix,
                                              std::vector<Ctxt>& state) {
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

void AGRASTA_128_HElib::MultiplyWithGF2Matrix(const mzd_t* matrix,
                                              std::vector<Ctxt>& state) {
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

void AGRASTA_128_HElib::addConstant(std::vector<Ctxt>& state,
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

void AGRASTA_128_HElib::add(std::vector<Ctxt>& state,
                            const std::vector<Ctxt>& key) {
  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    state[i] += key[i];
  }
}

void AGRASTA_128_HElib::sboxlayer(std::vector<Ctxt>& state) {
  std::vector<Ctxt> out;
  out.reserve(state.size());
  NTL::ZZX p;
  std::vector<long> tmp(nslots, 0);
  tmp[0] = 1;
  ea.encode(p, tmp);

  for (size_t i = 0; i < params.cipher_size_bits; i++) {
    int i_1 = (i + 1) % params.cipher_size_bits;
    int i_2 = (i + 2) % params.cipher_size_bits;

    Ctxt tmp = state[i_1];
    tmp.addConstant(p);
    tmp.multiplyBy(state[i_2]);  // includes relin
    tmp += state[i];
    out.push_back(std::move(tmp));
  }

  state = out;
}

}  // namespace AGRASTA
