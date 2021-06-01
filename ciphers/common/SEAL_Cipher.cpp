#include "SEAL_Cipher.h"

#include <iostream>

SEALCipher::SEALCipher(BlockCipherParams params,
                       std::vector<uint8_t> secret_key,
                       std::shared_ptr<seal::SEALContext> con)
    : secret_key(secret_key),
      params(params),
      context(con),
      keygen(*context),
      he_sk(keygen.secret_key()),
      encryptor(*context, he_sk),
      evaluator(*context),
      decryptor(*context, he_sk) {
  if (secret_key.size() != params.key_size_bytes)
    throw std::runtime_error("Invalid Key length");

  keygen.create_relin_keys(he_rk);
  keygen.create_public_key(he_pk);
  encryptor.set_public_key(he_pk);

  mod_degree = context->first_context_data()->parms().poly_modulus_degree();
  plain_mod = context->first_context_data()->parms().plain_modulus().value();
}

std::shared_ptr<seal::SEALContext> SEALCipher::create_context(
    size_t mod_degree, uint64_t plain_mod, int seclevel) {
  if (seclevel != 128) throw std::runtime_error("Security Level not supported");
  seal::sec_level_type sec = seal::sec_level_type::tc128;

  seal::EncryptionParameters parms(seal::scheme_type::bfv);
  parms.set_poly_modulus_degree(mod_degree);
  if (mod_degree == 65536) {
    sec = seal::sec_level_type::none;
    parms.set_coeff_modulus(
        {0xffffffffffc0001, 0xfffffffff840001, 0xfffffffff6a0001,
         0xfffffffff5a0001, 0xfffffffff2a0001, 0xfffffffff240001,
         0xffffffffefe0001, 0xffffffffeca0001, 0xffffffffe9e0001,
         0xffffffffe7c0001, 0xffffffffe740001, 0xffffffffe520001,
         0xffffffffe4c0001, 0xffffffffe440001, 0xffffffffe400001,
         0xffffffffdda0001, 0xffffffffdd20001, 0xffffffffdbc0001,
         0xffffffffdb60001, 0xffffffffd8a0001, 0xffffffffd840001,
         0xffffffffd6e0001, 0xffffffffd680001, 0xffffffffd2a0001,
         0xffffffffd000001, 0xffffffffcf00001, 0xffffffffcea0001,
         0xffffffffcdc0001, 0xffffffffcc40001});  // 1740 bits
  } else {
    parms.set_coeff_modulus(seal::CoeffModulus::BFVDefault(mod_degree));
  }
  parms.set_plain_modulus(plain_mod);
  return std::make_shared<seal::SEALContext>(parms, true, sec);
}

//----------------------------------------------------------------
int SEALCipher::print_noise() { return print_noise(secret_key_encrypted); }

//----------------------------------------------------------------

int SEALCipher::print_noise(std::vector<seal::Ciphertext>& ciphs) {
  int min = decryptor.invariant_noise_budget(ciphs[0]);
  int max = min;
  for (uint64_t i = 1; i < ciphs.size(); i++) {
    int budget = decryptor.invariant_noise_budget(ciphs[i]);
    if (budget > max) max = budget;
    if (budget < min) min = budget;
  }
  std::cout << "min noise budget: " << min << std::endl;
  std::cout << "max noise budget: " << max << std::endl;
  return min;
}

//----------------------------------------------------------------

int SEALCipher::print_noise(seal::Ciphertext& ciph) {
  int noise = decryptor.invariant_noise_budget(ciph);
  std::cout << "noise budget: " << noise << std::endl;
  return noise;
}

//----------------------------------------------------------------

void SEALCipher::print_parameters() {
  // Verify parameters
  if (!context) {
    throw std::invalid_argument("context is not set");
  }
  auto& context_data = *context->key_context_data();

  /*
  Which scheme are we using?
  */
  std::string scheme_name;
  switch (context_data.parms().scheme()) {
    case seal::scheme_type::bfv:
      scheme_name = "BFV";
      break;
    case seal::scheme_type::ckks:
      scheme_name = "CKKS";
      break;
    default:
      throw std::invalid_argument("unsupported scheme");
  }
  std::cout << "/" << std::endl;
  std::cout << "| Encryption parameters:" << std::endl;
  std::cout << "|   scheme: " << scheme_name << std::endl;
  std::cout << "|   poly_modulus_degree: "
            << context_data.parms().poly_modulus_degree() << std::endl;

  /*
  Print the size of the true (product) coefficient modulus.
  */
  std::cout << "|   coeff_modulus size: ";
  std::cout << context_data.total_coeff_modulus_bit_count() << " (";
  auto coeff_modulus = context_data.parms().coeff_modulus();
  std::size_t coeff_mod_count = coeff_modulus.size();
  for (std::size_t i = 0; i < coeff_mod_count - 1; i++) {
    std::cout << coeff_modulus[i].bit_count() << " + ";
  }
  std::cout << coeff_modulus.back().bit_count();
  std::cout << ") bits" << std::endl;

  /*
  For the BFV scheme print the plain_modulus parameter.
  */
  if (context_data.parms().scheme() == seal::scheme_type::bfv) {
    std::cout << "|   plain_modulus: "
              << context_data.parms().plain_modulus().value() << std::endl;
  }

  std::cout << "\\" << std::endl;
}

void SEALCipher::halfAdder(e_bit& c_out, e_bit& s, const e_bit& a,
                           const e_bit& b) {
  evaluator.multiply(a, b, c_out);
  evaluator.relinearize_inplace(c_out, he_rk);

  evaluator.add(a, b, s);
}

void SEALCipher::fullAdder(e_bit& c_out, e_bit& s, const e_bit& a,
                           const e_bit& b, const e_bit& c_in) {
  e_bit tmp_a, tmp_b, tmp_c;
  evaluator.add(a, c_in, tmp_a);
  evaluator.add(b, c_in, tmp_b);
  evaluator.multiply(tmp_a, tmp_b, tmp_c);
  evaluator.relinearize_inplace(tmp_c, he_rk);
  evaluator.add_inplace(tmp_c, c_in);

  evaluator.add(a, b, s);
  evaluator.add_inplace(s, c_in);

  c_out = tmp_c;
}

void SEALCipher::rippleCarryAdder(e_int& s, const e_int& a, const e_int& b) {
  size_t n = a.size();
  if (s.size() != n) s.resize(n);
  e_bit c;
  halfAdder(c, s[0], a[0], b[0]);
  for (size_t i = 1; i < n - 1; i++) fullAdder(c, s[i], a[i], b[i], c);
  evaluator.add(a[n - 1], b[n - 1], s[n - 1]);
  evaluator.add_inplace(s[n - 1], c);
}

void SEALCipher::fpg(const std::vector<e_bit>& g, const std::vector<e_bit>& p,
                     size_t i, e_bit& out_g, e_bit& out_p) {
  // out_p
  evaluator.multiply(p[i], p[i + 1], out_p);
  evaluator.relinearize_inplace(out_p, he_rk);
  e_bit tmp;
  evaluator.multiply(p[i + 2], p[i + 3], tmp);
  evaluator.relinearize_inplace(tmp, he_rk);
  evaluator.multiply_inplace(out_p, tmp);
  evaluator.relinearize_inplace(out_p, he_rk);

  // out_g
  evaluator.multiply(g[i], p[i + 1], out_g);
  evaluator.relinearize_inplace(out_g, he_rk);
  evaluator.multiply_inplace(out_g, tmp);
  evaluator.relinearize_inplace(out_g, he_rk);
  evaluator.multiply_inplace(tmp, g[i + 1]);
  evaluator.relinearize_inplace(tmp, he_rk);
  evaluator.add_inplace(out_g, tmp);
  evaluator.add_inplace(out_g, g[i + 3]);
  evaluator.multiply(g[i + 2], p[i + 3], tmp);
  evaluator.relinearize_inplace(tmp, he_rk);
  evaluator.add_inplace(out_g, tmp);
}

void SEALCipher::carryLookaheadAdder(e_int& s, const e_int& a, const e_int& b,
                                     int levels, int size) {
  if (levels > 3 || levels < 1)
    throw std::runtime_error("number of CLA levels not supported");

  size_t bitsize = size;
  for (int i = 1; i < levels; i++) bitsize *= size;

  if (s.size() != bitsize) s.resize(bitsize);

  std::vector<std::vector<e_bit>> g(levels), p(levels);
  std::vector<e_bit> c(bitsize);

  // claculate g, p
  g[0].resize(bitsize);
  p[0].resize(bitsize);
  for (size_t i = 0; i < bitsize; i++) {
    evaluator.add(a[i], b[i], p[0][i]);
    evaluator.multiply(a[i], b[i], g[0][i]);
    evaluator.relinearize_inplace(g[0][i], he_rk);
  }

  CLAinternal(s, bitsize, levels, size, g, p, c);
}

void SEALCipher::CLAinternal(e_int& s, size_t bitsize, size_t levels,
                             size_t size, std::vector<std::vector<e_bit>>& g,
                             std::vector<std::vector<e_bit>>& p,
                             std::vector<e_bit>& c) {
  size_t lim = bitsize / size;
  for (size_t l = 1; l < levels; l++) {
    g[l].resize(lim);
    p[l].resize(lim);
    for (size_t i = 0; i < lim; i++)
      fpg(g[l - 1], p[l - 1], size * i, g[l][i], p[l][i]);
    lim /= size;
  }

  int curr_level = levels - 1;

  for (size_t k = 0; k < size - 1; k++) {
    size_t src_ind = bitsize / size * k;
    size_t g_p_ind = src_ind * size / bitsize;
    size_t des_ind = bitsize / size * (k + 1);
    if (src_ind == 0) {
      c[des_ind] = g[curr_level][0];
      continue;
    }
    evaluator.multiply(c[src_ind], p[curr_level][g_p_ind], c[des_ind]);
    evaluator.relinearize_inplace(c[des_ind], he_rk);
    evaluator.add_inplace(c[des_ind], g[curr_level][g_p_ind]);
  }

  curr_level--;
  if (curr_level >= 0) {
    for (size_t k = 0; k < size; k++) {
      for (size_t j = 0; j < size - 1; j++) {
        size_t src_ind = bitsize / size * k + bitsize / size / size * j;
        size_t g_p_ind = src_ind * size * size / bitsize;
        size_t des_ind = bitsize / size * k + bitsize / size / size * (j + 1);
        if (src_ind == 0) {
          c[des_ind] = g[curr_level][0];
          continue;
        }
        evaluator.multiply(c[src_ind], p[curr_level][g_p_ind], c[des_ind]);
        evaluator.relinearize_inplace(c[des_ind], he_rk);
        evaluator.add_inplace(c[des_ind], g[curr_level][g_p_ind]);
      }
    }
  }

  curr_level--;
  if (curr_level >= 0) {
    for (size_t k = 0; k < size; k++) {
      for (size_t j = 0; j < size; j++) {
        for (size_t i = 0; i < size - 1; i++) {
          size_t src_ind = bitsize / size * k + bitsize / size / size * j + i;
          size_t g_p_ind = src_ind * size * size * size / bitsize;
          size_t des_ind =
              bitsize / size * k + bitsize / size / size * j + (i + 1);
          if (src_ind == 0) {
            c[des_ind] = g[curr_level][0];
            continue;
          }
          evaluator.multiply(c[src_ind], p[curr_level][g_p_ind], c[des_ind]);
          evaluator.relinearize_inplace(c[des_ind], he_rk);
          evaluator.add_inplace(c[des_ind], g[curr_level][g_p_ind]);
        }
      }
    }
  }

  s[0] = p[0][0];
  for (size_t i = 1; i < bitsize; i++) {
    evaluator.add(p[0][i], c[i], s[i]);
  }
}

void SEALCipher::encrypt(e_int& out, uint16_t in) {
  size_t bitsize = sizeof(in) * 8;
  out.reserve(bitsize);
  for (size_t i = 0; i < bitsize; i++) {
    int32_t bit = (in >> i) & 1;
    seal::Plaintext p;
    p = bit;
    e_bit c;
    encryptor.encrypt(p, c);
    out.push_back(std::move(c));
  }
}

void SEALCipher::encrypt(e_int& out, uint64_t in, size_t bitsize) {
  out.reserve(bitsize);
  for (size_t i = 0; i < bitsize; i++) {
    int32_t bit = (in >> i) & 1;
    seal::Plaintext p;
    p = bit;
    e_bit c;
    encryptor.encrypt(p, c);
    out.push_back(std::move(c));
  }
}

void SEALCipher::decrypt(e_int& in, uint16_t& out) {
  out = 0;
  size_t bitsize = std::min(sizeof(out) * 8, in.size());
  for (size_t i = 0; i < bitsize; i++) {
    seal::Plaintext p;
    decryptor.decrypt(in[i], p);
    uint16_t bit = p[0];
    out |= (bit << i);
  }
}

void SEALCipher::decrypt(e_int& in, uint64_t& out) {
  out = 0;
  size_t bitsize = std::min(sizeof(out) * 8, in.size());
  for (size_t i = 0; i < bitsize; i++) {
    seal::Plaintext p;
    decryptor.decrypt(in[i], p);
    uint64_t bit = p[0];
    out |= (bit << i);
  }
}

void SEALCipher::decode(e_vector& out, std::vector<seal::Ciphertext> encoded,
                        size_t bitsize) {
  size_t size = encoded.size() / bitsize;
  if (out.size() != size) out.resize(size);

  for (size_t i = 0; i < size; i++) {
    out[i].resize(bitsize);
    for (size_t k = 0; k < bitsize; k++) {
      out[i][k] = encoded[i * bitsize + k];
    }
  }
}

// n x n = n bit multiplier
void SEALCipher::multiply(e_int& s, const e_int& a, const e_int& b) {
  size_t n = a.size();

  std::vector<e_int> tree(n);
  for (size_t i = 0; i < n; i++) {
    tree[i].resize(n - i);
    for (size_t j = 0; j < n - i; j++) {
      evaluator.multiply(a[j], b[i], tree[i][j]);
      evaluator.relinearize_inplace(tree[i][j], he_rk);
    }
  }

  treeAddMul(tree);
  s = tree[0];
}

void SEALCipher::treeAddMul(std::vector<e_int>& tree) {
  auto len = tree.size();

  // tree add
  while (len != 1) {
    auto new_len = len / 2;
    for (unsigned int i = 0; i < new_len; i++) {
      size_t len1 = tree[2 * i].size();
      size_t len2 = tree[2 * i + 1].size();
      size_t diff = len1 - len2;
      e_bit c;
      tree[i].resize(len1);
      for (size_t j = 0; j < diff; j++) tree[i][j] = tree[2 * i][j];
      halfAdder(c, tree[i][diff], tree[2 * i][diff], tree[2 * i + 1][0]);
      for (size_t j = diff + 1; j < len1 - 1; j++)
        fullAdder(c, tree[i][j], tree[2 * i][j], tree[2 * i + 1][j - diff], c);
      if (diff + 1 < len1) {
        // already did that
        evaluator.add(tree[2 * i][len1 - 1], tree[2 * i + 1][len1 - 1 - diff],
                      tree[i][len1 - 1]);
        evaluator.add_inplace(tree[i][len1 - 1], c);
      }
    }
    if (len % 2) {
      tree[new_len] = tree[len - 1];
      new_len++;
    }
    len = new_len;
  }
}

void SEALCipher::treeAdd(std::vector<e_int>& tree) {
  auto len = tree.size();

  size_t bitsize = tree[0].size();

  // tree add
  while (len != 1) {
    auto new_len = len / 2;
    for (unsigned int i = 0; i < new_len; i++) {
      if (bitsize == 16)
        carryLookaheadAdder(tree[i], tree[2 * i], tree[2 * i + 1]);
      else if (bitsize == 64)
        carryLookaheadAdder(tree[i], tree[2 * i], tree[2 * i + 1], 3);
      else
        rippleCarryAdder(tree[i], tree[2 * i], tree[2 * i + 1]);
    }
    if (len % 2) {
      tree[new_len] = tree[len - 1];
      new_len++;
    }
    len = new_len;
  }
}

void SEALCipher::multiplyPlain(e_int& s, const e_int& a, const uint64_t b) {
  size_t n = a.size();

  if (!b) {
    seal::Plaintext p;
    p = 0;
    e_bit c;
    encryptor.encrypt(p, c);
    s.clear();
    s.reserve(n);
    s.insert(s.begin(), n, c);
    return;
  }

  std::vector<e_int> tree;
  tree.reserve(n);
  for (size_t i = 0; i < n; i++) {
    int32_t bit = (b >> i) & 1;
    if (!bit) continue;
    tree.emplace_back(a.begin(), a.end() - i);
  }

  treeAddMul(tree);
  s.clear();
  s.reserve(n);

  size_t diff = n - tree[0].size();
  if (diff) {
    // padd with 0
    seal::Plaintext p;
    p = 0;
    e_bit c;
    encryptor.encrypt(p, c);
    s.insert(s.begin(), diff, c);
  }
  s.insert(s.end(), tree[0].begin(), tree[0].end());
}

void SEALCipher::halfAdderPlain(e_bit& c_out, e_bit& s, const e_bit& a,
                                const bool b) {
  if (b) {
    c_out = a;
    seal::Plaintext p;
    p = b;
    evaluator.add_plain(a, p, s);
    return;
  }

  seal::Plaintext p;
  p = 0;
  encryptor.encrypt(p, c_out);
  s = a;
}

void SEALCipher::fullAdderPlain(e_bit& c_out, e_bit& s, const e_bit& a,
                                const bool b, const e_bit& c_in) {
  e_bit tmp_a, tmp_c;
  if (b) {
    seal::Plaintext p;
    p = b;
    evaluator.add_plain(a, p, tmp_a);
    evaluator.multiply(c_in, tmp_a, tmp_c);
    evaluator.relinearize_inplace(tmp_c, he_rk);
    evaluator.add_inplace(tmp_c, a);

    evaluator.add(a, c_in, s);
    evaluator.add_plain_inplace(s, p);
  } else {
    evaluator.multiply(c_in, a, tmp_c);
    evaluator.relinearize_inplace(tmp_c, he_rk);

    evaluator.add(a, c_in, s);
  }
  c_out = tmp_c;
}

void SEALCipher::rippleCarryAdderPlain(e_int& s, const e_int& a,
                                       const uint64_t b) {
  if (!b) {
    s = a;
    return;
  }

  size_t n = a.size();
  if (s.size() != n) s.resize(n);
  e_bit c;

  bool bit = b & 1;
  halfAdderPlain(c, s[0], a[0], bit);
  for (size_t i = 1; i < n - 1; i++) {
    bit = (b >> i) & 1;
    fullAdderPlain(c, s[i], a[i], bit, c);
  }
  bit = (b >> (n - 1)) & 1;
  evaluator.add(a[n - 1], c, s[n - 1]);
  if (bit) {
    seal::Plaintext p;
    p = bit;
    evaluator.add_plain_inplace(s[n - 1], p);
  }
}

void SEALCipher::carryLookaheadAdderPlain(e_int& s, const e_int& a,
                                          const uint64_t b, int levels,
                                          int size) {
  if (!b) {
    s = a;
    return;
  }

  if (levels > 3 || levels < 1)
    throw std::runtime_error("number of CLA levels not supported");

  size_t bitsize = size;
  for (size_t i = 1; i < levels; i++) bitsize *= size;

  if (s.size() != bitsize) s.resize(bitsize);

  std::vector<std::vector<e_bit>> g(levels), p(levels);
  std::vector<e_bit> c(bitsize);

  // claculate g, p
  g[0].resize(bitsize);
  p[0].resize(bitsize);
  for (size_t i = 0; i < bitsize; i++) {
    bool bit = (b >> i) & 1;
    if (bit) {
      seal::Plaintext pl;
      pl = bit;
      evaluator.add_plain(a[i], pl, p[0][i]);
      g[0][i] = a[i];
      continue;
    }
    p[0][i] = a[i];
    seal::Plaintext pl;
    pl = 0;
    encryptor.encrypt(pl, g[0][i]);
  }

  CLAinternal(s, bitsize, levels, size, g, p, c);
}

// vo = M * vi
void SEALCipher::matMul(e_vector& vo, const matrix& M, const e_vector& vi) {
  size_t cols = vi.size();
  size_t rows = M.size();
  if (vo.size() != rows) vo.resize(rows);

  for (size_t row = 0; row < rows; row++) {
    std::cout << "row " << row << std::endl;
    std::vector<e_int> tree(cols);
    for (size_t col = 0; col < cols; col++) {
      multiplyPlain(tree[col], vi[col], M[row][col]);
    }
    treeAdd(tree);
    vo[row] = tree[0];
  }
}

// vo = vi + b
void SEALCipher::vecAdd(e_vector& vo, const e_vector& vi, const vector& b) {
  size_t rows = vi.size();
  if (vo.size() != rows) vo.resize(rows);

  size_t bitsize = vi[0].size();
  for (size_t row = 0; row < rows; row++) {
    if (bitsize == 16)
      carryLookaheadAdderPlain(vo[row], vi[row], b[row]);
    else if (bitsize == 64)
      carryLookaheadAdderPlain(vo[row], vi[row], b[row], 3);
    else
      rippleCarryAdderPlain(vo[row], vi[row], b[row]);
  }
}

// vo = M * vi + b
void SEALCipher::affine(e_vector& vo, const matrix& M, const e_vector& vi,
                        const vector& b) {
  matMul(vo, M, vi);
  vecAdd(vo, vo, b);
}
