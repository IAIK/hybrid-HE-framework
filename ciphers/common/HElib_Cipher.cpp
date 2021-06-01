#include "HElib_Cipher.h"

#include <helib/binaryArith.h>

#include <iostream>

#include "matrix_helib.h"

using namespace helib;

HElibCipher::HElibCipher(BlockCipherParams params,
                         std::vector<uint8_t> secret_key,
                         std::shared_ptr<helib::Context> con, long L, long c,
                         bool packed)
    : secret_key(secret_key),
      params(params),
      context(con),
      he_sk(*context),
      ea(context->getEA()) {
  if (secret_key.size() != params.key_size_bytes)
    throw std::runtime_error("Invalid Key length");

  nslots = ea.size();

  he_sk.GenSecKey();
  if (packed) addSome1DMatrices(he_sk);
  he_pk = std::make_unique<helib::PubKey>(he_sk);
}

std::shared_ptr<helib::Context> HElibCipher::create_context(long m, long p,
                                                            long r, long L,
                                                            long c, long d,
                                                            long k, long s) {
  if (!m) m = FindM(k, L, c, p, d, s, 0);

  return std::shared_ptr<helib::Context>(helib::ContextBuilder<helib::BGV>()
                                             .m(m)
                                             .p(p)
                                             .r(r)
                                             .bits(L)
                                             .c(c)
                                             .buildPtr());
}

int HElibCipher::print_noise() { return print_noise(secret_key_encrypted); }

int HElibCipher::print_noise(std::vector<helib::Ctxt>& ciphs) {
  int min = ciphs[0].bitCapacity();
  int max = min;
  for (uint64_t i = 1; i < ciphs.size(); i++) {
    int budget = ciphs[i].bitCapacity();
    if (budget > max) max = budget;
    if (budget < min) min = budget;
  }
  std::cout << "min noise budget: " << min << std::endl;
  std::cout << "max noise budget: " << max << std::endl;
  return min;
}

int HElibCipher::print_noise(helib::Ctxt& ciph) {
  int noise = ciph.bitCapacity();
  std::cout << "noise budget: " << noise << std::endl;
  return noise;
}

void HElibCipher::print_parameters() {
  if (!context) {
    throw std::invalid_argument("context is not set");
  }

  std::cout << "/" << std::endl;
  std::cout << "| Encryption parameters:" << std::endl;
  std::cout << "|   scheme: BGV " << std::endl;
  std::cout << "|   slots: " << context->getNSlots() << std::endl;
  std::cout << "|   bootstrappable: " << context->isBootstrappable()
            << std::endl;
  std::cout << "|   m: " << context->getM() << std::endl;
  std::cout << "|   phi(m): " << context->getPhiM() << std::endl;
  std::cout << "|   plain_modulus: " << context->getP() << std::endl;
  std::cout << "|   cipher mod size (bits): " << context->bitSizeOfQ()
            << std::endl;
  std::cout << "|   r: " << context->getR() << std::endl;
  std::cout << "|   sec level: " << context->securityLevel() << std::endl;
  std::cout << "\\" << std::endl;
}

void HElibCipher::halfAdder(e_bit& c_out, e_bit& s, const e_bit& a,
                            const e_bit& b) {
  c_out = a;
  c_out.multiplyBy(b);

  s = a;
  s += b;
}

void HElibCipher::fullAdder(e_bit& c_out, e_bit& s, const e_bit& a,
                            const e_bit& b, const e_bit& c_in) {
  e_bit tmp_a(*he_pk), tmp_c(*he_pk);
  tmp_a = a;
  tmp_a += c_in;
  tmp_c = b;
  tmp_c += c_in;
  tmp_c.multiplyBy(tmp_a);
  tmp_c += c_in;

  s = a;
  s += b;
  s += c_in;

  c_out = tmp_c;
}

void HElibCipher::rippleCarryAdder(e_int& s, const e_int& a, const e_int& b) {
  size_t n = a.size();
  if (s.size() != n) s.resize(n, {ZeroCtxtLike, a[0]});
  e_bit c(*he_pk);
  halfAdder(c, s[0], a[0], b[0]);
  for (size_t i = 1; i < n - 1; i++) fullAdder(c, s[i], a[i], b[i], c);
  s[n - 1] = a[n - 1];
  s[n - 1] += b[n - 1];
  s[n - 1] += c;
}

void HElibCipher::fpg(const std::vector<e_bit>& g, const std::vector<e_bit>& p,
                      size_t i, e_bit& out_g, e_bit& out_p) {
  // out_p
  out_p = p[i];
  out_p.multiplyBy(p[i + 1]);
  e_bit tmp = p[i + 2];
  tmp.multiplyBy(p[i + 3]);
  out_p.multiplyBy(tmp);

  // out_g
  out_g = g[i];
  out_g.multiplyBy(p[i + 1]);
  out_g.multiplyBy(tmp);
  tmp.multiplyBy(g[i + 1]);
  out_g += tmp;
  out_g += g[i + 3];
  tmp = g[i + 2];
  tmp.multiplyBy(p[i + 3]);
  out_g += tmp;
}

void HElibCipher::carryLookaheadAdder(e_int& s, const e_int& a, const e_int& b,
                                      int levels, int size) {
  if (levels > 3 || levels < 1)
    throw std::runtime_error("number of CLA levels not supported");

  size_t bitsize = size;
  for (int i = 1; i < levels; i++) bitsize *= size;

  if (s.size() != bitsize) s.resize(bitsize, {ZeroCtxtLike, a[0]});

  std::vector<std::vector<e_bit>> g(levels), p(levels);
  std::vector<e_bit> c(bitsize, {ZeroCtxtLike, a[0]});

  // claculate g, p
  g[0].resize(bitsize, {ZeroCtxtLike, a[0]});
  p[0].resize(bitsize, {ZeroCtxtLike, a[0]});
  for (size_t i = 0; i < bitsize; i++) {
    p[0][i] = a[i];
    p[0][i] += b[i];
    g[0][i] = a[i];
    g[0][i].multiplyBy(b[i]);
  }

  CLAinternal(s, bitsize, levels, size, g, p, c);
}

void HElibCipher::CLAinternal(e_int& s, size_t bitsize, size_t levels,
                              size_t size, std::vector<std::vector<e_bit>>& g,
                              std::vector<std::vector<e_bit>>& p,
                              std::vector<e_bit>& c) {
  size_t lim = bitsize / size;
  for (size_t l = 1; l < levels; l++) {
    g[l].resize(lim, {ZeroCtxtLike, c[0]});
    p[l].resize(lim, {ZeroCtxtLike, c[0]});
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
    c[des_ind] = c[src_ind];
    c[des_ind].multiplyBy(p[curr_level][g_p_ind]);
    c[des_ind] += g[curr_level][g_p_ind];
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
        c[des_ind] = c[src_ind];
        c[des_ind].multiplyBy(p[curr_level][g_p_ind]);
        c[des_ind] += g[curr_level][g_p_ind];
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
          c[des_ind] = c[src_ind];
          c[des_ind].multiplyBy(p[curr_level][g_p_ind]);
          c[des_ind] += g[curr_level][g_p_ind];
        }
      }
    }
  }

  s[0] = p[0][0];
  for (size_t i = 1; i < bitsize; i++) {
    s[i] = p[0][i];
    s[i] += c[i];
  }
}

void HElibCipher::encrypt(e_int& out, uint16_t in) {
  size_t bitsize = sizeof(in) * 8;
  out.reserve(bitsize);
  std::vector<long> p(nslots, 0);
  for (size_t i = 0; i < bitsize; i++) {
    int32_t bit = (in >> i) & 1;
    Ctxt c(*he_pk);
    p[0] = bit;
    ea.encrypt(c, *he_pk, p);
    out.push_back(std::move(c));
  }
}

void HElibCipher::encrypt(e_int& out, uint64_t in, size_t bitsize) {
  out.reserve(bitsize);
  std::vector<long> p(nslots, 0);
  for (size_t i = 0; i < bitsize; i++) {
    int32_t bit = (in >> i) & 1;
    Ctxt c(*he_pk);
    p[0] = bit;
    ea.encrypt(c, *he_pk, p);
    out.push_back(std::move(c));
  }
}

void HElibCipher::decrypt(e_int& in, uint16_t& out) {
  out = 0;
  size_t bitsize = std::min(sizeof(out) * 8, in.size());
  std::vector<long> p;
  for (size_t i = 0; i < bitsize; i++) {
    ea.decrypt(in[i], he_sk, p);
    uint8_t bit = p[0] & 0xFF;
    out |= (bit << i);
  }
}

void HElibCipher::decrypt(e_int& in, uint64_t& out) {
  out = 0;
  size_t bitsize = std::min(sizeof(out) * 8, in.size());
  std::vector<long> p;
  for (size_t i = 0; i < bitsize; i++) {
    ea.decrypt(in[i], he_sk, p);
    uint8_t bit = p[0] & 0xFF;
    out |= (bit << i);
  }
}

void HElibCipher::decode(e_vector& out, std::vector<helib::Ctxt> encoded,
                         size_t bitsize) {
  size_t size = encoded.size() / bitsize;
  if (out.size() != size) out.resize(size);

  for (size_t i = 0; i < size; i++) {
    out[i].resize(bitsize, {ZeroCtxtLike, encoded[0]});
    for (size_t k = 0; k < bitsize; k++) {
      out[i][k] = encoded[i * bitsize + k];
    }
  }
}

// n x n = n bit multiplier
void HElibCipher::multiply(e_int& s, const e_int& a, const e_int& b) {
  size_t n = a.size();

  if (USE_HELIB_CIRC_IMPL) {
    helib::CtPtrs_vectorCt w1(const_cast<e_int&>(a));
    helib::CtPtrs_vectorCt w2(const_cast<e_int&>(b));
    helib::CtPtrs_vectorCt wr(s);
    helib::multTwoNumbers(wr, w1, w2, false, n, nullptr);
    return;
  }

  std::vector<e_int> tree(n);
  for (size_t i = 0; i < n; i++) {
    tree[i].resize(n - i, {ZeroCtxtLike, a[0]});
    for (size_t j = 0; j < n - i; j++) {
      tree[i][j] = a[j];
      tree[i][j].multiplyBy(b[i]);
    }
  }

  treeAddMul(tree);
  s = tree[0];
}

void HElibCipher::treeAddMul(std::vector<e_int>& tree) {
  auto len = tree.size();

  // tree add
  while (len != 1) {
    auto new_len = len / 2;
    for (unsigned int i = 0; i < new_len; i++) {
      size_t len1 = tree[2 * i].size();
      size_t len2 = tree[2 * i + 1].size();
      size_t diff = len1 - len2;
      e_bit c(*he_pk);
      tree[i].resize(len1, {ZeroCtxtLike, tree[2 * i][0]});
      for (size_t j = 0; j < diff; j++) tree[i][j] = tree[2 * i][j];
      if (USE_HELIB_CIRC_IMPL) {
        e_int w1_tmp(tree[2 * i].begin() + diff, tree[2 * i].end());
        e_int wr_tmp;
        helib::CtPtrs_vectorCt w1(w1_tmp);
        helib::CtPtrs_vectorCt w2(tree[2 * i + 1]);
        helib::CtPtrs_vectorCt wr(wr_tmp);
        helib::addTwoNumbers(wr, w1, w2, len2, nullptr);
        for (size_t j = diff; j < len1; j++) tree[i][j] = wr_tmp[j - diff];
      } else {
        halfAdder(c, tree[i][diff], tree[2 * i][diff], tree[2 * i + 1][0]);
        for (size_t j = diff + 1; j < len1 - 1; j++)
          fullAdder(c, tree[i][j], tree[2 * i][j], tree[2 * i + 1][j - diff],
                    c);
        if (diff + 1 < len1) {
          // already did that
          tree[i][len1 - 1] = tree[2 * i][len1 - 1];
          tree[i][len1 - 1] += tree[2 * i + 1][len1 - 1 - diff];
          tree[i][len1 - 1] += c;
        }
      }
    }
    if (len % 2) {
      tree[new_len] = tree[len - 1];
      new_len++;
    }
    len = new_len;
  }
}

void HElibCipher::treeAdd(std::vector<e_int>& tree) {
  auto len = tree.size();

  size_t bitsize = tree[0].size();

  // tree add
  while (len != 1) {
    auto new_len = len / 2;
    for (unsigned int i = 0; i < new_len; i++) {
      if (USE_HELIB_CIRC_IMPL) {
        e_int w1_tmp(tree[2 * i]);
        helib::CtPtrs_vectorCt w1(w1_tmp);
        helib::CtPtrs_vectorCt w2(tree[2 * i + 1]);
        helib::CtPtrs_vectorCt wr(tree[i]);
        helib::addTwoNumbers(wr, w1, w2, bitsize, nullptr);
      } else if (bitsize == 16)
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

void HElibCipher::multiplyPlain(e_int& s, const e_int& a, const uint64_t b) {
  size_t n = a.size();

  if (!b) {
    s.clear();
    s.reserve(n);
    s.insert(s.begin(), n, {ZeroCtxtLike, a[0]});
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
    s.insert(s.begin(), diff, {ZeroCtxtLike, a[0]});
  }
  s.insert(s.end(), tree[0].begin(), tree[0].end());
}

void HElibCipher::halfAdderPlain(e_bit& c_out, e_bit& s, const e_bit& a,
                                 const bool b) {
  if (b) {
    c_out = a;
    NTL::ZZX p;
    std::vector<long> tmp(ea.size(), 0);
    tmp[0] = b;
    ea.encode(p, tmp);
    s.addConstant(p);
    return;
  }

  c_out = helib::Ctxt(ZeroCtxtLike, a);
  s = a;
}

void HElibCipher::fullAdderPlain(e_bit& c_out, e_bit& s, const e_bit& a,
                                 const bool b, const e_bit& c_in) {
  e_bit tmp_a(*he_pk), tmp_c(*he_pk);
  if (b) {
    NTL::ZZX p;
    std::vector<long> tmp(ea.size(), 0);
    tmp[0] = b;
    ea.encode(p, tmp);
    tmp_a = a;
    tmp_a.addConstant(p);
    tmp_c = c_in;
    tmp_c.multiplyBy(tmp_a);
    tmp_c += a;

    s = a;
    s += c_in;
    s.addConstant(p);
  } else {
    tmp_c = c_in;
    tmp_c.multiplyBy(a);

    s = a;
    s += c_in;
  }
  c_out = tmp_c;
}

void HElibCipher::rippleCarryAdderPlain(e_int& s, const e_int& a,
                                        const uint64_t b) {
  if (!b) {
    s = a;
    return;
  }

  size_t n = a.size();
  if (s.size() != n) s.resize(n, {ZeroCtxtLike, a[0]});
  e_bit c(*he_pk);

  bool bit = b & 1;
  halfAdderPlain(c, s[0], a[0], bit);
  for (size_t i = 1; i < n - 1; i++) {
    bit = (b >> i) & 1;
    fullAdderPlain(c, s[i], a[i], bit, c);
  }
  bit = (b >> (n - 1)) & 1;
  s[n - 1] = a[n - 1];
  s[n - 1] += c;
  if (bit) {
    NTL::ZZX p;
    std::vector<long> tmp(ea.size(), 0);
    tmp[0] = bit;
    ea.encode(p, tmp);
    s[n - 1].addConstant(p);
  }
}

void HElibCipher::carryLookaheadAdderPlain(e_int& s, const e_int& a,
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

  if (s.size() != bitsize) s.resize(bitsize, {ZeroCtxtLike, a[0]});

  std::vector<std::vector<e_bit>> g(levels), p(levels);
  std::vector<e_bit> c(bitsize, {ZeroCtxtLike, a[0]});

  // claculate g, p
  g[0].resize(bitsize, {ZeroCtxtLike, a[0]});
  p[0].resize(bitsize, {ZeroCtxtLike, a[0]});
  for (size_t i = 0; i < bitsize; i++) {
    bool bit = (b >> i) & 1;
    if (bit) {
      NTL::ZZX ptxt;
      std::vector<long> tmp(ea.size(), 0);
      tmp[0] = bit;
      ea.encode(ptxt, tmp);
      p[0][i] = a[i];
      p[0][i].addConstant(ptxt);
      g[0][i] = a[i];
      continue;
    }
    p[0][i] = a[i];
    g[0][i] = helib::Ctxt(ZeroCtxtLike, a[i]);
  }

  CLAinternal(s, bitsize, levels, size, g, p, c);
}

// vo = M * vi
void HElibCipher::matMul(e_vector& vo, const matrix& M, const e_vector& vi) {
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
void HElibCipher::vecAdd(e_vector& vo, const e_vector& vi, const vector& b) {
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
void HElibCipher::affine(e_vector& vo, const matrix& M, const e_vector& vi,
                         const vector& b) {
  matMul(vo, M, vi);
  vecAdd(vo, vo, b);
}

//----------------------------------------------------------------
// packed:
//----------------------------------------------------------------

//----------------------------------------------------------------

void HElibCipher::babystep_giantstep(
    helib::Ctxt& in_out, const std::vector<std::vector<uint8_t>>& mat) {
  const size_t matrix_dim = mat.size();

  if (matrix_dim != nslots && matrix_dim * 2 > nslots)
    throw std::runtime_error("too little slots for matmul implementation!");

  if (bsgs_n1 * bsgs_n2 != matrix_dim)
    std::cout << "WARNING: wrong bsgs parameters" << std::endl;

  // diagonal method preperation:
  std::vector<NTL::ZZX> matrix;
  matrix.reserve(matrix_dim);
  for (auto i = 0ULL; i < matrix_dim; i++) {
    std::vector<long> diag;
    auto k = i / bsgs_n1;
    diag.reserve(matrix_dim + k * bsgs_n1);

    for (auto j = 0ULL; j < matrix_dim; j++) {
      diag.push_back(mat[j][(i + j) % matrix_dim]);
    }
    // rotate:
    if (k)
      std::rotate(diag.begin(), diag.begin() + diag.size() - k * bsgs_n1,
                  diag.end());

    // prepare for non-full-packed rotations
    if (nslots != matrix_dim) {
      for (uint64_t index = 0; index < k * bsgs_n1; index++) {
        diag.push_back(diag[index]);
        diag[index] = 0;
      }
    }

    NTL::ZZX row;
    diag.resize(nslots, 0);
    ea.encode(row, diag);
    matrix.push_back(row);
  }

  // prepare for non-full-packed rotations
  if (nslots != matrix_dim) {
    helib::Ctxt in_rot = in_out;
    ea.rotate(in_rot, matrix_dim);
    in_out += in_rot;
  }

  helib::Ctxt outer_sum(*he_pk);

  // prepare rotations
  std::vector<helib::Ctxt> rot(bsgs_n1, in_out);
  for (uint64_t j = 1; j < bsgs_n1; j++) ea.rotate(rot[j], -j);

  for (uint64_t k = 0; k < bsgs_n2; k++) {
    helib::Ctxt inner_sum = rot[0];
    inner_sum.multByConstant(matrix[k * bsgs_n1]);
    for (uint64_t j = 1; j < bsgs_n1; j++) {
      helib::Ctxt temp = rot[j];
      temp.multByConstant(matrix[k * bsgs_n1 + j]);
      inner_sum += temp;
    }
    if (!k)
      outer_sum = inner_sum;
    else {
      ea.rotate(inner_sum, -k * bsgs_n1);
      outer_sum += inner_sum;
    }
  }
  in_out = outer_sum;
}

//----------------------------------------------------------------

void HElibCipher::helib_matmul(helib::Ctxt& in_out,
                               const std::vector<std::vector<uint8_t>>& mat) {
  FullMatrixCustom_GF2 matrix(ea, mat);
  MatMulFullExec mat_exec(matrix, false);
  mat_exec.mul(in_out);
}

//----------------------------------------------------------------

void HElibCipher::diagonal(helib::Ctxt& in_out,
                           const std::vector<std::vector<uint8_t>>& mat) {
  const size_t matrix_dim = mat.size();

  if (matrix_dim != nslots && matrix_dim * 2 > nslots)
    throw std::runtime_error("too little slots for matmul implementation!");

  // non-full-packed rotation preparation
  if (nslots != matrix_dim) {
    helib::Ctxt in_rot = in_out;
    ea.rotate(in_rot, matrix_dim);
    in_out += in_rot;
  }

  // diagonal method preperation:
  std::vector<NTL::ZZX> matrix;
  matrix.reserve(matrix_dim);
  for (auto i = 0ULL; i < matrix_dim; i++) {
    std::vector<long> diag;
    diag.reserve(matrix_dim);
    for (auto j = 0ULL; j < matrix_dim; j++) {
      diag.push_back(mat[j][(i + j) % matrix_dim]);
    }
    NTL::ZZX row;
    diag.resize(nslots, 0);
    ea.encode(row, diag);
    matrix.push_back(row);
  }

  helib::Ctxt sum = in_out;
  sum.multByConstant(matrix[0]);
  for (auto i = 1ULL; i < matrix_dim; i++) {
    helib::Ctxt tmp = in_out;
    ea.rotate(tmp, -i);
    tmp.multByConstant(matrix[i]);
    sum += tmp;
  }
  in_out = sum;
}

//----------------------------------------------------------------

void HElibCipher::activate_bsgs(bool activate) { use_bsgs = activate; }

//----------------------------------------------------------------

void HElibCipher::set_bsgs_params(uint64_t n1, uint64_t n2) {
  bsgs_n1 = n1;
  bsgs_n2 = n2;
}

// vo = M * vi
helib::Ctxt HElibCipher::packed_matMul(
    const std::vector<std::vector<uint8_t>>& M, const helib::Ctxt& vi) {
  helib::Ctxt vo = vi;
  if (USE_HELIB_MATMUL_IMPL)
    helib_matmul(vo, M);
  else if (use_bsgs && bsgs_n1 != 1 && bsgs_n2 != 1)
    babystep_giantstep(vo, M);
  else
    diagonal(vo, M);
  return vo;
}

// vo = M * vi + b
helib::Ctxt HElibCipher::packed_affine(
    const std::vector<std::vector<uint8_t>>& M, const helib::Ctxt& vi,
    const std::vector<uint8_t>& b) {
  helib::Ctxt vo = packed_matMul(M, vi);

  std::vector<long> p(b.begin(), b.end());
  p.resize(nslots, 0);
  NTL::ZZX p_enc;
  ea.encode(p_enc, p);
  vo.addConstant(p_enc);
  return vo;
}
