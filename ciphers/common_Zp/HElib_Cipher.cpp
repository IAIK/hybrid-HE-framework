#include "HElib_Cipher.h"

#include <iostream>
#include <limits>

#include "matrix_helib.h"

using namespace helib;

HElibZpCipher::HElibZpCipher(ZpCipherParams params,
                             std::vector<uint64_t> secret_key,
                             std::shared_ptr<helib::Context> con, uint64_t L,
                             uint64_t c, bool packed)
    : secret_key(secret_key),
      params(params),
      context(con),
      he_sk(*context),
      ea(context->getEA()) {
  if (secret_key.size() != params.key_size)
    throw std::runtime_error("Invalid Key length");

  plain_mod = con->getP();

  if (plain_mod > (uint64_t)std::numeric_limits<long>::max())
    throw std::runtime_error("plain size to big for long");

  nslots = ea.size();

  he_sk.GenSecKey();

  power_of_2_ring = isPowerOfTwo(context->getM());
}

//----------------------------------------------------------------

std::shared_ptr<helib::Context> HElibZpCipher::create_context(
    uint64_t m, uint64_t p, uint64_t r, uint64_t L, uint64_t c, uint64_t d,
    uint64_t k, uint64_t s) {
  if (!m) m = FindM(k, L, c, p, d, s, 0);

  return std::shared_ptr<helib::Context>(helib::ContextBuilder<helib::BGV>()
                                             .m(m)
                                             .p(p)
                                             .r(r)
                                             .bits(L)
                                             .c(c)
                                             .buildPtr());
}

//----------------------------------------------------------------

int HElibZpCipher::print_noise() { return print_noise(secret_key_encrypted); }

//----------------------------------------------------------------

int HElibZpCipher::print_noise(std::vector<helib::Ctxt>& ciphs) {
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

//----------------------------------------------------------------

int HElibZpCipher::print_noise(helib::Ctxt& ciph) {
  int noise = ciph.bitCapacity();
  std::cout << "noise budget: " << noise << std::endl;
  return noise;
}

//----------------------------------------------------------------

void HElibZpCipher::print_parameters() {
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

//----------------------------------------------------------------

bool HElibZpCipher::isPowerOfTwo(long x) {
  /* First x in the below expression is for the case when x is 0 */
  return x && (!(x & (x - 1)));
}

//----------------------------------------------------------------

void HElibZpCipher::encrypt(helib::Ctxt& ctxt, std::vector<long>& ptxt) {
  ptxt.resize(nslots, 0);
  if (power_of_2_ring) {
    std::vector<long> p_enc(nslots);
    for (size_t i = 0; i < nslots / 2; i++) {
      p_enc[2 * i] = ptxt[i];
      p_enc[2 * i + 1] = ptxt[i + nslots / 2];
    }
    ea.encrypt(ctxt, *he_pk, p_enc);
  } else
    ea.encrypt(ctxt, *he_pk, ptxt);
}

//----------------------------------------------------------------

void HElibZpCipher::decrypt(helib::Ctxt& ctxt, std::vector<long>& ptxt) {
  if (power_of_2_ring) {
    std::vector<long> p_enc(nslots);
    ptxt.resize(nslots);
    ea.decrypt(ctxt, he_sk, p_enc);
    for (size_t i = 0; i < nslots; i += 2) {
      ptxt[i / 2] = p_enc[i];
      ptxt[i / 2 + nslots / 2] = p_enc[i + 1];
    }
  } else
    ea.decrypt(ctxt, he_sk, ptxt);
}

//----------------------------------------------------------------

void HElibZpCipher::encode(NTL::ZZX& enc, std::vector<long>& dec) {
  dec.resize(nslots, 0);
  if (power_of_2_ring) {
    std::vector<long> p(nslots);
    for (size_t i = 0; i < nslots / 2; i++) {
      p[2 * i] = dec[i];
      p[2 * i + 1] = dec[i + nslots / 2];
    }
    ea.encode(enc, p);
  } else
    ea.encode(enc, dec);
}

//----------------------------------------------------------------

void HElibZpCipher::decode(NTL::ZZX& enc, std::vector<long>& dec) {
  if (power_of_2_ring) {
    std::vector<long> p(nslots);
    dec.resize(nslots);
    ea.decode(p, enc);
    for (size_t i = 0; i < nslots; i += 2) {
      dec[i / 2] = p[i];
      dec[i / 2 + nslots / 2] = p[i + 1];
    }
  } else
    ea.decode(dec, enc);
}

//----------------------------------------------------------------
void HElibZpCipher::rotate_rows(helib::Ctxt& ctxt, long step) {
  ctxt.smartAutomorph(get_elt_from_step(step));
}

//----------------------------------------------------------------

void HElibZpCipher::rotate_columns(helib::Ctxt& ctxt) {
  ctxt.smartAutomorph(context->getPhiM() - 1);
}

//----------------------------------------------------------------

void HElibZpCipher::rotate(helib::Ctxt& ctxt, long step) {
  if (power_of_2_ring)
    rotate_rows(ctxt, step);
  else
    ea.rotate(ctxt, step);
}

//----------------------------------------------------------------

long HElibZpCipher::get_elt_from_step(long step) {
  long n2 = nslots << 1;
  long row_size = nslots >> 1;
  if (!step) return context->getPhiM() - 1;
  long sign = step < 0;
  long step_abs = sign ? -step : step;
  if (step_abs >= row_size)
    throw std::runtime_error("error: step count too large!");
  step = sign ? row_size - step_abs : step_abs;

  long gen = 3;
  long elt = 1;
  for (long i = 0; i < step; i++) elt = (elt * gen) % n2;
  return elt;
}

//----------------------------------------------------------------

void HElibZpCipher::mask(helib::Ctxt& cipher, std::vector<long>& mask) {
  std::vector<long> p = mask;
  NTL::ZZX mask_enc;
  encode(mask_enc, mask);
  cipher.multByConstant(mask_enc);
}

//----------------------------------------------------------------

helib::Ctxt HElibZpCipher::flatten(std::vector<helib::Ctxt>& in) {
  helib::Ctxt out = in[0];
  for (size_t i = 1; i < in.size(); i++) {
    helib::Ctxt tmp = in[i];
    rotate(tmp, i * params.plain_size);
    out += tmp;
  }
  return out;
}

//----------------------------------------------------------------

void HElibZpCipher::babystep_giantstep(helib::Ctxt& in_out, const matrix& mat) {
  const size_t matrix_dim = mat.size();

  if ((!power_of_2_ring && matrix_dim != nslots && matrix_dim * 2 > nslots) ||
      (power_of_2_ring && matrix_dim * 2 != nslots && matrix_dim * 4 > nslots))
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
    if ((!power_of_2_ring && nslots != matrix_dim) ||
        (power_of_2_ring && nslots != 2 * matrix_dim)) {
      for (uint64_t index = 0; index < k * bsgs_n1; index++) {
        diag.push_back(diag[index]);
        diag[index] = 0;
      }
    }

    NTL::ZZX row;
    encode(row, diag);
    matrix.push_back(row);
  }

  // prepare for non-full-packed rotations
  if ((!power_of_2_ring && nslots != matrix_dim) ||
      (power_of_2_ring && nslots != 2 * matrix_dim)) {
    helib::Ctxt in_rot = in_out;
    rotate(in_rot, matrix_dim);
    in_out += in_rot;
  }

  helib::Ctxt outer_sum(*he_pk);

  // prepare rotations
  std::vector<helib::Ctxt> rot(bsgs_n1, in_out);
  for (uint64_t j = 1; j < bsgs_n1; j++) rotate(rot[j], -j);

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
      rotate(inner_sum, -k * bsgs_n1);
      outer_sum += inner_sum;
    }
  }
  in_out = outer_sum;
}

//----------------------------------------------------------------

void HElibZpCipher::helib_matmul(helib::Ctxt& in_out, const matrix& mat) {
  FullMatrixCustom matrix(ea, mat);
  MatMulFullExec mat_exec(matrix, false);
  mat_exec.mul(in_out);
}

//----------------------------------------------------------------

void HElibZpCipher::diagonal(helib::Ctxt& in_out, const matrix& mat) {
  const size_t matrix_dim = mat.size();

  if ((!power_of_2_ring && matrix_dim != nslots && matrix_dim * 2 > nslots) ||
      (power_of_2_ring && matrix_dim * 2 != nslots && matrix_dim * 4 > nslots))
    throw std::runtime_error("too little slots for matmul implementation!");

  // non-full-packed rotation preparation

  if ((!power_of_2_ring && nslots != matrix_dim) ||
      (power_of_2_ring && nslots != 2 * matrix_dim)) {
    helib::Ctxt in_rot = in_out;
    rotate(in_rot, matrix_dim);
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
    encode(row, diag);
    matrix.push_back(row);
  }

  helib::Ctxt sum = in_out;
  sum.multByConstant(matrix[0]);
  for (auto i = 1ULL; i < matrix_dim; i++) {
    helib::Ctxt tmp = in_out;
    rotate(tmp, -i);
    tmp.multByConstant(matrix[i]);
    sum += tmp;
  }
  in_out = sum;
}

//----------------------------------------------------------------

void HElibZpCipher::activate_bsgs(bool activate) { use_bsgs = activate; }

//----------------------------------------------------------------

void HElibZpCipher::set_bsgs_params(uint64_t n1, uint64_t n2) {
  bsgs_n1 = n1;
  bsgs_n2 = n2;
}

//----------------------------------------------------------------

void HElibZpCipher::add_some_gk_indices(std::set<long>& gk_ind) {
  for (auto& it : gk_ind) gk_indices.emplace(it);
}

//----------------------------------------------------------------

void HElibZpCipher::add_bsgs_indices(uint64_t n1, uint64_t n2) {
  size_t mul = n1 * n2;
  add_diagonal_indices(mul);
  if (n1 == 1 || n2 == 1) return;

  for (uint64_t k = 1; k < n2; k++) gk_indices.emplace(-k * n1);
  for (uint64_t j = 1; j < n1; j++) gk_indices.emplace(-j);
}

//----------------------------------------------------------------

void HElibZpCipher::add_diagonal_indices(size_t size) {
  if ((!power_of_2_ring && size != nslots) ||
      (power_of_2_ring && size * 2 != nslots))
    gk_indices.emplace(size);
  gk_indices.emplace(-1);
}

//----------------------------------------------------------------

void HElibZpCipher::create_pk(bool packed) {
  if (!packed) {
    he_pk = std::make_unique<helib::PubKey>(he_sk);
    return;
  }
  if (!power_of_2_ring || gk_indices.size() == 0) {
    addSome1DMatrices(he_sk);
    he_pk = std::make_unique<helib::PubKey>(he_sk);
    return;
  }

  std::set<long> vals;
  for (auto it : gk_indices) {
    vals.emplace(get_elt_from_step(it));
  }
  addTheseMatrices(he_sk, vals);
  he_pk = std::make_unique<helib::PubKey>(he_sk);
}

//----------------------------------------------------------------

size_t HElibZpCipher::get_cipher_size(helib::Ctxt& ct, bool mod_switch) {
  if (mod_switch) {
    ct.dropSmallAndSpecialPrimes();  // is there a better solution in HElib?
  }
  std::stringstream s;
  ct.writeTo(s);
  s.seekp(0, ios::end);
  auto size = s.tellp();
  return size;
}

//----------------------------------------------------------------
// non-packed:
//----------------------------------------------------------------

void HElibZpCipher::encrypt(helib::Ctxt& out, uint64_t in) {
  std::vector<long> p(nslots, 0);
  p[0] = in;
  ea.encrypt(out, *he_pk, p);
}

//----------------------------------------------------------------

void HElibZpCipher::decrypt(helib::Ctxt& in, uint64_t& out) {
  std::vector<long> p;
  ea.decrypt(in, he_sk, p);
  out = p[0];
}

//----------------------------------------------------------------

// vo = M * vi
void HElibZpCipher::matMul(std::vector<helib::Ctxt>& vo, const matrix& M,
                           const std::vector<helib::Ctxt>& vi) {
  size_t cols = vi.size();
  size_t rows = M.size();
  if (vo.size() != rows) vo.resize(rows, {ZeroCtxtLike, vi[0]});

  std::vector<long> p(nslots, 0);
  NTL::ZZX p_enc;

  for (size_t row = 0; row < rows; row++) {
    for (size_t col = 0; col < cols; col++) {
      p[0] = M[row][col];
      ea.encode(p_enc, p);
      helib::Ctxt tmp = vi[col];
      tmp.multByConstant(p_enc);
      if (col == 0)
        vo[row] = tmp;
      else
        vo[row] += tmp;
    }
  }
}

//----------------------------------------------------------------

// vo = vi + b
void HElibZpCipher::vecAdd(std::vector<helib::Ctxt>& vo,
                           const std::vector<helib::Ctxt>& vi,
                           const vector& b) {
  size_t rows = vi.size();
  if (vo.size() != rows) vo.resize(rows, {ZeroCtxtLike, vi[0]});

  std::vector<long> p(nslots, 0);
  NTL::ZZX p_enc;

  for (size_t row = 0; row < rows; row++) {
    p[0] = b[row];
    ea.encode(p_enc, p);
    vo[row] = vi[row];
    vo[row].addConstant(p_enc);
  }
}

//----------------------------------------------------------------

// vo = M * vi + b
void HElibZpCipher::affine(std::vector<helib::Ctxt>& vo, const matrix& M,
                           const std::vector<helib::Ctxt>& vi,
                           const vector& b) {
  matMul(vo, M, vi);
  vecAdd(vo, vo, b);
}

//----------------------------------------------------------------

void HElibZpCipher::square(std::vector<helib::Ctxt>& vo,
                           const std::vector<helib::Ctxt>& vi) {
  size_t rows = vi.size();
  if (vo.size() != rows) vo.resize(rows, {ZeroCtxtLike, vi[0]});

  for (size_t row = 0; row < rows; row++) {
    vo[row] = vi[row];
    vo[row].square();
  }
}

//----------------------------------------------------------------
// packed:
//----------------------------------------------------------------

helib::Ctxt HElibZpCipher::packed_encrypt(std::vector<uint64_t> in) {
  helib::Ctxt out(*he_pk);
  std::vector<long> p(in.begin(), in.end());
  encrypt(out, p);
  return out;
}

//----------------------------------------------------------------

void HElibZpCipher::packed_decrypt(helib::Ctxt& in, std::vector<uint64_t>& out,
                                   size_t size) {
  std::vector<long> p;
  decrypt(in, p);
  p.resize(size);
  out.clear();
  out.insert(out.begin(), p.begin(), p.end());
}

//----------------------------------------------------------------

// vo = M * vi
helib::Ctxt HElibZpCipher::packed_matMul(const matrix& M,
                                         const helib::Ctxt& vi) {
  helib::Ctxt vo = vi;
  if (!power_of_2_ring && USE_HELIB_MATMUL_IMPL)
    helib_matmul(vo, M);
  else if (use_bsgs && bsgs_n1 != 1 && bsgs_n2 != 1)
    babystep_giantstep(vo, M);
  else
    diagonal(vo, M);
  return vo;
}

//----------------------------------------------------------------

// vo = M * vi + b
helib::Ctxt HElibZpCipher::packed_affine(const matrix& M, const helib::Ctxt& vi,
                                         const vector& b) {
  helib::Ctxt vo = packed_matMul(M, vi);

  std::vector<long> p(b.begin(), b.end());
  NTL::ZZX p_enc;
  encode(p_enc, p);
  vo.addConstant(p_enc);
  return vo;
}

//----------------------------------------------------------------

helib::Ctxt HElibZpCipher::packed_square(const helib::Ctxt& vi) {
  helib::Ctxt vo = vi;
  vo.square();
  return vo;
}
