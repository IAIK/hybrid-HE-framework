#include "pasta_3_helib.h"

using namespace helib;

namespace PASTA_3 {

void PASTA_HElib::encrypt_key() {
  if (!power_of_2_ring)
    throw std::runtime_error("Only implemented for power-of-2 rings");

  secret_key_encrypted.resize(1, Ctxt(*he_pk));
  std::vector<long> p(nslots, 0);
  for (size_t i = 0; i < PASTA_T; i++) {
    p[i] = secret_key[i];
    p[i + (halfslots)] = secret_key[i + PASTA_T];
  }
  encrypt(secret_key_encrypted[0], p);
}

//----------------------------------------------------------------

std::vector<Ctxt> PASTA_HElib::HE_decrypt(std::vector<uint64_t>& ciphertexts) {
  if (!power_of_2_ring)
    throw std::runtime_error("Only implemented for power-of-2 rings");

  uint64_t nonce = 123456789;
  size_t size = ciphertexts.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Pasta pasta(plain_mod);
  std::vector<Ctxt> res(num_block, {ZeroCtxtLike, secret_key_encrypted[0]});

  for (uint64_t b = 0; b < num_block; b++) {
    pasta.init_shake(nonce, b);
    Ctxt state = secret_key_encrypted[0];

    for (uint8_t r = 1; r <= PASTA_R; r++) {
      std::cout << "round " << (int)r << std::endl;
      auto mat1 = pasta.get_random_matrix();
      auto mat2 = pasta.get_random_matrix();
      auto rc = pasta.get_rc_vec(halfslots);
      matmul(state, mat1, mat2);
      add_rc(state, rc);
      mix(state);
      if (r == PASTA_R)
        sbox_cube(state);
      else
        sbox_feistel(state);
      print_noise(state);
    }

    std::cout << "final add" << std::endl;
    auto mat1 = pasta.get_random_matrix();
    auto mat2 = pasta.get_random_matrix();
    auto rc = pasta.get_rc_vec(halfslots);
    matmul(state, mat1, mat2);
    add_rc(state, rc);
    mix(state);

    // remove second vector if needed
    if (REMOVE_SECOND_VEC) {
      std::vector<long> mask_vec(PASTA_T, 1);
      NTL::ZZX mask;
      encode(mask, mask_vec);
      state.multByConstant(mask);
    }

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

//----------------------------------------------------------------

std::vector<uint64_t> PASTA_HElib::decrypt_result(
    std::vector<Ctxt>& ciphertext) {
  std::vector<long> res;
  decrypt(ciphertext[0], res);
  res.resize(params.plain_size);
  return std::vector<uint64_t>(res.begin(), res.end());
}

//----------------------------------------------------------------

void PASTA_HElib::add_gk_indices() {
  gk_indices.emplace(0);
  gk_indices.emplace(1);
  if (PASTA_T != halfslots) gk_indices.emplace(-PASTA_T);
  if (use_bsgs) {
    for (long k = 1; k < BSGS_N2; k++) gk_indices.emplace(k * BSGS_N1);
    for (uint64_t j = 1; j < BSGS_N1; j++) gk_indices.emplace(j);
  }
}

//----------------------------------------------------------------

void PASTA_HElib::add_rc(helib::Ctxt& state, std::vector<uint64_t>& rc) {
  std::vector<long> p(rc.begin(), rc.end());
  NTL::ZZX p_enc;
  encode(p_enc, p);
  state.addConstant(p_enc);
}

//----------------------------------------------------------------

void PASTA_HElib::sbox_cube(helib::Ctxt& state) {
  Ctxt tmp = state;
  state.multiplyBy(state);  // includes relin
  state.multiplyBy(tmp);    // includes relin
}

//----------------------------------------------------------------

void PASTA_HElib::sbox_feistel(helib::Ctxt& state) {
  // rotate state
  Ctxt state_rot = state;
  rotate(state_rot, 1);

  // mask rotatet state
  NTL::ZZX mask;
  std::vector<long> mask_vec(PASTA_T + halfslots, 1);
  mask_vec[0] = 0;
  mask_vec[halfslots] = 0;
  for (uint16_t i = PASTA_T; i < halfslots; i++) mask_vec[i] = 0;
  encode(mask, mask_vec);
  state_rot.multByConstant(mask);
  // state_rot = 0, x_1, x_2, x_3, .... x_(t-1)

  // square
  state_rot.square();  // includes relin
  // state_rot = 0, x_1^2, x_2^2, x_3^2, .... x_(t-1)^2

  // add
  state += state_rot;
  // state = x_1, x_1^2 + x_2, x_2^2 + x_3, x_3^2 + x_4, .... x_(t-1)^2 + x_t
}

//----------------------------------------------------------------

void PASTA_HElib::matmul(helib::Ctxt& state,
                         const std::vector<std::vector<uint64_t>>& mat1,
                         const std::vector<std::vector<uint64_t>>& mat2) {
  if (use_bsgs) {
    babystep_giantstep(state, mat1, mat2);
  } else {
    diagonal(state, mat1, mat2);
  }
}

//----------------------------------------------------------------

void PASTA_HElib::babystep_giantstep(
    helib::Ctxt& state, const std::vector<std::vector<uint64_t>>& mat1,
    const std::vector<std::vector<uint64_t>>& mat2) {
  const size_t matrix_dim = PASTA_T;

  if (matrix_dim * 2 != nslots && matrix_dim * 4 > nslots)
    throw std::runtime_error("too little slots for matmul implementation!");

  if (BSGS_N1 * BSGS_N2 != matrix_dim)
    std::cout << "WARNING: wrong bsgs parameters" << std::endl;

  // diagonal method preperation:
  std::vector<NTL::ZZX> matrix;
  matrix.reserve(matrix_dim);
  for (auto i = 0ULL; i < matrix_dim; i++) {
    std::vector<long> diag;
    diag.reserve(halfslots + matrix_dim);
    std::vector<long> tmp;
    tmp.reserve(matrix_dim);
    auto k = i / BSGS_N1;

    for (auto j = 0ULL; j < matrix_dim; j++) {
      diag.push_back(mat1[j][(j + matrix_dim - i) % matrix_dim]);
      tmp.push_back(mat2[j][(j + matrix_dim - i) % matrix_dim]);
    }

    // rotate:
    if (k) {
      std::rotate(diag.begin(), diag.begin() + k * BSGS_N1, diag.end());
      std::rotate(tmp.begin(), tmp.begin() + k * BSGS_N1, tmp.end());
    }

    // prepare for non-full-packed rotations
    if (halfslots != PASTA_T) {
      diag.resize(halfslots, 0);
      tmp.resize(halfslots, 0);
      for (uint64_t m = 0; m < k * BSGS_N1; m++) {
        uint64_t index_src = PASTA_T - 1 - m;
        uint64_t index_dest = halfslots - 1 - m;
        diag[index_dest] = diag[index_src];
        diag[index_src] = 0;
        tmp[index_dest] = tmp[index_src];
        tmp[index_src] = 0;
      }
    }
    // combine both diags
    diag.resize(nslots, 0);
    for (size_t j = halfslots; j < nslots; j++) {
      diag[j] = tmp[j - halfslots];
    }

    NTL::ZZX row;
    encode(row, diag);
    matrix.push_back(row);
  }

  // prepare for non-full-packed rotations
  if (halfslots != PASTA_T) {
    helib::Ctxt state_rot = state;
    rotate(state_rot, -PASTA_T);
    state += state_rot;
  }

  helib::Ctxt outer_sum(*he_pk);

  // prepare rotations
  std::vector<helib::Ctxt> rot(BSGS_N1, state);
  for (uint64_t j = 1; j < BSGS_N1; j++) rotate(rot[j], j);

  for (uint64_t k = 0; k < BSGS_N2; k++) {
    helib::Ctxt inner_sum = rot[0];
    inner_sum.multByConstant(matrix[k * BSGS_N1]);
    for (uint64_t j = 1; j < BSGS_N1; j++) {
      helib::Ctxt temp = rot[j];
      temp.multByConstant(matrix[k * BSGS_N1 + j]);
      inner_sum += temp;
    }
    if (!k)
      outer_sum = inner_sum;
    else {
      rotate(inner_sum, k * BSGS_N1);
      outer_sum += inner_sum;
    }
  }
  state = outer_sum;
}

//----------------------------------------------------------------

void PASTA_HElib::diagonal(helib::Ctxt& state,
                           const std::vector<std::vector<uint64_t>>& mat1,
                           const std::vector<std::vector<uint64_t>>& mat2) {
  const size_t matrix_dim = PASTA_T;

  if (matrix_dim * 2 != nslots && matrix_dim * 4 > nslots)
    throw std::runtime_error("too little slots for matmul implementation!");

  // non-full-packed rotation preparation
  if (halfslots != PASTA_T) {
    helib::Ctxt state_rot = state;
    rotate(state_rot, -PASTA_T);
    state += state_rot;
  }

  // diagonal method preperation:
  std::vector<NTL::ZZX> matrix;
  matrix.reserve(matrix_dim);
  for (auto i = 0ULL; i < matrix_dim; i++) {
    std::vector<long> diag(matrix_dim + halfslots, 0);
    for (auto j = 0ULL; j < matrix_dim; j++) {
      diag[j] = mat1[j][(j + matrix_dim - i) % matrix_dim];
      diag[j + halfslots] = mat2[j][(j + matrix_dim - i) % matrix_dim];
    }
    NTL::ZZX row;
    encode(row, diag);
    matrix.push_back(row);
  }

  helib::Ctxt sum = state;
  sum.multByConstant(matrix[0]);
  for (auto i = 1ULL; i < matrix_dim; i++) {
    helib::Ctxt tmp = state;
    rotate(tmp, i);
    tmp.multByConstant(matrix[i]);
    sum += tmp;
  }
  state = sum;
}

//----------------------------------------------------------------

void PASTA_HElib::mix(helib::Ctxt& state) {
  Ctxt tmp = state;
  rotate_columns(tmp);
  tmp += state;
  state += tmp;
}

}  // namespace PASTA_3
