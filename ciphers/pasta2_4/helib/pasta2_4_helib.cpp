#include "pasta2_4_helib.h"

using namespace helib;

namespace PASTA2_4 {

void PASTA2_HElib::encrypt_key() {
  if (!power_of_2_ring)
    throw std::runtime_error("Only implemented for power-of-2 rings");

  secret_key_encrypted.resize(1, Ctxt(*he_pk));
  std::vector<long> p(nslots, 0);
  for (size_t i = 0; i < PASTA2_T; i++) {
    p[i] = secret_key[i];
    p[i + (halfslots)] = secret_key[i + PASTA2_T];
  }
  encrypt(secret_key_encrypted[0], p);
}

//----------------------------------------------------------------

std::vector<Ctxt> PASTA2_HElib::HE_decrypt(std::vector<uint64_t>& ciphertexts) {
  if (!power_of_2_ring)
    throw std::runtime_error("Only implemented for power-of-2 rings");

  uint64_t nonce = 123456789;
  size_t size = ciphertexts.size();

  size_t num_block = ceil((double)size / params.cipher_size);

  Pasta2 pasta2(instance);
  std::vector<Ctxt> res(num_block, {ZeroCtxtLike, secret_key_encrypted[0]});
  auto mat = encode_mat(instance.matrix, instance.matrix);

  for (uint64_t b = 0; b < num_block; b++) {
    pasta2.init_shake(nonce, b);
    Ctxt state = secret_key_encrypted[0];

    std::cout << "first random affine" << std::endl;
    auto mat1 = pasta2.get_random_matrixL();
    auto mat2 = pasta2.get_random_matrixR();
    auto rc = pasta2.get_rc_vec(halfslots);
    auto rand_mat = encode_mat(mat1, mat2);
    matmul(state, rand_mat);
    add_rc(state, rc);
    mix(state);

    for (uint8_t r = 0; r < PASTA2_R; r++) {
      std::cout << "round " << (int)r + 1 << std::endl;
      if (r == PASTA2_R - 1)
        sbox_cube(state);
      else
        sbox_feistel(state);
      matmul(state, mat);
      add_rc(state, r);
      mix(state);
      print_noise(state);
    }

    // remove second vector if needed
    if (REMOVE_SECOND_VEC) {
      std::vector<long> mask_vec(PASTA2_T, 1);
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

std::vector<uint64_t> PASTA2_HElib::decrypt_result(
    std::vector<Ctxt>& ciphertext) {
  std::vector<long> res;
  decrypt(ciphertext[0], res);
  res.resize(params.plain_size);
  return std::vector<uint64_t>(res.begin(), res.end());
}

//----------------------------------------------------------------

void PASTA2_HElib::add_gk_indices() {
  gk_indices.emplace(0);
  gk_indices.emplace(1);
  if (PASTA2_T != halfslots) gk_indices.emplace(-PASTA2_T);
  if (use_bsgs) {
    for (long k = 1; k < BSGS_N2; k++) gk_indices.emplace(k * BSGS_N1);
    for (uint64_t j = 1; j < BSGS_N1; j++) gk_indices.emplace(j);
  }
}

//----------------------------------------------------------------

void PASTA2_HElib::add_rc(helib::Ctxt& state, size_t r) {
  std::vector<long> p(halfslots + PASTA2_T, 0);
  for (uint16_t i = 0; i < PASTA2_T; i++) {
    p[i] = instance.rc1[r][i];
    p[i + halfslots] = instance.rc2[r][i];
  }
  NTL::ZZX p_enc;
  encode(p_enc, p);
  state.addConstant(p_enc);
}

//----------------------------------------------------------------

void PASTA2_HElib::add_rc(helib::Ctxt& state, std::vector<uint64_t>& rc) {
  std::vector<long> p(rc.begin(), rc.end());
  NTL::ZZX p_enc;
  encode(p_enc, p);
  state.addConstant(p_enc);
}

//----------------------------------------------------------------

void PASTA2_HElib::sbox_cube(helib::Ctxt& state) {
  Ctxt tmp = state;
  state.multiplyBy(state);  // includes relin
  state.multiplyBy(tmp);    // includes relin
}

//----------------------------------------------------------------

void PASTA2_HElib::sbox_feistel(helib::Ctxt& state) {
  // rotate state
  Ctxt state_rot = state;
  rotate(state_rot, 1);

  // mask rotatet state
  NTL::ZZX mask;
  std::vector<long> mask_vec(PASTA2_T + halfslots, 1);
  mask_vec[0] = 0;
  mask_vec[halfslots] = 0;
  for (uint16_t i = PASTA2_T; i < halfslots; i++) mask_vec[i] = 0;
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

std::vector<NTL::ZZX> PASTA2_HElib::encode_mat(
    const std::vector<std::vector<uint64_t>>& mat1,
    const std::vector<std::vector<uint64_t>>& mat2) {
  if (use_bsgs) {
    return encode_babystep_giantstep(mat1, mat2);
  } else {
    return encode_diagonal(mat1, mat2);
  }
}

//----------------------------------------------------------------

std::vector<NTL::ZZX> PASTA2_HElib::encode_babystep_giantstep(
    const std::vector<std::vector<uint64_t>>& mat1,
    const std::vector<std::vector<uint64_t>>& mat2) {
  const size_t matrix_dim = PASTA2_T;
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
    if (halfslots != PASTA2_T) {
      diag.resize(halfslots, 0);
      tmp.resize(halfslots, 0);
      for (uint64_t m = 0; m < k * BSGS_N1; m++) {
        uint64_t index_src = PASTA2_T - 1 - m;
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
  return matrix;
}

//----------------------------------------------------------------

std::vector<NTL::ZZX> PASTA2_HElib::encode_diagonal(
    const std::vector<std::vector<uint64_t>>& mat1,
    const std::vector<std::vector<uint64_t>>& mat2) {
  const size_t matrix_dim = PASTA2_T;
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
  return matrix;
}

//----------------------------------------------------------------

void PASTA2_HElib::matmul(helib::Ctxt& state, std::vector<NTL::ZZX>& mat) {
  if (use_bsgs) {
    babystep_giantstep(state, mat);
  } else {
    diagonal(state, mat);
  }
}

//----------------------------------------------------------------

void PASTA2_HElib::babystep_giantstep(helib::Ctxt& state,
                                      std::vector<NTL::ZZX>& matrix) {
  const size_t matrix_dim = PASTA2_T;

  if (matrix_dim * 2 != nslots && matrix_dim * 4 > nslots)
    throw std::runtime_error("too little slots for matmul implementation!");

  if (BSGS_N1 * BSGS_N2 != matrix_dim)
    std::cout << "WARNING: wrong bsgs parameters" << std::endl;

  // prepare for non-full-packed rotations
  if (halfslots != PASTA2_T) {
    helib::Ctxt state_rot = state;
    rotate(state_rot, -PASTA2_T);
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

void PASTA2_HElib::diagonal(helib::Ctxt& state, std::vector<NTL::ZZX>& matrix) {
  const size_t matrix_dim = PASTA2_T;

  if (matrix_dim * 2 != nslots && matrix_dim * 4 > nslots)
    throw std::runtime_error("too little slots for matmul implementation!");

  // non-full-packed rotation preparation
  if (halfslots != PASTA2_T) {
    helib::Ctxt state_rot = state;
    rotate(state_rot, -PASTA2_T);
    state += state_rot;
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

void PASTA2_HElib::mix(helib::Ctxt& state) {
  Ctxt tmp = state;
  rotate_columns(tmp);
  tmp += state;
  state += tmp;
}

}  // namespace PASTA2_4
