#pragma once

#include <NTL/ZZ.h>
#include <helib/FHE.h>
#include <helib/matmul.h>

#include <array>
#include <bitset>

NTL_CLIENT

class FullMatrixCustom_GF2 : public helib::MatMulFull_derived<helib::PA_GF2> {
  const helib::EncryptedArray& ea;
  std::vector<std::vector<uint8_t>> data;

 public:
  FullMatrixCustom_GF2(const helib::EncryptedArray& _ea,
                       const std::vector<std::vector<uint8_t>>& matrix)
      : ea(_ea), data(matrix) {}

  virtual bool get(RX& out, long i, long j) const override {
    // OLD: assert(i >= 0 && i < ea.size());
    helib::assertInRange(i, 0l, ea.size(), "Matrix index out of range");
    // OLD: assert(j >= 0 && j < ea.size());
    helib::assertInRange(j, 0l, ea.size(), "Matrix index out of range");
    // transpose for our purposes
    if (j >= data.size() || i >= data[j].size()) {
      return true;
    }
    if (data[j][i] == 0) return true;
    out = RX(data[j][i]);
    return false;
  }

  const helib::EncryptedArray& getEA() const override { return ea; }
};
