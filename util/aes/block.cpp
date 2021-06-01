#include "block.h"

#include <iomanip>
#include <sstream>
#include <vector>

#include "BitIterator.h"

namespace osuCrypto {

const block ZeroBlock = toBlock(0, 0);
const block OneBlock = toBlock(0, 1);
const block AllOneBlock = toBlock(uint64_t(-1), uint64_t(-1));
const std::array<block, 2> zeroAndAllOne = {{ZeroBlock, AllOneBlock}};
const block CCBlock = toBlock(0xcccccccccccccccc, 0xcccccccccccccccc);
// ([]() {block cc; memset(&cc, 0xcc, sizeof(block)); return cc; })();

template <typename T>
void setBit(T& b, uint64_t idx) {
  *BitIterator((uint8_t*)&b, idx) = 1;
}

std::array<block, 2> shiftMod(uint64_t s) {
  if (s > 127) throw std::runtime_error("block shiftMod");

  static const constexpr std::array<std::uint64_t, 5> mod{0, 1, 2, 7, 128};
  //= 0b10000111;
  std::array<block, 2> mm{ZeroBlock, ZeroBlock};
  for (auto b : mod) {
    setBit(mm, b + s);
  }
  return mm;
}

namespace {

template <typename T>
std::string bits(T x, uint64_t width = 99999999) {
  std::stringstream ss;
  BitIterator iter((uint8_t*)&x, 0);
  for (uint64_t i = 0; i < sizeof(T) * 8; ++i) {
    if (i && (i % width == 0)) ss << " ";
    ss << *iter;

    ++iter;
  }
  return ss.str();
}
}  // namespace

}  // namespace osuCrypto

std::ostream& operator<<(std::ostream& out, const osuCrypto::block& blk) {
  out << std::hex;
  uint64_t* data = (uint64_t*)&blk;

  out << std::setw(16) << std::setfill('0') << data[1] << std::setw(16)
      << std::setfill('0') << data[0];

  out << std::dec << std::setw(0);
  return out;
}
