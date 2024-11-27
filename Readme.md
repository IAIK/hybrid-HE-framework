# Framework for Hybrid Homomorphic Encryption

This repository contains code to test and benchmark symmetric ciphers in hybrid homomorphic encryption. This code is also used in the evaluations of the ciphers in the paper [1].

## HE libraries

The following Homomorphic Encryption Libraries are part of the framework:

- [HElib](https://github.com/homenc/HElib/) (version 2.2.2)
- [SEAL](https://github.com/Microsoft/SEAL/) (version 3.7.3)
- [TFHE](https://github.com/tfhe/tfhe) (version 1.1)

The libraries are included as submodules in this repository and will be downloaded to the `thirdparty` directory.

## Ciphers

The following ciphers are already implemented in the framework:

- [LowMC](https://eprint.iacr.org/2016/687.pdf)
- [Rasta](https://eprint.iacr.org/2018/181.pdf)
- [Agrasta](https://eprint.iacr.org/2018/181.pdf)
- [Dasta](https://tosc.iacr.org/index.php/ToSC/article/view/8696/8288)
- [Kreyvium](https://eprint.iacr.org/2015/113.pdf)
- [FiLIP](https://eprint.iacr.org/2019/483.pdf)
- [Masta](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9240936)
- [Hera](https://eprint.iacr.org/2020/1335.pdf)
- [Pasta](https://eprint.iacr.org/2021/731.pdf)

## Compilation

The framework is developed and tested on Linux (and WSL2). The dependencies of the framework are `git`, `gcc/g++` (or `clang/clang++`), `cmake`, `autoconf`, and `libtool`. Install these dependencies with

```bash
sudo apt install build-essential cmake autoconf libtool
```

To compile the framework, execute the following commands from the root directory:

```bash
mkdir build
cd build
cmake ..
make -j4
```

Each cipher for each library will then have its own executable, located in `build/test`.

## Adding a cipher

A new cipher can be added to the framework by adding the source code to the `ciphers` directory. Make sure to use the same structure and naming convention as the already implemented ciphers! Furthermore, add the cipher to `CMakeLists.txt`.

## Benchmarking a cipher

The framework already includes different benchmarks, which are implemented in `ciphers/common/<lib>_kats` for Z_2 ciphers and in `ciphers/common_Zp/<lib>_kats` for Z_p ciphers. The benchmarks can be chosen by adding corresponding tests to the `testvectors.h` file of the cipher.

## Citing our work

Please use the following BibTeX entry to cite our work in academic papers.

```tex
@article{HybridHE,
  author    = {Christoph Dobraunig and
               Lorenzo Grassi and
               Lukas Helminger and
               Christian Rechberger and
               Markus Schofnegger and
               Roman Walch},
  title     = {Pasta: A Case for Hybrid Homomorphic Encryption},
  journal   = {{IACR} Cryptol. ePrint Arch.},
  volume    = {2021},
  pages     = {731},
  year      = {2021}
}
```

# Acknowledgement

This work is partly supported by the European Union under the project Confidential6G with Grant agreement ID: 101096435.

[1] [https://eprint.iacr.org/2021/731.pdf](https://eprint.iacr.org/2021/731.pdf)
