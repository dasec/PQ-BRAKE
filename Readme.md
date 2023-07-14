# Available benchmarks

There are 3 tests available:
1. KEM test - performance of a CRYSTALS-Kyber example
   - usage: ./01_test_KEM
2. OPRF test - performance of an OPRF procedure example
   - usage: ./02_test_OPRF
3. PQ-BRAKE test - performance of the PQ-BRAKE protocol, enrolling a fingerprint and queries another; if successful, a shared secret is established
   - usage: (sudo) ./03_test_PQBRAKE path_to_reference_fingerprint.pgm path_to_query_fingerprint.pgm
   - root privileges are needed in order to write the full performance numbers to the logfile, program can be run as a normal user but no logs will be made and only a shortened version of the performance numbers will be printed to console

# Installation

## Note
- The PQ-BRAKE test will only work correctly on systems that include the **AVX2** instruction set.

## How to
To install the program:
1. Clone the repository
2. Run the [installation script](install.sh) script as root (see requirements section below)
3. executables are created in the [build folder](build/) folder (test logs too)
*if the installation fails for any reason, a precompiled version of the test executables is provided in the [precompiled](/tests/precompiledTests/) folder*

## Requirements (tested on Ubuntu-based Linux distro):
 - libssl-dev
 - cmake
 - astyle
 - gcc
 - ninja-build
 - unzip
 - xsltproc
 - valgrind
 - libgmp-dev (GNU mp Bignum)
 - m4