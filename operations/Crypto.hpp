/**
 *  Cryptographic operations, hashing, LWE, Ring, etc.
 */
#pragma once

#include <NTL/ZZ_pE.h>
#include "../participants/Client.hpp"
#include "../participants/Evaluator.hpp"
#include "../participants/Server.hpp"
#include "../oqs_cpp.h"
#include <vector>


std::string hashSHA256(const std::string &plaintext);

NTL::ZZ hashDigestToIntegerModQ(const std::string &digest_string);

std::vector<std::string> hashCoefficients(const NTL::ZZX &secret_polynomial);

NTL::ZZX rounding(const NTL::ZZ_pE &polynom);

NTL::ZZ_pE sampleSmallUniformPolynomial(long long lbound, long long ubound);

NTL::ZZ_pE sampleBigUniformPolynomial(const NTL::ZZ &bound);

NTL::ZZ_pE aSampleBigUniformPolynomial(const NTL::ZZ &bound);

NTL::ZZX OPRFWithTimings(Client *client, Evaluator *evaluator, std::vector<double> &sampling_big_a,
                         std::vector<double> &sampling_small_k, std::vector<double> &sampling_small_e,
                         std::vector<double> &compute_c, std::vector<double> &sampling_small_s,
                         std::vector<double> &sampling_small_e_prime, std::vector<double> &compute_a_x,
                         std::vector<double> &compute_c_x, std::vector<double> &sampling_big_E,
                         std::vector<double> &compute_d_x, std::vector<double> &compute_y,
                         std::vector<double> &rounding_y);

NTL::ZZX OPRF(Client *client, Evaluator *evaluator, bool common_values_initialized);

oqs::bytes kyberWithTimings(std::vector<double> &timings_KeyGen, std::vector<double> &timings_Encap,
                            std::vector<double> &timings_Decap, const string &kyber_version);
