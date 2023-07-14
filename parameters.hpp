/**
 * @file parameters.hpp
 * @brief Parameters common to all OPRF calculations
 */
#pragma once

#include <cmath>
#include <NTL/ZZ.h>

/* EDIT THESE VALUES TO MODIFY OPRF PARAMETERS - q= 2^75, N= 2^12 recommended, NOTE: input just the exponents */
const int           hr_q = 75;    /**< human readable q value, to which power is 2 raised for the value of q */
const int           hr_N = 12;    /**< human readable N value, to which power is 2 raised for the value of N */

/* DO NOT EDIT THESE VALUES - the above set values are used as exponents to set the true values here */
const NTL::ZZ       q   = NTL::NextPrime(NTL::power(NTL::conv<NTL::ZZ>(2),hr_q));
const long          N   = NTL::conv<long>(NTL::power(NTL::conv<NTL::ZZ>(2),hr_N));
const int           sec = 40;
const NTL::ZZ       B   = NTL::conv<NTL::ZZ>(2)*NTL::conv<NTL::ZZ>(N)*NTL::power(NTL::conv<NTL::ZZ>(2),sec);  //2N*2^sec
const std::string   hr_B = "2^"+ std::to_string(hr_N+1+sec);    // used just for printing
const long          p   = 2;