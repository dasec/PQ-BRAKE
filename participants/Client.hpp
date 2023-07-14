/**
 *  Client class
 */
#pragma once
#include <NTL/ZZX.h>
#include <NTL/ZZ_pE.h>
#include "../oqs_cpp.h"
#include "../fuzzyVault/Thimble.hpp"

class Client
{
public:
    NTL::ZZ_pE compute_a_x();
    NTL::ZZ_pE compute_c_x(const NTL::ZZ_pE& a);

    NTL::ZZX secret_polynomial, y_rounded;
    NTL::ZZ_pE  s,
                e_prime,
                d_x,
                a_x,
                y;

    oqs::bytes  public_key,
                secret_key,
                ephemeral_public_key,
                ephemeral_secret_key,
                ciphertext,
                shared_secret;

    /**
    * @brief Default constructor that sets a random value for the secret polynomial.
    * Used only for testing.
    */
    Client()
    {
        for (int i=0; i<16; i++)
        {
            SetCoeff(secret_polynomial, i, NTL::RandomBnd(pow(2,18)));
        }
        secret_polynomial.normalize();  // strips leading zeroes
    }

    /**
    * @brief Constructor that sets the secret polynomial value for the object based on input.
    * @param secret_polynomial_pre_hash a polynomial
    * Used for turning the fuzzy-vault-generated random polynomial into a usable NTL-format inside the class.
    */
    explicit Client(const SmallBinaryFieldPolynomial& secret_polynomial_pre_hash)
    {
        for (int i=0; i<=secret_polynomial_pre_hash.deg(); i++)
        {
            SetCoeff(secret_polynomial, i, NTL::ZZ(secret_polynomial_pre_hash.getCoeff(i)));
        }
        secret_polynomial.normalize();  // strips leading zeroes
    }
};

