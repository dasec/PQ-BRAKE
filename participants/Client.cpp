/**
 *  Client class methods
 */
#include "Client.hpp"
#include "../operations/Crypto.hpp"
#include "../operations/Helpers.hpp"
#include "../parameters.hpp"


/**
    * @brief Computes a_x value in modified OPRF protocol based on the secret polynomial stored in the Client object.
    * Takes the coefficients of the secret polynomial, concatenates them - thereby creating h,
    * then new coefficients (a0...aN) are created by hashing "0h","1h","2h"..."nh",
    * lastly converting the hashes to integers and performing a 'mod q' operation.
    */
NTL::ZZ_pE Client::compute_a_x()
{
    std::vector<std::string> hashed_coefficients = hashCoefficients(secret_polynomial);

    NTL::ZZ a_x_coeff[N+1];     // N+1 element array because of number of coefficients in polynomial
    NTL::ZZ_pE a_x_polynomial;

    for(int i=0; i<=N; i++)
    {
        /* creates a_x coefficients by hashing the biometric data polynomial */
        a_x_coeff[i] = hashDigestToIntegerModQ(hashed_coefficients[i]);
    }
    /* converts array of coefficients to ring element (ZZ_pE polynomial) */
    a_x_polynomial = spawnRingPolynomial(a_x_coeff);

    return a_x_polynomial;
}

NTL::ZZ_pE Client::compute_c_x(const NTL::ZZ_pE& a)
{
    return (a*s)+e_prime+a_x;
}
