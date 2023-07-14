/**
 *  Cryptographic operations, hashing, LWE, Ring, etc.
 */
#include "Crypto.hpp"
#include "Helpers.hpp"
#include "../parameters.hpp"
#include <openssl/evp.h>
#include <NTL/ZZXFactoring.h>
#include <NTL/ZZ_pE.h>
#include <NTL/RR.h>
#include <iostream>
#include <iomanip>
#include <random>
#include <sstream>


using namespace std;
using namespace NTL;


/**
 * @brief Sampling small uniform polynomial of degree N in the range [lbound,ubound],
 * negative values represented with modulo q.
 * @param lbound lower bound
 * @param ubound upper bound
 */
ZZ_pE sampleSmallUniformPolynomial(const long long lbound, const long long ubound)
{
    /* samples uniform polynomial */
    /* random number generation, uniform from [lbound,ubound], using 32 bit Mersenne Twister */
    random_device rd;
    mt19937 generator(rd());
    uniform_int_distribution<long long> distr(lbound,ubound);

    ZZ_pX uniform_polynomial;
    ZZ coefficient;
    for(int i=0; i <= N; i++)
    {
        coefficient = distr(generator);
        SetCoeff(uniform_polynomial,i,conv<ZZ_p>(coefficient));
    }
    uniform_polynomial.normalize();

    return conv<ZZ_pE>(uniform_polynomial);
}

/**
 * @brief Samples uniform polynomial of degree N in the range [-bound,bound], negative values represented with modulo q.
 * @param bound integer that determines the range to sample from
 */
ZZ_pE sampleBigUniformPolynomial(const ZZ& bound)
{
    ZZ_pX uniform_polynomial;

    for(int i=0; i <= N; i++)
    {
        SetCoeff(uniform_polynomial,i,conv<ZZ_p>(RandomBnd(2*bound+1)-bound));
    }
    uniform_polynomial.normalize();

    return conv<ZZ_pE>(uniform_polynomial);
}

/**
 * @brief Slightly optimized sampling (for a value).
 * @param bound integer that determines the range to sample from
 * Samples uniform polynomial of degree N in the range [0,bound-1], negative values represented with modulo q.
 */
ZZ_pE aSampleBigUniformPolynomial(const ZZ& bound)
{
    ZZ_pX uniform_polynomial;

    for(int i=0; i <= N; i++)
    {
        SetCoeff(uniform_polynomial,i,conv<ZZ_p>(RandomBnd(bound)));
    }
    uniform_polynomial.normalize();

    return conv<ZZ_pE>(uniform_polynomial);
}

/**
 * @brief SHA256 - implementation from the openssl library.
 * @param plaintext string that is to be hashed
 */
string hashSHA256(const string& plaintext)
{
    /* creates message digest context (memory allocation) */
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    if(context != nullptr)
    {
        /* initializes digest context */
        if(EVP_DigestInit_ex(context, EVP_sha256(), nullptr))
        {
            /* hashes plaintext.length() bytes of data at plaintext.c_str() into the digest context*/
            if(EVP_DigestUpdate(context, plaintext.c_str(), plaintext.length()))
            {
                unsigned char hash[EVP_MAX_MD_SIZE];
                unsigned int lengthOfHash = 0;

                /* retrieves digest result from 'context' and puts into output buffer 'hash' */
                if(EVP_DigestFinal_ex(context, hash, &lengthOfHash))
                {
                    std::stringstream ss;
                    for(unsigned int i = 0; i < lengthOfHash; ++i)
                    {
                        /* formats hash elements into human-readable hexadecimal form */
                        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                    }
                    EVP_MD_CTX_free(context);

                    return ss.str();
                }
            }
        }
        /* cleans context and frees memory allocated */
        EVP_MD_CTX_free(context);
    }
    return "";
}

/**
 * @brief Turns a hash digest into integer values.
 * @param digest_string hash digest
 */
ZZ hashDigestToIntegerModQ(const string& digest_string)
{
    /* converts the digest from a string to a C style string (char array), with delimiter */
    const char *digest_hex = digest_string.c_str();

    return ZZFromBytes(reinterpret_cast<const unsigned char *>(digest_hex), digest_string.length());
}

/**
 * @brief Hashes coefficients of a client's secret polynomial, on a per-coefficient basis.
 * @param secret_polynomial polynomial with integer coefficients
 */
vector<string> hashCoefficients(const ZZX& secret_polynomial)
{
    stringstream ss;

    /* loads coefficients from secret polynomial and concatenates them for hashing */
    for (int i=0; i<=deg(secret_polynomial); i++)
    {
        ss << coeff(secret_polynomial,i);
    }
    string concat_coefficients = ss.str();

    /* hashes concatenated coefficients of secret polynomial with SHA256 */
    string h = hashSHA256(concat_coefficients);

    vector<string> output_coefficients;

    for (int i=0; i<=N; i++)
    {
        /* concatenates i with h, producing 0h,1h,2h... strings and hashes them
 */
        output_coefficients.push_back(hashSHA256(to_string(i) + h));
    }

    return output_coefficients;
}

/**
 * @brief Rounding procedure, values are shifted into <-q/2,q/2> range and rounded (ties rounded down).
 * @param polynom polynomial in the ring
 */
ZZX rounding(const ZZ_pE& polynom)
{
    ZZ_pX pre_rounded_polynom;
    ZZX rounded_polynom;
    pre_rounded_polynom = conv<ZZ_pX>(polynom);

    RR  element,
        q_half = floor(conv<RR>(q)/conv<RR>(2)),
        q_floating = conv<RR>(q),
        q_p_rounding_multiplier = conv<RR>(q)/conv<RR>(p);

    /* rounding procedure - multiplying by 1/(q/p) and rounding to the nearest int with ties rounded down */
    for (int i=0; i<=deg(pre_rounded_polynom); i++)
    {
        element = conv<RR>(conv<ZZ>(coeff(pre_rounded_polynom,i)));
        if (element > q_half)
            element -= q_floating;
        /* using ceiling(element-0.5) as workaround to get rounding-down on ties, default NTL functions round-to-even */
        element = ceil((element/q_p_rounding_multiplier)-0.5);
        SetCoeff(rounded_polynom, i, conv<ZZ>(element));
    }

    rounded_polynom.normalize();

    return rounded_polynom;
}

/**
 * @brief Modified OPRF protocol execution based on the original protocol from:
 * "Martin R Albrecht et al. “Round-optimal verifiable oblivious pseudorandom functions from ideal lattices”. - 2021.".
 * Includes the following: timing mechanisms for each step,
 * sampling preliminary values, blinding and unblinding operations.
 * @param client client object
 * @param evaluator evaluator object
 * @param sampling_big_a vector of time values
 * @param sampling_small_k vector of time values
 * @param sampling_small_e vector of time values
 * @param compute_c vector of time values
 * @param sampling_small_s vector of time values
 * @param sampling_small_e_prime vector of time values
 * @param compute_a_x vector of time values
 * @param compute_c_x vector of time values
 * @param sampling_big_E vector of time values
 * @param compute_d_x vector of time values
 * @param compute_y vector of time values
 * @param rounding_y vector of time values
 */
ZZX OPRFWithTimings(Client *client,
                    Evaluator *evaluator,
                    std::vector<double> &sampling_big_a,
                    std::vector<double> &sampling_small_k,
                    std::vector<double> &sampling_small_e,
                    std::vector<double> &compute_c,
                    std::vector<double> &sampling_small_s,
                    std::vector<double> &sampling_small_e_prime,
                    std::vector<double> &compute_a_x,
                    std::vector<double> &compute_c_x,
                    std::vector<double> &sampling_big_E,
                    std::vector<double> &compute_d_x,
                    std::vector<double> &compute_y,
                    std::vector<double> &rounding_y)
{
    auto pre_rounding_start = chrono::steady_clock::now();

    /* Sampling */
    auto sampling_big_a_start = chrono::steady_clock::now();
    ZZ_pE a = aSampleBigUniformPolynomial(q);
    auto sampling_big_a_end = chrono::steady_clock::now();
    sampling_big_a.push_back(std::chrono::duration<double, std::milli>(sampling_big_a_end - sampling_big_a_start).count());

    auto sampling_small_k_start = chrono::steady_clock::now();
    evaluator->k = sampleSmallUniformPolynomial(-1, 1);
    auto sampling_small_k_end = chrono::steady_clock::now();
    sampling_small_k.push_back(std::chrono::duration<double, std::milli>(sampling_small_k_end - sampling_small_k_start).count());

    auto sampling_small_e_start = chrono::steady_clock::now();
    evaluator->e = sampleSmallUniformPolynomial(-1, 1);
    auto sampling_small_e_end = chrono::steady_clock::now();
    sampling_small_e.push_back(std::chrono::duration<double, std::milli>(sampling_small_e_end - sampling_small_e_start).count());

    /* EVALUATOR computes c, value is sent to client and stored there */
    auto compute_c_start = chrono::steady_clock::now();
    evaluator->c = evaluator->compute_c(a);
    auto compute_c_end = chrono::steady_clock::now();
    compute_c.push_back(std::chrono::duration<double, std::milli>(compute_c_end - compute_c_start).count());

    /* CLIENT computes */
    auto sampling_small_s_start = chrono::steady_clock::now();
    client->s = sampleSmallUniformPolynomial(-1, 1);
    auto sampling_small_s_end = chrono::steady_clock::now();
    sampling_small_s.push_back(std::chrono::duration<double, std::milli>(sampling_small_s_end - sampling_small_s_start).count());

    auto sampling_small_e_prime_start = chrono::steady_clock::now();
    client->e_prime = sampleSmallUniformPolynomial(-1, 1);
    auto sampling_small_e_prime_end = chrono::steady_clock::now();
    sampling_small_e_prime.push_back(std::chrono::duration<double, std::milli>(sampling_small_e_prime_end - sampling_small_e_prime_start).count());

    /* CLIENT computes a_x (hashed fuzzy vault candidate polynomial) */
    auto compute_a_x_start = chrono::steady_clock::now();
    client->a_x = client->compute_a_x();
    auto compute_a_x_end = chrono::steady_clock::now();
    compute_a_x.push_back(std::chrono::duration<double, std::milli>(compute_a_x_end - compute_a_x_start).count());

    /* CLIENT computes c_x and "sends" value to EVALUATOR who uses it*/
    auto compute_c_x_start = chrono::steady_clock::now();
    evaluator->c_x = client->compute_c_x(a);
    auto compute_c_x_end = chrono::steady_clock::now();
    compute_c_x.push_back(std::chrono::duration<double, std::milli>(compute_c_x_end - compute_c_x_start).count());

    /* EVALUATOR samples a large noise value (E) from [-B,B] */
    auto sampling_big_E_start = chrono::steady_clock::now();
    evaluator->E = sampleBigUniformPolynomial(B);
    auto sampling_big_E_end = chrono::steady_clock::now();
    sampling_big_E.push_back(std::chrono::duration<double, std::milli>(sampling_big_E_end - sampling_big_E_start).count());

    /* EVALUATOR computes d_x, value is sent to client */
    auto compute_d_x_start = chrono::steady_clock::now();
    client->d_x = evaluator->compute_d_x();
    auto compute_d_x_end = chrono::steady_clock::now();
    compute_d_x.push_back(std::chrono::duration<double, std::milli>(compute_d_x_end - compute_d_x_start).count());

    /* CLIENT computes y */
    auto compute_y_start = chrono::steady_clock::now();
    client->y = client->d_x-(evaluator->c*client->s);
    auto compute_y_end = chrono::steady_clock::now();
    compute_y.push_back(std::chrono::duration<double, std::milli>(compute_y_end - compute_y_start).count());

    /* CLIENT rounds y */
    auto rounding_y_start = chrono::steady_clock::now();
    client->y_rounded = client->y_rounded = rounding(client->y);
    auto rounding_y_end = chrono::steady_clock::now();
    rounding_y.push_back(std::chrono::duration<double, std::milli>(rounding_y_end - rounding_y_start).count());

    return client->y_rounded;
}

/**
 * @brief Modified OPRF protocol execution based on the original protocol from:
 * "Martin R Albrecht et al. “Round-optimal verifiable oblivious pseudorandom functions from ideal lattices”. - 2021.".
 * Includes the following: sampling preliminary values, blinding and unblinding operations.
 * @param client client object
 * @param evaluator evaluator object
 * @param common_values_initialized true if the server already published its commitment (values a,k,e,c)
 */
ZZX OPRF(Client *client, Evaluator *evaluator, bool common_values_initialized)
{
    if (!common_values_initialized)
    {
        /* Sampling */
        evaluator->a = aSampleBigUniformPolynomial(q);

        /* Sampling key (k) and RLWE error (e) as ternary polynomials */
        evaluator->k = sampleSmallUniformPolynomial(-1, 1);
        evaluator->e = sampleSmallUniformPolynomial(-1, 1);

        /* EVALUATOR computes c, value is sent to client and stored there */
        evaluator->c = evaluator->compute_c(evaluator->a);
    }

    /* CLIENT computes */
    client->s = sampleSmallUniformPolynomial(-1, 1);

    client->e_prime = sampleSmallUniformPolynomial(-1, 1);

    /* CLIENT computes a_x (hashed fuzzy vault candidate polynomial) */
    client->a_x = client->compute_a_x();

    /* CLIENT computes c_x and "sends" value to EVALUATOR who uses it*/
    evaluator->c_x = client->compute_c_x(evaluator->a);

    /* EVALUATOR samples a large noise value (E) from [-B,B] */
    evaluator->E = sampleBigUniformPolynomial(B);

    /* EVALUATOR computes d_x, value is sent to client */
    client->d_x = evaluator->compute_d_x();

    /* CLIENT computes y */
    client->y = client->d_x-(evaluator->c*client->s);

    /* CLIENT rounds y */
    client->y_rounded = client->y_rounded = rounding(client->y);

    return client->y_rounded;
}

/**
 * @brief CRYSTALS-kyber KEM example function with timing code.
 * @param kyber_version string representing the kyber version desired
 * @param timings_KeyGen vector of time values for key generation
 * @param timings_Encap vector of time values for encapsulation
 * @param timings_Decap vector of time values for decapsulation
 *
 * The function does the following: generates a random fresh keypair and random shared secret,
 * performs encapsulation, decapsulation and then checking if the decapsulation was successful.
 */
oqs::bytes kyberWithTimings(std::vector<double> &timings_KeyGen,
                            std::vector<double> &timings_Encap,
                            std::vector<double> &timings_Decap,
                            const string &kyber_version)
{
    oqs::KeyEncapsulation KEM_client{kyber_version};
    oqs::KeyEncapsulation KEM_server{kyber_version};
    oqs::bytes ciphertext, client_shared_secret, server_shared_secret;

    auto KeyGen_timer_start = chrono::steady_clock::now();

    /* generates keypair, secret key is not returned but is generated and stored in the KEM_client object */
    oqs::bytes client_public_key = KEM_client.generate_keypair();

    auto KeyGen_timer_end = chrono::steady_clock::now();
    timings_KeyGen.push_back(std::chrono::duration<double, std::milli>(KeyGen_timer_end - KeyGen_timer_start).count());

    auto Encap_timer_start = chrono::steady_clock::now();

    /* a shared secret is randomly generated and encapsulated with the client's public key */
    std::tie(ciphertext, server_shared_secret) = KEM_server.encap_secret(client_public_key);

    auto Encap_timer_end = chrono::steady_clock::now();

    timings_Encap.push_back(std::chrono::duration<double, std::milli>(Encap_timer_end - Encap_timer_start).count());

    auto Decap_timer_start = chrono::steady_clock::now();

    /* client attempts to recover (decapsulate) the shared secret from the ciphertext using its secret key */
    client_shared_secret = KEM_client.decap_secret(ciphertext);

    auto Decap_timer_end = chrono::steady_clock::now();

    timings_Decap.push_back(std::chrono::duration<double, std::milli>(Decap_timer_end - Decap_timer_start).count());

    /**
     * if decapsulation is successful -> the shared secret is returned,
     * if it fails -> a predetermined failure value is returned
     */
    if (client_shared_secret == server_shared_secret)
        return {client_shared_secret};
    else
    {
        oqs::bytes empty_shared_secret = convert_to_oqs_bytes("", 1);
        return {empty_shared_secret};
    }
}