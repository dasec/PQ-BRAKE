/**
 * Helper functions
 */
#include "../parameters.hpp"
#include "Helpers.hpp"
#include <iostream>
#include <vector>
#include <NTL/ZZ_pE.h>
#include <NTL/RR.h>
#include "Crypto.hpp"

using namespace std;
using namespace NTL;

/**
 * @brief Takes a string and converts it into a vector of bytes of desired length.
 * @param c_str string to be converted
 * @param length number of bytes desired
 */
oqs::bytes convert_to_oqs_bytes(const char *c_str, std::size_t length) {
    oqs::bytes result(length);
    for (std::size_t i = 0; i < length; ++i)
        result[i] = static_cast<oqs::byte>(c_str[i]);
    return result;
}

/**
 * @brief Constructs a ZZ_pE type polynomial (element of ring) from an array of integer coefficients.
 * @param coefficients pointer to first element of an array of integer polynomial coefficients
 * This is needed due to certain intricacies in NTL's manipulation of polynomial coefficients.
 */
ZZ_pE spawnRingPolynomial(ZZ *coefficients) {
    ZZ_pX ring_polynomial;

    for (int i = 0; i <= N; i++) {
        ZZ_p coefficient = conv < ZZ_p > (coefficients[i]);
        SetCoeff(ring_polynomial, i, coefficient);
    }
    ring_polynomial.normalize();

    return conv < ZZ_pE > (ring_polynomial);
}

/**
 * @brief Sets up a ring as defined by the NTL library, initializing the modulo q, and a cyclotomic polynomial of deg N.
 */
void ringSetup() {
    /* Ring setup */
    ZZ_p::init(q);               // setting the current modulo q for integers mod q NTL class
    ZZ_pX P(INIT_MONO, N);
    SetCoeff(P, 0, 1);             // Cyclotomic polynomial x^N+1

    ZZ_pE::init(P);              // ring extension over ZZ_p (integer modulo q)
}

/**
 * @brief Takes a vector of floating point values from [0,q-1] and shifts them into [-q/2,q/2].
 * @param coefficients vector of floating point values of type NTL::RR
 */
vector<RR> qShifting(vector<RR> coefficients) {
    vector<RR> shifted_coefficients = coefficients;
    for (auto &element: shifted_coefficients) {
        /* q converted to RR --> nothing lost
         * q/2 -> result always either .0 or .5
         * floor(q/2) -> floor() simulates integer division (//)
         */
        if (element > ((floor(conv < RR > (q) / conv < RR > (2)))))
            element -= conv < RR > (q);
        else;
    }
    return shifted_coefficients;
}

/**
 * @brief Converts an element of the ring to a vector of floating point values.
 * @param polynom polynomial in the ring
 */
vector<RR> pEtoVectorRR(const ZZ_pE &polynom) {
    vector<RR> coefficients_in_RR;

    for (int i = 0; i <= deg(conv < ZZ_pX > (polynom)); i++) {
        /* conversion goes from ZZ_p to ZZ to RR, nothing lost since original value is already an 0<=integer<q */
        coefficients_in_RR.push_back(conv < RR > (conv < ZZ > (coeff(conv < ZZ_pX > (polynom),
                                                                     i))));
    }

    return coefficients_in_RR;
}

/**
 * @brief Calculates the chance for the noise introduced through RLWE
 * to overflow when rounding for a single OPRF execution based on the values of N,B,q.
 */
RR computeExpectedErrorRate() {
    RR rate, one_coeff_fail, complement;
    one_coeff_fail = conv < RR > (2 * N + B) / conv < RR > (q);
    complement = conv < RR > (1) - one_coeff_fail;
    rate = 1 - pow(complement, conv < RR > (N));

    return rate;
}

/**
 * @brief Takes a vector of values and returns the arithmetical average.
 * @param values vector of double type values
 */
double computeAverage(const vector<double> &values) {
    if (values.empty()) {
        return 0;
    }

    double sum = 0.0;

    for (auto &element: values) {
        sum += element;
    }

    return sum / values.size();
}

/**
 * @brief Takes an array of float values and returns the arithmetical average.
 * @param values array of float type values
 */
float computeAverageFloat(const float values[], int size) {
    float sum = 0.0;

    for (int i = 0; i<size ; i++) {
        sum += values[i];
    }

    return sum / (float) size;
}

/**
 * @brief Prints the values of OPRF parameters.
 */
void printParameters() {
    cout << "\n------------------------ PARAMETER VALUES: -------------------------\n";
    cout << "q: " << "2^" + std::to_string(hr_q) << "\n";
    cout << "N: " << "2^" + std::to_string(hr_N) << "\n";
    cout << "B: " << hr_B << "\n";
    cout << "p: " << p << "\n";
    cout << "--------------------------------------------------------------------";
}

/**
 * @brief Checks if the OPRF unblinding procedure failed and logs into a file.
 * @param client client object
 * @param evaluator evaluator object
 * @param OutputFile output file to save logs into
 * @param iter vector of double type values
 */
void OPRFCheckLogging(Client *client, Evaluator *evaluator, ofstream &OutputFile, int iter) {
    ZZ_pE lift;
    ZZX a_x_k_rounded;
    lift = client->a_x * evaluator->k;
    a_x_k_rounded = rounding(lift);

    ZZ_pPush push;                  /**< backup of current modulus */
    ZZ_p::init(conv < ZZ > (2));        // sets current modulus to 2

    /* converts results to binary representation */
    ZZ_pX a_x_k_rounded_mod_2 = conv < ZZ_pX > (a_x_k_rounded), y_rounded_mod2 = conv < ZZ_pX > (client->y_rounded);

    if (a_x_k_rounded_mod_2 != y_rounded_mod2) {
        OutputFile << "\n--------------------------------------------------------------\n"
                   << ">>>>>>>>>>>>>>>>>>>> ITERATION: " << setw(9) << iter
                   << " <<<<<<<<<<<<<<<<<<<<\n--------------------------------------------------------------\n";
        OutputFile << "OPRF - FAILED" << "\n";
        OutputFile << "-------------------- ERRORS AT: --------------------\n";

        for (int i = 0; i <= deg(y_rounded_mod2); i++)               // checks at which coefficient the error occurs
        {
            if (coeff(a_x_k_rounded_mod_2, i) != coeff(y_rounded_mod2, i)) {
                OutputFile << i << ". coeff. (y,a_x*k) => " << coeff(y_rounded_mod2, i) << ", "
                           << coeff(a_x_k_rounded_mod_2, i) << "\n";

                OutputFile << "y = " << coeff(conv < ZZ_pX > (client->y), i) << "\n" << "a_x*k = "
                           << coeff(conv < ZZ_pX > (lift), i) << "\n";

                OutputFile << "q/2-shifted y     = " << qShifting(pEtoVectorRR(client->y))[i] << " -> "
                           << conv < RR >
                           (conv < ZZ > (qShifting(pEtoVectorRR(client->y))[i])) / (conv < RR > (q) / conv < RR > (p))
                           << "\n"
                           << "q/2-shifted a_x*k = "
                           << qShifting(pEtoVectorRR(lift))[i]
                           << " -> "
                           << conv <
                RR > (conv < ZZ > (qShifting(pEtoVectorRR(lift))[i])) / (conv < RR > (q) / conv < RR > (p))
                << "\n" << "----------" << "\n";
            }
        }
        /* exception that indicates to the test that this is a failed iteration */
        throw 1;
    }
}

/**
 * @brief Checks if the OPRF unblinding procedure failed.
 * @param client client object
 * @param evaluator evaluator object
 * @param OutputFile output file to save logs into
 * @param iter vector of double type values
 */
void OPRFCheck(Client *client, Evaluator *evaluator) {
    ZZ_pE lift;
    ZZX a_x_k_rounded;
    lift = client->a_x * evaluator->k;
    a_x_k_rounded = rounding(lift);

    ZZ_pPush push;                  // backs up current modulus
    ZZ_p::init(conv < ZZ > (2));        // set modulus to 2
    ZZ_pX a_x_k_rounded_mod_2 = conv < ZZ_pX > (a_x_k_rounded), y_rounded_mod2 =
            conv < ZZ_pX > (client->y_rounded);    // converts results to binary representation

    if (a_x_k_rounded_mod_2 != y_rounded_mod2) {
        throw 1;
    }
}

/**
 * @brief Converts an integer polynomial from NTL representation into a string representation.
 * @param polynomial integer polynomial of type ZZX
 */
string printZZXconcatenated(const ZZX &polynomial) {
    stringstream ss;

    /* loads coefficients from a polynomial and concatenates them */
    for (int i = 0; i <= deg(polynomial); i++) {
        ss << coeff(polynomial, i);
    }
    return ss.str();
}

/**
 * @brief Prints an array of float values in a nicely formatted line into a file.
 * @param print_array array of float values to be printed
 */
void printArrayForLog(ofstream &OutputFile, const float *print_array, bool last_line) {
    for(int i = 0; i<6; i++)
    {
        if (!last_line)
            OutputFile << print_array[i] << ",";
        else if (i<5)
            OutputFile << print_array[i] << ",";
        else
            OutputFile << print_array[i] << "\n";
    }
}

/**
 * @brief Writes the results of a PQ-BRAKE protocol run into an output file.
 * @param outputFile filename for output file
 */
void printPQBRAKEresultToFile(ofstream &OutputFile, const string& reference_fingerprint_filename, const string& query_fingerprint_filename, const string& protocol_failure_reason, const float preprocessing[], const float lock[], const float unlock[], const float OPRF[], const float keygen [],
                              const float encap[], const float decap[]) {
    OutputFile << reference_fingerprint_filename << "," << query_fingerprint_filename << "," << protocol_failure_reason << ",";
    printArrayForLog(OutputFile, preprocessing);
    printArrayForLog(OutputFile, lock);
    printArrayForLog(OutputFile, unlock);
    printArrayForLog(OutputFile, OPRF);
    printArrayForLog(OutputFile, keygen);
    printArrayForLog(OutputFile, encap);
    printArrayForLog(OutputFile, decap, true);
}

/**
 * @brief Prints an array of float values in a nicely formatted line.
 * @param print_array array of float values to be printed
 */
void printArrayForTable(const float *print_array, bool average) {
    if (!average)
    {
        for(int i = 0; i<6; i++)
            cout << "  " << setw(6) << round(print_array[i]*100)/100 << "  ";
        cout << "\n";
    } else
    {
        cout << setw(32) << round(computeAverageFloat(print_array)*100)/100 << "\n";
    }
}