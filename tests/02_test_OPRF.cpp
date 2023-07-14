/**
 * @file 02_test_OPRF.cpp
 * @brief Measures average performance of the modified OPRF protocol.
 * The test measures the average performance of the modified OPRF protocol execution. This is based on the
 * original protocol from "Martin R Albrecht et al. “Round-optimal verifiable oblivious pseudorandom
 * functions from ideal lattices”. - 2021.".
 * The test includes the following: sampling preliminary values, blinding and unblinding operations.
 * @author Matej Poljuha
 */

#include <NTL/tools.h>
#include <NTL/RR.h>
#include <chrono>
#include "../operations/Crypto.hpp"
#include "../operations/Helpers.hpp"
#include <fstream>


using namespace std;
using namespace NTL;

int main() {
    ringSetup();    // creates cyclotomic polynomial, defines modulo (q) and creates ring
    /* initializing protocol participant objects */
    Client client_machine;
    Server server_machine;
    Evaluator evaluator_machine;

    ofstream log_failed_OPRF_iterations;
    log_failed_OPRF_iterations.open("01_failed_OPRF_iterations_details.txt");

    printParameters();
    /* prints expected failure rate of any one OPRF iteration,
     * due to noise overflowing the resulting values during rounding
     */
    cout << "\nExpected unblinding failure rate: " << computeExpectedErrorRate() * 100
         << " %\n--------------------------------------------------------------------\n";

    /* setting up helper variables for testing */
    int OPRF_fail_counter = 0, iter = 1, iterations;
    vector<double>  timings,
                    sampling_big_a,
                    sampling_small_k,
                    sampling_small_e,
                    compute_c,
                    sampling_small_s,
                    sampling_small_e_prime,
                    compute_a_x,
                    compute_c_x,
                    sampling_big_E,
                    compute_d_x,
                    compute_y,
                    rounding_y;

    /* testing parameter input */
    cout << "Choose number of test iterations (1 - 10 000) [warning: long runtime - about 30ms expected per iteration]: ";
    cin >> iterations;
    while (iterations < 1 || iterations > 10000)
    {
        cout << "Please enter a value between 1 and 10 000: ";
        cin >> iterations;
    }

    /* main testing loop */
    while (iter < iterations + 1)
    {
        try
        {
            auto OPRF_timer_start = chrono::steady_clock::now();

            /* calls the OPRF function with built-in performance measuring */
            ZZX OPRF_client_output = OPRFWithTimings(&client_machine, &evaluator_machine,
                                                     sampling_big_a,
                                                     sampling_small_k,
                                                     sampling_small_e,
                                                     compute_c,
                                                     sampling_small_s,
                                                     sampling_small_e_prime,
                                                     compute_a_x,
                                                     compute_c_x,
                                                     sampling_big_E,
                                                     compute_d_x,
                                                     compute_y,
                                                     rounding_y);

            auto OPRF_timer_end = chrono::steady_clock::now();

            /* checks if the OPRF unblinding procedure failed and logs into a file */
            OPRFCheckLogging(&client_machine, &evaluator_machine, log_failed_OPRF_iterations, iter);

            timings.push_back(std::chrono::duration<double, std::milli>(OPRF_timer_end - OPRF_timer_start).count());
        } catch (int exc) {
            /* notes a failed OPRF unblinding */
            OPRF_fail_counter++;
        }
        iter++;
    }

    cout << "------------------------------ RESULT ------------------------------" << "\n";
    cout << "Successful OPRF attempts: " << iter-OPRF_fail_counter-1 << "\n";
    cout << "Failed OPRF attempts: " << OPRF_fail_counter << "\n";
    cout << "Realized unblinding failure rate: " << ((double) OPRF_fail_counter/iterations) * 100 << " %\n";
    cout << "------------------------------ TIMING ------------------------------" << "\n";
    cout << "Average sampling_big_a runtime (ms): " << computeAverage(sampling_big_a) << "\n";
    cout << "Average sampling_small_k runtime (ms): " << computeAverage(sampling_small_k) << "\n";
    cout << "Average sampling_small_e runtime (ms): " << computeAverage(sampling_small_e) << "\n";
    cout << "Average compute_c runtime (ms): " << computeAverage(compute_c) << "\n";
    cout << "Average sampling_small_s runtime (ms): " << computeAverage(sampling_small_s) << "\n";
    cout << "Average sampling_small_e_prime runtime (ms): " << computeAverage(sampling_small_e_prime) << "\n";
    cout << "Average compute_a_x OPRF runtime (ms): " << computeAverage(compute_a_x) << "\n";
    cout << "Average compute_c_x OPRF runtime (ms): " << computeAverage(compute_c_x) << "\n";
    cout << "Average sampling_big_E OPRF runtime (ms): " << computeAverage(sampling_big_E) << "\n";
    cout << "Average compute_d_x OPRF runtime (ms): " << computeAverage(compute_d_x) << "\n";
    cout << "Average compute_y OPRF runtime (ms): " << computeAverage(compute_y) << "\n";
    cout << "Average rounding_y OPRF runtime (ms): " << computeAverage(rounding_y) << "\n";
    cout << "Average (successful) OPRF runtime (ms): " << computeAverage(timings) << "\n";
    cout << "--------------------------------------------------------------------" << "\n";

    log_failed_OPRF_iterations.close();

    return 0;
}
