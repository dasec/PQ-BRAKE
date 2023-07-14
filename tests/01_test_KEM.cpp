/**
 * @file 01_test_KEM.cpp
 * @brief Measures average performance of a CRYSTALS-kyber KEM example.
 * The test measures the average performance of a simple KEM process, includes the following: generation of a random fresh keypair and random shared secret,
 * encapsulation, decapsulation and finally checking if the decapsulation was successful.
 * @author Matej Poljuha
 */

#include <iomanip>
#include <chrono>
#include "../operations/Crypto.hpp"
#include "../operations/Helpers.hpp"

using namespace std;

int main() {
    /* setting up helper variables for testing */
    string kyber_version;                                                    /**< KEM version used, defaults to 768 */
    vector<double> timings, timings_KeyGen, timings_Encap, timings_Decap;    /**< vectors holding performance numbers of all runs */
    oqs::bytes empty_shared_secret = convert_to_oqs_bytes("", 1);            /**< predetermined failure value */
    int failure_counter = 0, iterations;

    /* testing parameter input */
    cout << "1 - Kyber512" << "\n2 - Kyber768" << "\n3 - Kyber1024" << endl;
    cout << "Choose CRYSTALS-kyber version (1/2/3): ";
    cin >> kyber_version;
    while (kyber_version != "1" && kyber_version != "2" && kyber_version != "3")
    {
        cout << "Please enter a value between 1 and 3: ";
        cin >> kyber_version;
    }
    if(kyber_version == "1")
        kyber_version = "Kyber512";
    if(kyber_version == "2")
        kyber_version = "Kyber768";
    if(kyber_version == "3")
        kyber_version = "Kyber1024";

    cout << "Choose number of test iterations (1 - 1 000 000): ";
    cin >> iterations;
    while (iterations < 1 || iterations > 1000000)
    {
        cout << "Please enter a value between 1 and 1 000 000: ";
        cin >> iterations;
    }

    for (int i = 0; i < iterations + 1; i++) {
        auto KEM_timer_start = chrono::steady_clock::now();

        /* calling the KEM function, timing is done inside it and given as return values */
        oqs::bytes KEM_output = kyberWithTimings(timings_KeyGen,
                                                 timings_Encap,
                                                 timings_Decap,
                                                 kyber_version);

        auto KEM_timer_end = chrono::steady_clock::now();

        /* if successful, records the values, if not, increase failure counter and disregards performance */
        if (KEM_output != empty_shared_secret) {
            timings.push_back(std::chrono::duration<double, std::milli>(KEM_timer_end - KEM_timer_start).count());
        } else
            failure_counter++;
    }

    /* removes the first run performance which has a performance penalty due to warmup (caching/memory alloc/etc.) */
    timings.erase(timings.begin());
    timings_KeyGen.erase(timings_KeyGen.begin());
    timings_Encap.erase(timings_Encap.begin());
    timings_Decap.erase(timings_Decap.begin());

    cout << "-------------------- TEST RESULTS -------------------- ";
    cout << "\n" << setw(47) << "Iterations: " << iterations;
    cout << "\n" << setw(47) << "Average key generation time (miliseconds): "
         << computeAverage(timings_KeyGen);
    cout << "\n" << setw(47) << "Average encapsulation time (miliseconds): "
         << computeAverage(timings_Encap);
    cout << "\n" << setw(47) << "Average decapsulation time (miliseconds): "
         << computeAverage(timings_Decap);
    cout << "\n" << setw(47) << "Average (successful) KEM time (miliseconds): "
         << computeAverage(timings);
    cout << "\n" << setw(47) << "Number of failed KEM executions: " << failure_counter << " (out of " << iterations << ")" << endl;

    return 0;
}
