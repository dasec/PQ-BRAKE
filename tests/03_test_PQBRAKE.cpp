/**
 * @file 03_test_PQBRAKE.cpp
 * @brief Measures performance of the PQ-BRAKE protocol.
 * The test measures the performance of the PQ-BRAKE protocol execution, depending on the size of the secret polynomial.
 * Simulates the enrollment of a reference fingerprint and an attempt to verify a user with a query fingerprint.
 * It is possible to change the parameters for the OPRF mechanism by editing the
 * parameters.hpp file (instructions inside) and recompiling.
 * However, the CRYSTALS-Kyber KEM parameters are fixed as Kyber768 is used.
 * The results are output into a .csv file.
 * @param reference_fingerprint grayscale .pgm image of a fingerprint that is "enrolled" into the fuzzy vault
 * @param query_fingerprint grayscale .pgm image of a fingerprint that queries the fuzzy vault
 * @author Matej Poljuha
 */

#include <chrono>
#include <openssl/ec.h>
#include "../fuzzyVault/Thimble.hpp"
#include "../operations/Crypto.hpp"
#include "../operations/Helpers.hpp"


using namespace std;
using namespace NTL;

int main(int argc, char **argv)
{
    /* setup of test variables */
    float   empty_timings[6] = {0,0,0,0,0,0},
            preprocessing_timings[6],
            lock_timings[6],
            unlock_timings[6],
            OPRF_timings[6],
            keygen_timings[6],
            encap_timings[6],
            decap_timings[6];

    /* ring setup for OPRF process */
    ringSetup();

    /* check if exactly two arguments are provided */
    if (argc != 3)
    {
        cout << "ERROR!\nUsage hint: 03_test_PQBRAKE <path to reference image> <path to query image> NOTE: images must be in .pgm format." << endl;
        exit(1);
    }

    /* creation of output file,
     * syntax of output file reference_fingerprint_filename is _referencefilename_.pgm|_queryfilename_.pgm (without '_' symbols)
     */
    ofstream OutputFile;
    string reference_fingerprint_path = argv[1];
    string query_fingerprint_path = argv[2];
    string reference_fingerprint_filename = reference_fingerprint_path.substr(reference_fingerprint_path.find_last_of('/')+1, reference_fingerprint_path.find_last_of('.')-reference_fingerprint_path.find_last_of('/')-1);;
    string query_fingerprint_filename = query_fingerprint_path.substr(query_fingerprint_path.find_last_of('/')+1, query_fingerprint_path.find_last_of('.')-query_fingerprint_path.find_last_of('/')-1);;
    cout << setw(23) << "Reference fingerprint: " << reference_fingerprint_filename << "\n";
    cout << setw(23) << "Query fingerprint: " << query_fingerprint_filename << "\n";
    OutputFile.open("PQBRAKE_results.csv", fstream::app);

    /* hardcoded values for varying the size of the secret polynomial k */
    int polynomial_sizes[] = {6,6,8,10,12,14,16};

    /* main test loop */
    int iter = 0;
    bool warmup_run = true; // needed because of memory alloc./caching impacting benchmark
    for (int i : polynomial_sizes) {
        //---------------------------------------------------------------
        //                   PRELIMINARY CALCULATIONS
        //---------------------------------------------------------------

        cout << "-------------------------------------------------------------------------------------------\n";
        Server server_machine;
        Evaluator evaluator_machine;

        /* generates a random keypair for the server */
        oqs::KeyEncapsulation preliminary_server_key_generator{"Kyber768"};
        server_machine.public_key = preliminary_server_key_generator.generate_keypair();
        server_machine.secret_key = preliminary_server_key_generator.export_secret_key();

        //---------------------------------------------------------------
        //                         ENROLLMENT
        //---------------------------------------------------------------

                //-------------------------------
                //          Fuzzy vault
                //-------------------------------

        /* a fuzzy vault is created, temporarily with secret size=10 (overriden later) */
        ProtectedMinutiaeTemplate vault(mcytWidth, mcytHeight, mcytDpi);
        cout << "Degree of secret polynomial: " << i << endl;
        vault.setSecretSize(i);     // overrides and sets the size of the secret polynomial
        MinutiaeView ref = getMinutiaeView(reference_fingerprint_path);      // processes the raw fingerprint image

        auto lock_timer_start = chrono::steady_clock::now();
        bool vault_locked = vault.enroll(ref);
        auto lock_timer_end = chrono::steady_clock::now();
        lock_timings[iter] = std::chrono::duration<float, std::milli>(lock_timer_end - lock_timer_start).count();

        if (vault_locked)
        {
            cout << "Vault locked" << endl;
        }
        else
        {
            cout << "Failed to lock the vault with the reference " << reference_fingerprint_path << endl;
            printPQBRAKEresultToFile(OutputFile, reference_fingerprint_filename, query_fingerprint_filename, "biometric_lock_failure", empty_timings, empty_timings, empty_timings, empty_timings, empty_timings, empty_timings, empty_timings);
            OutputFile.close();
            exit(1);
        }

        /* temporarily opening the vault to access the value of the secret polynomial,
         * this is the only way to access this value,
         * the vault.open function sets the secret_polynomial variable if unlocking is successful
         */
        SmallBinaryFieldPolynomial secret_polynomial(vault.getField());
        if (!vault.open(secret_polynomial, ref))
        {
            cout << "Failed to temporarily unlock the vault with the reference " << reference_fingerprint_path << endl;
            printPQBRAKEresultToFile(OutputFile, reference_fingerprint_filename, query_fingerprint_filename, "biometric_unlock_failure", empty_timings, empty_timings, empty_timings, empty_timings, empty_timings, empty_timings, empty_timings);
            OutputFile.close();
            exit(1);
        }

                //-------------------------------
                //             OPRF
                //-------------------------------

        Client enrolled_client_machine(secret_polynomial);

        try
        {
            ZZX OPRF_client_enrollment_output = OPRF(&enrolled_client_machine, &evaluator_machine, false);

            OPRFCheck(&enrolled_client_machine, &evaluator_machine);   // checks if OPRF result is correct

            /* hashes the y_x output value of the OPRF procedure and converts it into a format suitable for
             * use as key input
             */
            string key_input = hashSHA256(printZZXconcatenated(OPRF_client_enrollment_output));
            uint8_t bytes_hash[32];
            for(int j=0; j<32; j++)
            {
                bytes_hash[j] = unsigned(key_input[j]);
            }

            oqs::KeyEncapsulation enrollment_KEM_client{"Kyber768"};
            auto enrollment_key_generation_start = chrono::steady_clock::now();
            enrolled_client_machine.public_key = enrollment_KEM_client.generate_keypair_based_on_input(bytes_hash);
            auto enrollment_key_generation_end = chrono::steady_clock::now();
            enrolled_client_machine.secret_key = enrollment_KEM_client.export_secret_key();
        } catch (int exc) {
            cout << "OPRF failure" << endl;
            printPQBRAKEresultToFile(OutputFile, reference_fingerprint_filename, query_fingerprint_filename, "OPRF_unblinding_failure", empty_timings, empty_timings, empty_timings, empty_timings, empty_timings, empty_timings, empty_timings);
            OutputFile.close();
            exit(1);
        }

        //---------------------------------------------------------------
        //                         VERIFICATION
        //---------------------------------------------------------------

                //-------------------------------
                //       Fuzzy vault query
                //-------------------------------

        auto preprocessing_start = chrono::steady_clock::now();
        MinutiaeView query = getMinutiaeView(query_fingerprint_path);
        auto preprocessing_end = chrono::steady_clock::now();
        preprocessing_timings[iter] = std::chrono::duration<float, std::milli>(preprocessing_end - preprocessing_start).count();

        SmallBinaryFieldPolynomial f(vault.getField());

        auto unlock_timer_start = chrono::steady_clock::now();
        bool vault_unlocked = vault.open(f, query);
        auto unlock_timer_end = chrono::steady_clock::now();
        if (vault_unlocked)
        {
            cout << "Vault unlocked" << endl;
        }
        else
        {
            cout << "Failed to unlock the vault with the query: " << query_fingerprint_filename << endl;
        }

        unlock_timings[iter] = std::chrono::duration<float, std::milli>(unlock_timer_end - unlock_timer_start).count();

        Client verifying_client_machine(f);       // initializes the verifying client

                //-------------------------------
                //   Ephemeral key generation
                //-------------------------------

        auto keygen_1_start = chrono::steady_clock::now();
        oqs::KeyEncapsulation ephemeral_keypair_client{"Kyber768"};
        verifying_client_machine.ephemeral_public_key = ephemeral_keypair_client.generate_keypair();
        auto keygen_1_end = chrono::steady_clock::now();
        keygen_timings[iter] = std::chrono::duration<float, std::milli>(keygen_1_end - keygen_1_start).count();
        verifying_client_machine.ephemeral_secret_key = ephemeral_keypair_client.export_secret_key();

        auto keygen_2_start = chrono::steady_clock::now();
        oqs::KeyEncapsulation ephemeral_keypair_server{"Kyber768"};
        server_machine.ephemeral_public_key = ephemeral_keypair_server.generate_keypair();
        auto keygen_2_end = chrono::steady_clock::now();
        keygen_timings[iter] = keygen_timings[iter] + std::chrono::duration<float, std::milli>(keygen_2_end - keygen_2_start).count();
        server_machine.ephemeral_secret_key = ephemeral_keypair_server.export_secret_key();

                //-------------------------------
                //             OPRF
                //-------------------------------

        oqs::KeyEncapsulation verification_KEM_client{"Kyber768"};   // initializes Client KEM object

        try
        {
            auto OPRF_timer_start = chrono::steady_clock::now();
            ZZX OPRF_client_verification_output = OPRF(&verifying_client_machine, &evaluator_machine, true);    // OPRF execution
            auto OPRF_timer_end = chrono::steady_clock::now();

            OPRF_timings[iter] = std::chrono::duration<float, std::milli>(OPRF_timer_end - OPRF_timer_start).count();

            OPRFCheck(&verifying_client_machine, &evaluator_machine);   // checks if OPRF result is correct

            /* hashes the y_x output value of the OPRF procedure and converts it into a format suitable for
             * use as key input
             */
            string key_input = hashSHA256(printZZXconcatenated(OPRF_client_verification_output));
            uint8_t bytes_hash[32];
            for(int l=0; l<32; l++)
            {
                bytes_hash[l] = unsigned(key_input[l]);
            }

            auto keygen_3_start = chrono::steady_clock::now();
            verifying_client_machine.public_key = verification_KEM_client.generate_keypair_based_on_input(bytes_hash); // generates keypair
            auto keygen_3_end = chrono::steady_clock::now();
            keygen_timings[iter] = keygen_timings[iter] + std::chrono::duration<float, std::milli>(keygen_3_end - keygen_3_start).count();
            verifying_client_machine.secret_key = verification_KEM_client.export_secret_key();
        } catch (int exc) {
            cout << "OPRF: failed" << endl;
            printPQBRAKEresultToFile(OutputFile, reference_fingerprint_filename, query_fingerprint_filename, "OPRF_unblinding_failure", empty_timings, empty_timings, empty_timings, empty_timings, empty_timings, empty_timings, empty_timings);
            OutputFile.close();
            exit(1);
        }

                //-------------------------------
                //             KEM
                //-------------------------------

        oqs::KeyEncapsulation KEM_server{"Kyber768"};
        auto encap_start = chrono::steady_clock::now();
        std::tie(server_machine.ciphertext, server_machine.shared_secret) =
                KEM_server.encap_secret(enrolled_client_machine.public_key);     // encapsulation
        auto encap_end = chrono::steady_clock::now();
        encap_timings[iter] = std::chrono::duration<float, std::milli>(encap_end - encap_start).count();

        auto decap_start = chrono::steady_clock::now();
        verifying_client_machine.shared_secret = verification_KEM_client.decap_secret(server_machine.ciphertext);   // decapsulation
        auto decap_end = chrono::steady_clock::now();
        decap_timings[iter] = std::chrono::duration<float, std::milli>(decap_end - decap_start).count();

                //-------------------------------
                //        Shared secret
                //-------------------------------

        string shared_secret_serverside;
        string shared_secret_clientside;

        string  cpkt(enrolled_client_machine.public_key.begin(), enrolled_client_machine.public_key.end()),
                cpke(verifying_client_machine.ephemeral_public_key.begin(), verifying_client_machine.ephemeral_public_key.end()),
                spk(server_machine.public_key.begin(), server_machine.public_key.end()),
                spke(server_machine.ephemeral_public_key.begin(), server_machine.ephemeral_public_key.end()),
                gamma(server_machine.shared_secret.begin(), server_machine.shared_secret.end()),
                cpkt_prime(verifying_client_machine.public_key.begin(), verifying_client_machine.public_key.end()),
                gamma_prime(verifying_client_machine.shared_secret.begin(), verifying_client_machine.shared_secret.end());

        /* derived shared secrets, KDF is a simple SHA256 hash for this example */
        shared_secret_serverside = hashSHA256(cpkt + cpke + spk + spke + gamma);
        shared_secret_clientside = hashSHA256(cpkt_prime + cpke + spk + spke + gamma_prime);

        /* compares hashes of shared secrets */
        if (hashSHA256(shared_secret_serverside) == hashSHA256(shared_secret_clientside))
            cout << "RESULT: Verification successful, established shared secret: " << hashSHA256(shared_secret_clientside) << endl;
        else
        {
            cout << "RESULT: Verification failed, shared secrets do not match." << endl;
            printPQBRAKEresultToFile(OutputFile, reference_fingerprint_filename, query_fingerprint_filename, "verification_failed", empty_timings, empty_timings, empty_timings, empty_timings, empty_timings, empty_timings, empty_timings);
            OutputFile.close();
            exit(1);
        }
        cout << "-------------------------------------------------------------------------------------------\n";
        if (!warmup_run)
            iter++;
        else
            warmup_run = false;
    }

    printPQBRAKEresultToFile(OutputFile,
                             reference_fingerprint_filename,
                             query_fingerprint_filename,
                             "verification_success",
                             preprocessing_timings,
                             lock_timings,
                             unlock_timings,
                             OPRF_timings,
                             keygen_timings,
                             encap_timings,
                             decap_timings
                             );
    OutputFile.close();

    /* prints result table with timings */
    cout << setw(21) << "";
    cout << setw(10) << "6    " << setw(10) << "8    " << setw(10) << "10    " << setw(10) << "12    " << setw(10) << "14    " << setw(10) << "16    " << "\n";
    cout << setw(21) << "Feature extraction |" << "\n";
    cout << setw(21) << "and preprocessing |";
    printArrayForTable(preprocessing_timings,true);
    cout << setw(21) << "lock |";
    printArrayForTable(lock_timings,true);
    cout << setw(21) << "unlock |";
    printArrayForTable(unlock_timings);
    cout << setw(21) << "OPRF |";
    printArrayForTable(OPRF_timings,true);
    cout << setw(21) << "Keygen, pkGen |";
    printArrayForTable(keygen_timings,true);
    cout << setw(21) << "encap |";
    printArrayForTable(encap_timings,true);
    cout << setw(21) << "decap |";
    printArrayForTable(decap_timings,true);
    cout << "-------------------------------------------------------------------------------------------" << "\n";
    cout << setw(21) << "Verification |";
    for(float unlock_timing : unlock_timings)
        cout << "  " << setw(6)
        <<  round(computeAverageFloat(preprocessing_timings)*100)/100 +
            round(computeAverageFloat(lock_timings)*100)/100 +
            round(unlock_timing*100)/100 +
            round(computeAverageFloat(OPRF_timings)*100)/100 +
            round(computeAverageFloat(keygen_timings)*100)/100 +
            round(computeAverageFloat(encap_timings)*100)/100 +
            round(computeAverageFloat(decap_timings)*100)/100
        << "  ";
    cout << "\n";

    return 0;
}