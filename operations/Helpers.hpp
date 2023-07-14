/**
 * Helper functions
 */
#pragma once

#include <vector>
#include <cmath>
#include <string>
#include <NTL/ZZXFactoring.h>
#include <NTL/ZZ_pE.h>
#include <NTL/ZZ_pXFactoring.h>
#include <NTL/ZZ_pEX.h>
#include <NTL/RR.h>
#include "../participants/Client.hpp"
#include "../participants/Evaluator.hpp"
#include "../participants/Server.hpp"
#include "../oqs_cpp.h"

NTL::ZZ_pE spawnRingPolynomial(NTL::ZZ *coefficients);

void ringSetup();

std::vector<NTL::RR> qShifting(std::vector<NTL::RR> coefficients);

std::vector<NTL::RR> pEtoVectorRR(const NTL::ZZ_pE &polynom);

NTL::RR computeExpectedErrorRate();

double computeAverage(const vector<double> &values);

float computeAverageFloat(const float values[], int size=6);

void printParameters();

oqs::bytes convert_to_oqs_bytes(const char *c_str, std::size_t length);

void OPRFCheckLogging(Client *client, Evaluator *evaluator, ofstream &OutputFile, int iter);

void OPRFCheck(Client *client, Evaluator *evaluator);

std::string printZZXconcatenated(const NTL::ZZX &polynomial);

void printPQBRAKEresultToFile(ofstream &OutputFile, const string& reference_fingerprint_filename, const string& query_fingerprint_filename, const string& protocol_failure_reason, const float preprocessing[], const float lock[], const float unlock[], const float OPRF[], const float keygen [],
                              const float encap[], const float decap[]);

void printArrayForLog(ofstream &OutputFile, const float *print_array, bool last_line=false);
void printArrayForTable(const float *print_array, bool average = false);