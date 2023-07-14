/*
 *  Client
 * */
#pragma once
#include <NTL/ZZ_pE.h>


class Evaluator
{
public:
    NTL::ZZ_pE  a,
                k,
                e,
                c,
                E,
                c_x;
    NTL::ZZ_pE compute_d_x();
    NTL::ZZ_pE compute_c(NTL::ZZ_pE a);
};