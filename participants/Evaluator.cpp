#include "Evaluator.hpp"

NTL::ZZ_pE Evaluator::compute_d_x() {
    return (c_x*k)+E;
}

NTL::ZZ_pE Evaluator::compute_c(NTL::ZZ_pE a) {
    return (a*k)+e;
}
