// concolic/solver.cpp
#include "concolic/solver.hpp"

namespace lure::concolic {

#ifdef LURE_USE_Z3
std::unique_ptr<Solver> create_z3_solver();
#endif

std::unique_ptr<Solver> create_solver()
{
#ifdef LURE_USE_Z3
    return create_z3_solver();
#else
    return nullptr;
#endif
}

} // namespace lure::concolic