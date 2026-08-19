// vm/ivm_runner.cpp
#include "vm/ivm_runner.hpp"

namespace lure::vm {

std::unique_ptr<IVMRunner> make_mock_runner();

#ifdef LURE_HAS_LUAU
std::unique_ptr<IVMRunner> make_luau_runner();
#else
std::unique_ptr<IVMRunner> make_luau_runner()
{
    return nullptr; // built without the Luau submodule
}
#endif

} // namespace lure::vm