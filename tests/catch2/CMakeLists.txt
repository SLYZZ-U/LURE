add_executable(lure_tests
    test_pipeline.cpp
    test_emulator.cpp
)
target_link_libraries(lure_tests PRIVATE
    Catch2::Catch2WithMain
    lure_reconstruct
    lure_lift
    lure_vm
    lure_common
    rbx_emulator
)
include(Catch)
catch_discover_tests(lure_tests)