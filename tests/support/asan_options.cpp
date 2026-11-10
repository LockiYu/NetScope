// Homebrew's prebuilt GoogleTest and the active Apple libc++ use different
// container-annotation settings. Disabling only this annotation check prevents
// a false positive during --gtest_list_tests while retaining ASan's bounds,
// use-after-free, and leak checks for project code.
extern "C" const char* __asan_default_options() {
    return "detect_container_overflow=0";
}

