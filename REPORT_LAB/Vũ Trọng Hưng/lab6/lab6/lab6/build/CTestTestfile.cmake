# CMake generated Testfile for 
# Source directory: C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6
# Build directory: C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(help_test "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/build/pqtool.exe" "--help")
set_tests_properties(help_test PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;101;add_test;C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;0;")
add_test(kat_tests "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/build/pqtool.exe" "--kat" "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/test_vectors.json")
set_tests_properties(kat_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;102;add_test;C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;0;")
add_test(negative_tests "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/build/pqtool.exe" "--negative-tests")
set_tests_properties(negative_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;103;add_test;C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;0;")
add_test(batch_verify_demo "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/build/pqtool.exe" "--batch-verify-demo" "--algo" "mldsa-44" "--count" "5")
set_tests_properties(batch_verify_demo PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;104;add_test;C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;0;")
add_test(batch_decaps_bench "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/build/pqtool.exe" "--batch-decaps-bench" "--algo" "mlkem-512" "--count" "5")
set_tests_properties(batch_decaps_bench PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;105;add_test;C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;0;")
add_test(unit_tests "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/build/unit_tests.exe")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;130;add_test;C:/Users/lenovo/Desktop/REPORT~2/VTRNGH~1/lab6/lab6/lab6/CMakeLists.txt;0;")
