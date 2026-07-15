# CMake generated Testfile for 
# Source directory: C:/VTH/lab4/lab4
# Build directory: C:/VTH/lab4/lab4/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(help_test "C:/VTH/lab4/lab4/build/hashtool.exe" "--help")
set_tests_properties(help_test PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab4/lab4/CMakeLists.txt;162;add_test;C:/VTH/lab4/lab4/CMakeLists.txt;0;")
add_test(kat_tests "C:/VTH/lab4/lab4/build/hashtool.exe" "--kat" "C:/VTH/lab4/lab4/test_vectors.json")
set_tests_properties(kat_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab4/lab4/CMakeLists.txt;167;add_test;C:/VTH/lab4/lab4/CMakeLists.txt;0;")
add_test(negative_tests "C:/VTH/lab4/lab4/build/hashtool.exe" "--negative-tests")
set_tests_properties(negative_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab4/lab4/CMakeLists.txt;172;add_test;C:/VTH/lab4/lab4/CMakeLists.txt;0;")
add_test(unit_tests "C:/VTH/lab4/lab4/build/unit_tests.exe")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab4/lab4/CMakeLists.txt;214;add_test;C:/VTH/lab4/lab4/CMakeLists.txt;0;")
