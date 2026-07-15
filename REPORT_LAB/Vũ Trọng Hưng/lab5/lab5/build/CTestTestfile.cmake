# CMake generated Testfile for 
# Source directory: C:/VTH/lab5/lab5
# Build directory: C:/VTH/lab5/lab5/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(help_test "C:/VTH/lab5/lab5/build/sigtool.exe" "--help")
set_tests_properties(help_test PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab5/lab5/CMakeLists.txt;179;add_test;C:/VTH/lab5/lab5/CMakeLists.txt;0;")
add_test(kat_tests "C:/VTH/lab5/lab5/build/sigtool.exe" "--kat" "C:/VTH/lab5/lab5/test_vectors.json")
set_tests_properties(kat_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab5/lab5/CMakeLists.txt;183;add_test;C:/VTH/lab5/lab5/CMakeLists.txt;0;")
add_test(negative_tests "C:/VTH/lab5/lab5/build/sigtool.exe" "--negative-tests")
set_tests_properties(negative_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab5/lab5/CMakeLists.txt;187;add_test;C:/VTH/lab5/lab5/CMakeLists.txt;0;")
add_test(unit_tests "C:/VTH/lab5/lab5/build/unit_tests.exe")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab5/lab5/CMakeLists.txt;252;add_test;C:/VTH/lab5/lab5/CMakeLists.txt;0;")
