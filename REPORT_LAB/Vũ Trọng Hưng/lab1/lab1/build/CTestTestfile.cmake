# CMake generated Testfile for 
# Source directory: C:/VTH/lab1/lab1
# Build directory: C:/VTH/lab1/lab1/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(help_test "C:/VTH/lab1/lab1/build/encrypt_tool.exe" "--help")
set_tests_properties(help_test PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab1/lab1/CMakeLists.txt;221;add_test;C:/VTH/lab1/lab1/CMakeLists.txt;0;")
add_test(kat_vectors_test "C:/VTH/lab1/lab1/build/encrypt_tool.exe" "--kat" "C:/VTH/lab1/lab1/test_vectors.json")
set_tests_properties(kat_vectors_test PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab1/lab1/CMakeLists.txt;226;add_test;C:/VTH/lab1/lab1/CMakeLists.txt;0;")
add_test(negative_tests "C:/VTH/lab1/lab1/build/encrypt_tool.exe" "--negative-tests")
set_tests_properties(negative_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab1/lab1/CMakeLists.txt;231;add_test;C:/VTH/lab1/lab1/CMakeLists.txt;0;")
add_test(unit_tests "C:/VTH/lab1/lab1/build/unit_tests.exe")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab1/lab1/CMakeLists.txt;273;add_test;C:/VTH/lab1/lab1/CMakeLists.txt;0;")
