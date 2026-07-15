# CMake generated Testfile for 
# Source directory: C:/VTH/lab3/lab3
# Build directory: C:/VTH/lab3/lab3/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(help_test "C:/VTH/lab3/lab3/build/rsatool.exe" "--help")
set_tests_properties(help_test PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab3/lab3/CMakeLists.txt;192;add_test;C:/VTH/lab3/lab3/CMakeLists.txt;0;")
add_test(unit_tests "C:/VTH/lab3/lab3/build/unit_tests.exe")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "C:/VTH/lab3/lab3/CMakeLists.txt;237;add_test;C:/VTH/lab3/lab3/CMakeLists.txt;0;")
