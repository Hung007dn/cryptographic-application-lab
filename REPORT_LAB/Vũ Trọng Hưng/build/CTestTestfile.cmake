# CMake generated Testfile for 
# Source directory: D:/Documents/DAIHOC/MMUD/REPORT_5_LAB/lab3/lab3
# Build directory: D:/Documents/DAIHOC/MMUD/REPORT_5_LAB/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(help_test "D:/Documents/DAIHOC/MMUD/REPORT_5_LAB/build/rsatool.exe" "--help")
set_tests_properties(help_test PROPERTIES  _BACKTRACE_TRIPLES "D:/Documents/DAIHOC/MMUD/REPORT_5_LAB/lab3/lab3/CMakeLists.txt;192;add_test;D:/Documents/DAIHOC/MMUD/REPORT_5_LAB/lab3/lab3/CMakeLists.txt;0;")
add_test(unit_tests "D:/Documents/DAIHOC/MMUD/REPORT_5_LAB/build/unit_tests.exe")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "D:/Documents/DAIHOC/MMUD/REPORT_5_LAB/lab3/lab3/CMakeLists.txt;237;add_test;D:/Documents/DAIHOC/MMUD/REPORT_5_LAB/lab3/lab3/CMakeLists.txt;0;")
