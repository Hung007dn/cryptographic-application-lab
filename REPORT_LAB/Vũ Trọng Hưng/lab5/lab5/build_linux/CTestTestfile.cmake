# CMake generated Testfile for 
# Source directory: /home/kali/Desktop/REPORT_5_LAB/lab5/lab5
# Build directory: /home/kali/Desktop/REPORT_5_LAB/lab5/lab5/build_linux
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(help_test "/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/build_linux/sigtool" "--help")
set_tests_properties(help_test PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/CMakeLists.txt;179;add_test;/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/CMakeLists.txt;0;")
add_test(kat_tests "/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/build_linux/sigtool" "--kat" "/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/test_vectors.json")
set_tests_properties(kat_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/CMakeLists.txt;183;add_test;/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/CMakeLists.txt;0;")
add_test(negative_tests "/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/build_linux/sigtool" "--negative-tests")
set_tests_properties(negative_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/CMakeLists.txt;187;add_test;/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/CMakeLists.txt;0;")
add_test(unit_tests "/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/build_linux/unit_tests")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/CMakeLists.txt;252;add_test;/home/kali/Desktop/REPORT_5_LAB/lab5/lab5/CMakeLists.txt;0;")
