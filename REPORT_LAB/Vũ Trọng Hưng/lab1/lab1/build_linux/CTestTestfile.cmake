# CMake generated Testfile for 
# Source directory: /home/kali/Desktop/REPORT_5_LAB/lab1/lab1
# Build directory: /home/kali/Desktop/REPORT_5_LAB/lab1/lab1/build_linux
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(help_test "/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/build_linux/encrypt_tool" "--help")
set_tests_properties(help_test PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/CMakeLists.txt;221;add_test;/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/CMakeLists.txt;0;")
add_test(kat_vectors_test "/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/build_linux/encrypt_tool" "--kat" "/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/test_vectors.json")
set_tests_properties(kat_vectors_test PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/CMakeLists.txt;226;add_test;/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/CMakeLists.txt;0;")
add_test(negative_tests "/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/build_linux/encrypt_tool" "--negative-tests")
set_tests_properties(negative_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/CMakeLists.txt;231;add_test;/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/CMakeLists.txt;0;")
add_test(unit_tests "/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/build_linux/unit_tests")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/CMakeLists.txt;273;add_test;/home/kali/Desktop/REPORT_5_LAB/lab1/lab1/CMakeLists.txt;0;")
