# CMake generated Testfile for 
# Source directory: /home/kali/Desktop/REPORT_5_LAB/lab6/lab6
# Build directory: /home/kali/Desktop/REPORT_5_LAB/lab6/lab6/build_linux
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(help_test "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/build_linux/pqtool" "--help")
set_tests_properties(help_test PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;101;add_test;/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;0;")
add_test(kat_tests "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/build_linux/pqtool" "--kat" "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/test_vectors.json")
set_tests_properties(kat_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;102;add_test;/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;0;")
add_test(negative_tests "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/build_linux/pqtool" "--negative-tests")
set_tests_properties(negative_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;103;add_test;/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;0;")
add_test(batch_verify_demo "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/build_linux/pqtool" "--batch-verify-demo" "--algo" "mldsa-44" "--count" "5")
set_tests_properties(batch_verify_demo PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;104;add_test;/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;0;")
add_test(batch_decaps_bench "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/build_linux/pqtool" "--batch-decaps-bench" "--algo" "mlkem-512" "--count" "5")
set_tests_properties(batch_decaps_bench PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;105;add_test;/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;0;")
add_test(unit_tests "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/build_linux/unit_tests")
set_tests_properties(unit_tests PROPERTIES  _BACKTRACE_TRIPLES "/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;130;add_test;/home/kali/Desktop/REPORT_5_LAB/lab6/lab6/CMakeLists.txt;0;")
