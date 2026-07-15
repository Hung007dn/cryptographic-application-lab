#pragma once
#include <string>
#include <vector>

class PQNegativeTests {
public:
    // Run all negative tests, returns true if all pass correctly (all must fail as expected)
    static bool runAll();

private:
    static bool testModifiedMessageFails();
    static bool testModifiedSigFails();
    static bool testWrongKeyFails();
    static bool testModifiedKEMCiphertextFails();
    static bool testTamperedCertFails();
};
