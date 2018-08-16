Testing Graph Signature Library notes
-------------------------------------

Regenerating the signer's keypair for each test is performance intensive when we require a bitlength of 2048.

We can use a pre-generated serialized keypair to facilitate in the rapid testing of the Graph Signature Library.

Steps for generating a new signer's keypair and a new signer public key:
------------------------------------------------------------------------

1. In file FilePersistenceUtilTest in test package util set the generateKey flag to true.

2. Execute the writeSignerKeyPairAndPublicKey test case in the same file.

3. Set generateKey flag to false so that generation of the keypair and public key is not executed when we have already generated a new keypair and public key.


Testing with Maven
------------------
Tests can be executed using Maven from command line:
mvn clean test

Test Suites
-----------
The file GSTestSuite.java in package integration provides the parallel execution of test classes, which are used for testing the issuing protocol and the geo-location separation proof. This is accomplished by using a custom JUnit test extension annotation such as @EnabledOnSuite(name = GSSuite.PROVER_VERIFIER). This annotation enables JUnit to execute the first tests for the Prover and then the tests for the Verifier. These tests will only be executed from inside the GSTestSuite class. If the tests need to be executed manually the annotations EnabledOnSuite can be commented out and execute the corresponding test cases.

