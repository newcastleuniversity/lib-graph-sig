Testing Graph Signature Library notes
-------------------------------------

Regenerating the signer's keypair for each test is performance intensive when we require a bitlength of 2048.

We can use a pre-generated serialized keypair to facilitate in the rapid testing of the Graph Signature Library.

Steps for generating a new signer's keypair:
---------------------------------------------

1. In file FilePersistenceUtilTest set the generateKeyPair flag to true.

2. Execute the writeSignerKeyPair test case in the same file.

3. Set generateKeyPair flag to false so that generation of the keypair is not executed when we have already generated a new keypair.


Testing with Maven
------------------
Tests can be executed using Maven from command line:
mvn clean test
