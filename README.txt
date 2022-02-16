Build library without executing test cases
--------------------------------------------
mvn clean package  install -Dmaven.test.skip=true

Build javadocs
--------------
mvn javadoc:javadoc

Generate new public and secret keys
-----------------------------------
java -jar target/graph-sig-0.0.1-SNAPSHOT.jar -k 2048

Start the issuing protocol between a signer and a recipient
-----------------------------------------------------------
Recipient side: 
java -jar target/graph-sig-0.0.1-SNAPSHOT.jar  -r --verbose  -H localhost -T 9997

Signer side:
java -jar target/graph-sig-0.0.1-SNAPSHOT.jar  -s --verbose  -H localhost -T 9997

Execute the proof of geo-separation between a prover and a verifier
----------------------------------------------------------------------------
Prover side: 
java -jar target/graph-sig-0.0.1-SNAPSHOT.jar  -p --verbose  -H localhost -T 9997

Verifier side: 
java -jar target/graph-sig-0.0.1-SNAPSHOT.jar  -v --verbose  -q 1 -q 14 -H localhost -T 9997
