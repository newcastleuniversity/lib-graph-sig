/**
 * Offers verifier classes, which are responsible for verifying responses offered 
 * by provers for proof clauses. The verifiers main task is to compute the
 * verifier's view on the witness, here called a hat-value.
 * 
 * <p>As a general rule, a verifier will implement the IVerifier interface.
 * As such, an IVerifier will receive its dependencies at construction.
 * It will offer an explicit checkLengths() method to validate its inputs.
 * Finally, executeVerification() will take a BigInteger challenge as input
 * and produce the hat-value for its proof clause.
 */
package eu.prismacloud.primitives.zkpgs.verifier;