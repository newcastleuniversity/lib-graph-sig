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
 * 
 * <p>Normally, each verifier instance is only responsible for a single proof clause
 * and will, in turn, only produce a single hat-value. Hence, verifiers are usually
 * instantiated and called by an IVerifierOrchestrator, which is responsible for
 * organizing the work of multiple verifiers and to combine their hat-values in
 * the final verification step.
 * 
 * <p>In general, verifiers depend on two kinds of external data:
 * <ul>
 *   <li>an ExtendedPublicKey issued by a Signer, and 
 *   <li>an instance of a ProofStore to arrange for data sharing between verifiers
 *   and orchestrators.
 * </ul>
 * 
 * <p>A typical call sequence for a IVerifier will be as follows:
 * <ol>
 *   <li>IVerifier verifier = new IVerifier(public value, extendedPublicKey, proofStore);
 *   The verifier may relay on values in the ProofStore.
 *   <li>if (!verifier.checkLengths()) abort!
 *   <li>Get BigInteger challenge from orchestrator.
 *   <li>GroupElement hatValue = verifier.executeVerification(challenge);
 *   <li>The orchestrator will then include this hatValue in the ProofContext for verification.
 * </ol>
 */
package uk.ac.ncl.cascade.zkpgs.verifier;