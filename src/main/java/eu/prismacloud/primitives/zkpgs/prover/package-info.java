/**
 * Offers prover classes, which are responsible for creating witnesses and responses
 * for zero-knowledge proves. Normally, a prover will be responsible for a single 
 * proof clause, for instance, proving the representation of a single commitment or
 * proving the pair-wise difference between two committed exponents.
 * 
 * <p>As a general rule, a prover will implement the IProver interface.
 * As such, an IProver will receive its dependencies at construction.
 * Provers function in three phases:
 * <ol>
 *   <li>executePrecomputation() - enables the prover to make computations of 
 *   values needed for its own proofs (as well as a possibly by other provers).
 *   The pre-computation is optional and will be a no-operation in many cases.
 *   <li>executePreChallengePhase() - constructs the witness randomness and witness
 *   for the proof clause this prover is concerned with. The witness is calles a tilde-value.
 *   <li>executePostChallengePhase(BigInteger challenge) - takes a BigInteger challenge
 *   as input to compute the appropriate for the secrets this prover is responsible for.
 * </ol>
 * 
 * <p>Normally, each prover instance is only responsible for a single proof clause
 * and will, in turn, only compute a single tilde-value. Provers are 
 * instantiated and called by an IProverOrchestrator. The orchestrator will
 * organizing the computations of multiple component provers and to combine their 
 * tilde-values to compute the challenge in the Fiat-Shamir heuristic.
 * 
 * <p>Provers depend on two kinds of external data:
 * <ul>
 *   <li>an ExtendedPublicKey issued by a Signer, and 
 *   <li>a ProofStore to share data with other provers
 *   and orchestrators.
 * </ul>
 * 
 * <p>A typical call sequence for a IProver will be as follows:
 * <ol>
 *   <li>IProver prover = new IProver(public value, extendedPublicKey, proofStore);
 *   The prover may relay on further data in the ProofStore.
 *   <li>prover.executePrecomputation();
 *   <li>GroupElement tildeValue = prover.executePreChallengePhase();
 *   <li>The orchestrator will combine the tildeValues of all provers to compute the 
 *   challenge in the FiatShamir heuristic. Then all provers are called with the same
 *   challenge.
 *   <li>Map<URN, BigInteger> responses = prover.executePostChallengePhase(challenge);
 *   <li>The responses are then combined by the prover orchestrator to be sent to the 
 *   verifier.
 * </ol>
 */
package eu.prismacloud.primitives.zkpgs.prover;