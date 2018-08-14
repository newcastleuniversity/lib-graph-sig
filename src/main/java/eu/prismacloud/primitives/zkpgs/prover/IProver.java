package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

/**
 * The prover role computes zero-knowledge proofs of knowledge with a policy predicate P on graph
 * signatures. Theses proofs can either be interactive or non-interactive.
 */
public interface IProver {

/**
 * Computes the witness randomness with appropriate length and 
 * stores the witness randomness in the ProofStore.
 * 
 * The createWitnessRandomness method is responsible for having all witness randomness
 * stored in the ProofStore under appropriate URNs after its execution.
 *  
 * @throws ProofStoreException
 */
  void createWitnessRandomness() throws ProofStoreException;

  /**
   * Computes the witness for this component prover.
   * 
   * @throws ProofStoreException
   */
  void computeWitness() throws ProofStoreException;

  // TODO Challenge is computed by the Orchestrator, not the prover.
  BigInteger computeChallenge() throws NoSuchAlgorithmException;

  /** 
   * Computes the appropriate responses for the witness
   * 
   * TODO per topocert specification, this method should return the responses.
   */
  void computeResponses();
  
  /**
   * Self-verifies the proof in the post-challenge phase. 
   * 
   * @return <tt>true</tt> if the responses yield a correct verification with respect to
   *   established witness and given responses.
   */
  boolean verify();
}
