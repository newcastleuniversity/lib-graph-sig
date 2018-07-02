package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public interface IProver {
  /**
   * The prover role computes zero-knowledge proofs of knowledge with a policy predicate P on graph
   * signatures. Theses proofs can either be interactive or non-interactive.
   */
  void createWitnessRandomness() throws ProofStoreException;

  void computeWitness() throws ProofStoreException;

  BigInteger computeChallenge() throws NoSuchAlgorithmException;

  void computeResponses();
}
