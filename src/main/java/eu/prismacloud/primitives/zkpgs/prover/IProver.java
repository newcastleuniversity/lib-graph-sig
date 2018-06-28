package eu.prismacloud.primitives.zkpgs.prover;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public interface IProver {
  /**
   * The prover role computes zero-knowledge proofs of knowledge with a policy predicate P on graph
   * signatures. Theses proofs can either be interactive or non-interactive.
   */
  void createWitnessRandomness();

  void computeWitness();

  BigInteger computeChallenge() throws NoSuchAlgorithmException;

  void computeResponses();
}
