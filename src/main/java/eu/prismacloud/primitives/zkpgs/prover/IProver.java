package eu.prismacloud.primitives.zkpgs.prover;

public interface IProver {
  /**
   * The prover role computes zero-knowledge proofs of knowledge with a policy predicate P on graph
   * signatures. Theses proofs can either be interactive or non-interactive.
   */
  void createWitnessRandomness();
  void computeWitness();
  void computeChallenge();
  void computeResponses();
  
}
