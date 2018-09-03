/**
 * The package holds variants of orchestrators, that is, 
 * classes that are responsible for organizing zero-knowledge
 * proofs of knowledge with multiple component provers and verifiers.
 * 
 * <p>As general separation of duty, an orchestrator is responsible
 * for instantiating and running one or multiple component 
 * provers/verifiers, for governing the ProofStore and for 
 * establishing the overall ProofContext and challenge.
 * 
 * <p>The component provers/verifiers are, in turn, responsible for 
 * computing either witnesses and responses on the prover side or
 * the verifier's view of the witness.
 * 
 * <p>As a convention, an orchestrator will create one component
 * prover/verifier for each proof clause and delegate the computation
 * of the corresponding algebra to the component prover/verifier.
 * 
 * <p>The IProverOrchestrator interface prescribes the methods of 
 * orchstrators running proofs. The IVerifierOrchestrator interface methods
 * of running verifications.
 */
package eu.prismacloud.primitives.zkpgs.orchestrator;