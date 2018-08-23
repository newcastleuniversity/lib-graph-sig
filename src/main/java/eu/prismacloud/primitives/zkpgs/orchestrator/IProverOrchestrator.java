package eu.prismacloud.primitives.zkpgs.orchestrator;

import java.math.BigInteger;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;



/**
 * An orchestrator realizing the IProverOrchestrator realizes an overall zero-knowledge proof of knowledge,
 * using one or multiple component provers for sub-protocols.
 * 
 * <p>A proof orchestrator organizes the inputs for component provers and 
 * calls upon them to compute witnesses and responses. 
 * The orchestrator is responsible for knowing  and managing all proof context.
 * The orchestrator is responsible for computing the overall (cross-prover) challenge.
 */
public interface IProverOrchestrator {
	
	/**
	 * The orchestrator initializes and sets up an appropriate proof store for the proofs to come.
	 */
	void init();

	/**
	 * The orchestrator organizes the computations of the pre-challenge phase.
	 * 
	 * <p>Unlike component provers, orchestrators are expected to catch exceptions and to handle them appropriately.
	 */
	void executePreChallengePhase();

	/**
	 * The orchestrator organizes the computations of the post-challenge phase, based on a challenge.
	 * @param cChallenge
	 */
	void executePostChallengePhase(BigInteger cChallenge);

	/**
	 * Establishes the challenge for the current proof, based on the overall proof context.
	 * 
	 * @return BigInteger challenge with appropriate length.
	 * 
	 * @throws ProofStoreException
	 */
	BigInteger computeChallenge() throws ProofStoreException;

	/**
	 * Generates the serializable proof signature for the proof.
	 * 
	 * @return proof signature.
	 */
	ProofSignature createProofSignature();
}