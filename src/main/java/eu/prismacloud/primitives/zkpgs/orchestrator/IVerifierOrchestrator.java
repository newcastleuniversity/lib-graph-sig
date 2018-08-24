package eu.prismacloud.primitives.zkpgs.orchestrator;

import java.math.BigInteger;
import java.util.Map;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.util.URN;



/**
 * An orchestrator realizing the IVerifierOrchestrator realizes the verification of
 * a Zero-Knowledge Proof of Knowledge by drawing upon component verifiers.
 * 
 * <p>A proof orchestrator organizes the inputs for component verifiers. 
 * The orchestrator is responsible for knowing  and managing all proof context.
 * The orchestrator is responsible for computing the overall (cross-prover) challenge.
 */
public interface IVerifierOrchestrator {
	
	/**
	 * The orchestrator initializes and sets up an appropriate proof store for the proofs to come.
	 */
	void init();

	/**
	 * The orchestrator organizes the computations of the verification, based on a challenge.
	 * @param cChallenge
	 */
	boolean executeVerification(BigInteger cChallenge);

	/**
	 * Establishes the challenge for the current verification, based on the overall proof context.
	 * 
	 * @return BigInteger challenge with appropriate length.
	 * 
	 * @throws ProofStoreException
	 */
	BigInteger computeChallenge() throws ProofStoreException;
	
	/**
	 * Orchestrates to have the lengths of all proof signature elements checked.
	 * 
	 * @param proofSignatureElements
	 * 
	 * @return <tt>true</tt> if all lengths are validated successfully.
	 */
	boolean checkLengths(Map<URN, Object> proofSignatureElements);
}
