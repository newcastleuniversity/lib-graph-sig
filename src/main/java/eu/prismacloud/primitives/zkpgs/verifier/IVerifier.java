package eu.prismacloud.primitives.zkpgs.verifier;

import java.math.BigInteger;
import java.util.List;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

public interface IVerifier {
	
	/**
	 * Evaluates the verification computation, producing a verifier-side hat-value.
	 * 
	 * <p>In terms of overall proof-consistency, the hat-value produced by the component
	 * verifier must equal the tilde-value of the corresponding prover. 
	 * 
	 * <p>The method relies upon the public values and responses being stored in the
	 * ProofStore under URNs that correspond to the component verifier.
	 * 
	 * @param cChallenge the challenge of the overall proof.
	 * @return hat-value to be included in the overall verification.
	 * 
	 * @throws ProofStoreException
	 */
	GroupElement executeVerification(BigInteger cChallenge) throws ProofStoreException;
	
	/**
	 * Checks the lengths of inputed prover-responses (hat-values).
	 *  
	 * @return <tt>true</tt> if the lengths fulfil the requirements for the given prover.
	 */
	boolean checkLengths();
	
	/**
	 * Verifies if the component verifier is setup consistently to commence the 
	 * verification on challenge and responses.
	 * 
	 * @return
	 */
	boolean isSetupComplete();
	
	/**
	 * Returns a list of the URN identifiers of the data in the ProofStore
	 * that this verifier governs.
	 * 
	 * @return List of URNs this verifier is responsible for.
	 */
	List<URN> getGovernedURNs();
}
