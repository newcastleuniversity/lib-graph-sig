package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

/**
 * The prover role computes zero-knowledge proofs of knowledge with a policy predicate P on graph
 * signatures. Theses proofs can either be interactive or non-interactive.
 * 
 * <p>Provers have a common interface in that they are executed in two distinct phases,
 * with common goals and outputs:
 * <ol>
 *   <li><strong>PreChallengePhase:</strong>  
 *   Operates on proof-specific public values to compute witness randomness as 
 *   internal state and to output a witness (called a tilde-value).</li>
 *   <li><strong>PostChallgenePhase:</strong> 
 *   Takes as explicit input a BigInteger challenge value and outputs a number 
 *   of responses (so called hat-values) corresponding to proven secrets and their witness randomness.
 * </ol>
 * 
 * <p>Provers may relay on a ProofStore to hold their governed state under URNs.
 * AS a convention all prover classes shall declare an URNID constant.
 * 
 * <p>The provers come with methods to validate their internal state and 
 * the verifiability of their responses.
 * 
 * <p>As a general rule, provers are responsible for throwing exceptions and 
 * enabling the proof orchestrator to handle them accordingly.
 * 
 * <p>By convention, the IProvers use Constructor Dependency Injection, that is,
 * all dependencies of the prover shall be set at construction time and be
 * declared <tt>final</tt>.
 * 
 * <p>The constructors are to have a parameter order that names the ProofStore last,
 * and the IPublicKey used second to last. Prover-specific parameters (public values)
 * are submitted first.
 */
public interface IProver {

	/**
	 * Enables the prover to execute a pre-computation before the pre-challenge phase is called.
	 * For many provers this step may be a no-operation.
	 */
	public void executePrecomputation() throws ProofStoreException;


	/**
	 * Executes the pre-challenge phase of the proof computing witness 
	 * randomness and the corresponding witness.
	 * 
	 * <p>Provers are responsible for computing witness randomness and to 
	 * store this witness randomness in the ProofStore as a side-effect.
	 *
	 * @return a GroupElement being the overall witness (tilde-value) for this proof.
	 * @throws ProofStoreException
	 */
	// TODO this method is to replace preChallengePhase()
	GroupElement executePreChallengePhase() throws ProofStoreException;

	/**
	 * Computes the witness randomness with appropriate length and 
	 * stores the witness randomness in the ProofStore.
	 * 
	 * The createWitnessRandomness method is responsible for having all witness randomness
	 * stored in the ProofStore under appropriate URNs after its execution.
	 *  
	 * @throws ProofStoreException
	 */
	/* TODO createWitnessRandomness and computeWitness() should not exposed on the interface
	 * because they can leave the prover in an inconsistent state or fail.
	 */
	void createWitnessRandomness() throws ProofStoreException;

	/**
	 * Computes the witness for this component prover.
	 * 
	 * @throws ProofStoreException
	 */
	GroupElement computeWitness() throws ProofStoreException;

	// TODO Challenge is computed by the Orchestrator, not the prover.
	BigInteger computeChallenge() throws NoSuchAlgorithmException;

	/**
	 * Computes the post-challenge phase of the prover, based on a given challenge.
	 * 
	 * <p>The prover must output a (possibly one-element) map of responses computed.
	 * The prover is further required to store these responses in the ProofStore.
	 * 
	 * @param cChallenge BigInteger challenge, which can either be 0 or 1 or a longer bit-string.
	 * 
	 * @return A map of response BigIntger values, where the URN index must correspond to
	 * this provers URN name for those responses.
	 */
	// TODO This method is to replace computeResponses() or postChallengePhase()
	public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge) throws ProofStoreException;

	/** 
	 * Computes the appropriate responses for the witness
	 * 
	 * TODO per topocert specification, this method should return the responses.
	 */
	void computeResponses();

	/**
	 * This method checks whether the prover has everything at its disposal to
	 * start the pre-challenge phase, incl. a possibly required pre-computation.
	 * 
	 * <p>This method is not only to check whether all required proof-specific
	 * public values are set correctly, it is also to verify that the ProofStore
	 * contains the data this prover would require.
	 * 
	 * @return <tt>true</tt> if the prover can be expected to complete its computations
	 * without fail.
	 */
	boolean isSetupComplete();
	
	/**
	 * Self-verifies the proof in the post-challenge phase. 
	 * 
	 * @return <tt>true</tt> if the responses yield a correct verification with respect to
	 *   established witness and given responses.
	 */
	boolean verify();
	
	// TODO include URN inquiry into interface?
//	String getProverURN(URNType t);
//	
//	String getProverURN(URNType t, int index);
	
	/**
	 * Returns a list of the URN identifiers of the data in the ProofStore
	 * that this prover governs.
	 * 
	 * @return List of URNs this prover is responsible for.
	 */
	List<URN> getGovernedURNs();
}
