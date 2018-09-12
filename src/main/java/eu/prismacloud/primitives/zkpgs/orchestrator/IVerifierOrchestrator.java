package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.message.IMessagePartner;
import eu.prismacloud.primitives.zkpgs.store.IURNGoverner;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;


/**
 * An orchestrator realizing the IVerifierOrchestrator realizes the verification of
 * a Zero-Knowledge Proof of Knowledge by drawing upon component verifiers.
 *
 * <p>A verifier orchestrator organizes the inputs for component verifiers.
 * The orchestrator is responsible for knowing  and managing all proof context.
 * The orchestrator is responsible for computing the overall (cross-prover) challenge.
 *
 * <p>A class implementing IVerifierOrchestrator is expected to offer a constructor to
 * completely settle the dependencies of the orchestrator.
 * <ol>
 * <li>The init() function should be called first for preliminary computations.</li>
 * <li>Then, checkLength() is next to establish that all inputs are sound.</li>
 * <li>computeChallenge() establishes an appropriate challenge for the proof context.</li>
 * <li>Finally, executeVerification() completes the verification.</li>
 * </ol>
 *
 * <p>Top-level orchestrators should catch exceptions and handle them conservatively.
 */
public interface IVerifierOrchestrator extends IMessagePartner, IURNGoverner {

    /**
     * The orchestrator initializes and sets up an appropriate proof store for the proofs to come.
     */
    @Override
    void init() throws IOException;

    /**
     * The orchestrator organizes the computations of the verification, based on a challenge.
     *
     * @param cChallenge the challenge used for the verification computations
     * @return <tt>true</tt> if the verification succeeds or <tt>false</tt> if the verification fails
     * @throws NoSuchAlgorithmException if storing or retrieving elements from the proof store fails
     * @throws ProofStoreException if algorithm for hash function is not supported
     */
    boolean executeVerification(BigInteger cChallenge) throws NoSuchAlgorithmException, ProofStoreException;

    /**
     * Establishes the challenge for the current verification, based on the overall proof context.
     *
     * @return BigInteger challenge with appropriate length.
     * @throws ProofStoreException if storing or retrieving elements from the proof store fails
     * @throws NoSuchAlgorithmException if algorithm for hash function is not supported
     */
    BigInteger computeChallenge() throws ProofStoreException, NoSuchAlgorithmException;

    /**
     * Orchestrates to have the lengths of all proof signature elements checked.
     *
     * @return <tt>true</tt> if all lengths are validated successfully.
     */
    boolean checkLengths();

    /**
     * Orchestrates to have the lengths of inputted proof signature elements checked.
     *
     * @param proofSignatureElements
     *
     * @return <tt>true</tt> if all lengths are validated successfully.
     * @deprecated
     */
    //boolean checkLengths(Map<URN, Object> proofSignatureElements);
}
