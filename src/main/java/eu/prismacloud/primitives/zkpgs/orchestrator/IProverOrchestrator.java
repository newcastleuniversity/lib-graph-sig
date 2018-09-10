package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.message.IMessagePartner;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.IURNGoverner;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;


/**
 * An orchestrator realizing the IProverOrchestrator realizes an overall zero-knowledge proof of knowledge,
 * using one or multiple component provers for sub-protocols.
 *
 * <p>A proof orchestrator organizes the inputs for component provers and
 * calls upon them to compute witnesses and responses.
 * The orchestrator is responsible for knowing  and managing all proof context.
 * The orchestrator is responsible for computing the overall (cross-prover) challenge.
 */
public interface IProverOrchestrator extends IMessagePartner, IURNGoverner {
    /* TODO There is an option to have orchestrator and provers share the exact interfaces
    of pre- and post-challenge phases. Then a class could implement both interfaces as a short-hand. */

    /**
     * The orchestrator initializes and sets up an appropriate proof store for the proofs to come.
     */
    @Override
    void init() throws IOException;

    /**
     * The orchestrator organizes the computations of the pre-challenge phase.
     *
     * <p>Unlike component provers, top-level orchestrators are 
     * expected to catch exceptions and to handle them appropriately.
     * 
     * @throws ProofStoreException if a ProofStore element could 
     * not be accessed.
     */
    void executePreChallengePhase() throws ProofStoreException;

    /**
     * The orchestrator organizes the computations of the post-challenge phase, based on a challenge.
     *
     * @param cChallenge the challenge used for executing the post challenge phase
     * @throws IOException if Input or Output operation fails when executing post challenge phase
     */
    void executePostChallengePhase(BigInteger cChallenge) throws ProofStoreException, IOException;

    /**
     * Establishes the challenge for the current proof, based on the overall proof context.
     *
     * @return BigInteger challenge with appropriate length.
     * @throws ProofStoreException if storing or retrieving elements from the proof store fails
     * @throws NoSuchAlgorithmException  if the hash algorithm wasn't found.
     */
    BigInteger computeChallenge() throws ProofStoreException, NoSuchAlgorithmException;

    /**
     * Generates the serializable proof signature for the proof.
     *
     * @return proof signature.
     */
    ProofSignature createProofSignature();
}
