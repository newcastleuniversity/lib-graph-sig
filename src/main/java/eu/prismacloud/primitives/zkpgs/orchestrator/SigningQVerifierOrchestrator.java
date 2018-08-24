package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.GSVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.PossessionVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.SigningQCorrectnessVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.VerifierFactory;
import eu.prismacloud.primitives.zkpgs.verifier.VerifierFactory.VerifierType;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class SigningQVerifierOrchestrator implements IVerifierOrchestrator {

	private Logger gslog = GSLoggerConfiguration.getGSlog();

	private final ProofSignature P_2;

	private final ExtendedPublicKey extendedPublicKey;
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;
	private final GraphEncodingParameters graphEncodingParameters;

	private BigInteger cChallenge;
	private BigInteger hatc;
	private BigInteger hatd;

	private GroupElement Q;

	private GroupElement A;

	private GroupElement hatA;

	private final BigInteger n_2;

	private GSSignature sigma;
	
	private final SigningQCorrectnessVerifier verifier; 

	public SigningQVerifierOrchestrator(
			final ProofSignature P_2,
			final GSSignature sigma,
			final BigInteger nonce,
			final ExtendedPublicKey extendedPublicKey,
			final ProofStore<Object> proofStore) {

		this.extendedPublicKey = extendedPublicKey;
		this.proofStore = proofStore;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
		
		this.sigma = sigma;
		this.P_2 = P_2;
		this.n_2 = nonce;
		
		this.verifier = new SigningQCorrectnessVerifier(extendedPublicKey.getPublicKey(), proofStore);
	}

	
	@Override
	public void init() {
		// no further initialization needed.
	}


	@Override
	public boolean checkLengths(Map<URN, Object> proofSignatureElements) {
		return verifier.checkLengths();
	}

	@Override
	public BigInteger computeChallenge() {
		gslog.info("compute challenge ");
		List<String> ctxList = populateChallengeList();
		try {
			hatc = CryptoUtilsFacade.computeHash(ctxList, keyGenParameters.getL_H());
		} catch (NoSuchAlgorithmException e) {
			gslog.log(Level.SEVERE, "Could not find the hash algorithm.", e);
			return null;
		}
		return hatc;
	}


	private boolean verifyChallenge() throws VerificationException {
		if (!cChallenge.equals(hatc)) {
			throw new VerificationException("challenge verification failed");
		}
		return true;
	}

	private List<String> populateChallengeList() {
		List<String> ctxList = new ArrayList<String>();

		GSContext gsContext =
				new GSContext(extendedPublicKey);
		gsContext.addToChallengeContext(ctxList);

		ctxList.add(String.valueOf(Q));
		ctxList.add(String.valueOf(A));
		ctxList.add(String.valueOf(hatA));
		ctxList.add(String.valueOf(n_2));

		return ctxList;
	}

	@Override
	public boolean executeVerification(BigInteger cChallenge) {
		if (!checkLengths(P_2.getProofSignatureElements())) {
			gslog.log(Level.SEVERE, "Length checks on inputs failed");
			return false;
		}
		
		cChallenge = computeChallenge();
		
		try {
			hatA = verifier.executeVerification(cChallenge);
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, "ProofStore elements could not be retrieved.", e);
			return false;
		}
		
		try {
			return verifyChallenge();
		} catch (VerificationException e) {
			gslog.log(Level.SEVERE, "Verification failed.", e);
			return false;
		}
	}
}
