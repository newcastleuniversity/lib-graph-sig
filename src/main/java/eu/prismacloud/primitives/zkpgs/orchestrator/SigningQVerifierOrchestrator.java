package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.SigningQCorrectnessVerifier;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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

	private final GroupElement A;

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
		
		Assert.notNull(P_2, "Pre-signature ProofSignature P_2 has been found to be null.");
		Assert.notNull(sigma, "Pre-signature sigma has been found to be null.");
		Assert.notNull(extendedPublicKey, "The extended public key has been found to be null.");
		Assert.notNull(proofStore, "The ProofStore has been found to be null.");
		Assert.notNull(nonce, "The nonce n_2 has been found to be null.");

		this.extendedPublicKey = extendedPublicKey;
		this.proofStore = proofStore;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
		
		this.P_2 = P_2;
		this.n_2 = nonce;
		
		this.sigma = sigma;
		this.A = sigma.getA();
		Assert.notNull(this.A, "Pre-signature value A has been found to be null.");
		
		
		this.verifier = new SigningQCorrectnessVerifier(P_2, sigma, extendedPublicKey.getPublicKey(), proofStore);
	}

	
	@Override
	public void init() {
		this.Q = (GroupElement) proofStore.retrieve("issuing.recipient.Q");
		Assert.notNull(Q, "Pre-signature value Q has been found to be null.");
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
		if (!this.cChallenge.equals(hatc)) {
			throw new VerificationException("challenge verification failed");
		}
		return true;
	}

	private List<String> populateChallengeList() {
		Assert.notNull(Q, "Pre-signature value Q has been found to be null.");
		Assert.notNull(A, "Pre-signature value A has been found to be null.");
		Assert.notNull(hatA, "Pre-signature verifier witness hatA has been found to be null.");
		Assert.notNull(n_2, "Pre-signature nonce n_2 has been found to be null.");
		
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
		
		this.cChallenge = cChallenge;
		
		if (!checkLengths(P_2.getProofSignatureElements())) {
			gslog.log(Level.SEVERE, "Length checks on inputs failed");
			return false;
		}
		
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