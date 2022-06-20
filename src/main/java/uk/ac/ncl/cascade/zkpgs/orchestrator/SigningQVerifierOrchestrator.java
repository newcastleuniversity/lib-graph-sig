package uk.ac.ncl.cascade.zkpgs.orchestrator;

import uk.ac.ncl.cascade.zkpgs.context.GSContext;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.verifier.SigningQCorrectnessVerifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class SigningQVerifierOrchestrator implements IVerifierOrchestrator {

	private Logger gslog = GSLoggerConfiguration.getGSlog();

	private final ProofSignature P_2;

	private final ExtendedPublicKey extendedPublicKey;
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;

	private BigInteger hatc;
	private BigInteger cPrime;

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

		this.P_2 = P_2;
		this.n_2 = nonce;

		this.sigma = sigma;
		this.A = this.sigma.getA();
		Assert.notNull(this.A, "Pre-signature value A has been found to be null.");

		this.verifier =
				new SigningQCorrectnessVerifier(P_2, sigma, extendedPublicKey.getPublicKey(), proofStore);
	}

	@Override
	public void init() throws IOException {
		try {
			this.Q = (GroupElement) proofStore.retrieve("issuing.recipient.Q");
			Assert.notNull(Q, "Pre-signature value Q has been found to be null.");
		} catch (IllegalStateException e) {
			throw new IOException("Presignature value Q was not successfully communicated and stored in the ProofStore.");
		} catch(NullPointerException e) {
			throw new IOException(e.getMessage());
		}
	}

	@Override
	public boolean checkLengths() {
		return verifier.checkLengths();
	}

	@Override
	public BigInteger computeChallenge() throws NoSuchAlgorithmException {
		List<String> ctxList = populateChallengeList();

		hatc = CryptoUtilsFacade.computeHash(ctxList, keyGenParameters.getL_H());

		return hatc;
	}

	private List<String> populateChallengeList() {
		Assert.notNull(Q, "Pre-signature value Q has been found to be null.");
		Assert.notNull(A, "Pre-signature value A has been found to be null.");
		Assert.notNull(hatA, "Pre-signature verifier witness hatA has been found to be null.");
		Assert.notNull(n_2, "Pre-signature nonce n_2 has been found to be null.");

		List<String> ctxList = new ArrayList<String>();

		GSContext gsContext = new GSContext(extendedPublicKey);
		gsContext.addToChallengeContext(ctxList);

		ctxList.add(String.valueOf(Q));
		ctxList.add(String.valueOf(A));
		ctxList.add(String.valueOf(hatA));
		ctxList.add(String.valueOf(n_2));

		return ctxList;
	}

	@Override
	public boolean executeVerification(BigInteger cPrime) throws NoSuchAlgorithmException, ProofStoreException {
		this.cPrime = cPrime;

		if (!checkLengths()) {
			gslog.log(Level.SEVERE, "Length checks on inputs failed");
			return false;
		}

		hatA = verifier.executeVerification(cPrime);

		return this.cPrime.equals(computeChallenge());
	}

	@Override
	public void close() throws IOException {
		// Intentional No-Operation
	}
}
