package uk.ac.ncl.cascade.zkpgs.orchestrator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import uk.ac.ncl.cascade.zkpgs.context.GSContext;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.prover.SigningQCorrectnessProver;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;

public class SigningQProverOrchestrator implements IProverOrchestrator {

	private Logger gslog = GSLoggerConfiguration.getGSlog();

	private final GSSignature gsSignature;
	private final BigInteger nonce;
	private final ExtendedKeyPair ekp;
	private final ExtendedPublicKey epk;
	private final KeyGenParameters keyGenParameters;
	private final ProofStore<Object> proofStore;
	private final SigningQCorrectnessProver prover;

	private BigInteger cPrime;

	private List<String> challengeList;

	private BigInteger hatd;

	private GroupElement tildeA;

	public SigningQProverOrchestrator(final GSSignature gsSignature, final BigInteger nonce, 
			final ExtendedKeyPair ekp, final ProofStore<Object> ps) {
		Assert.notNull(gsSignature, "The signature was found to be null.");
		Assert.notNull(nonce, "The nonce was found to be null.");
		Assert.notNull(ekp, "The extended keypair was found to be null.");
		Assert.notNull(ps, "The ProofStore was found to be null.");



		this.gsSignature = gsSignature;
		this.nonce = nonce;
		this.ekp = ekp;
		this.epk = ekp.getExtendedPublicKey();
		this.keyGenParameters = ekp.getKeyGenParameters();
		this.proofStore = ps;
		this.prover = new SigningQCorrectnessProver(gsSignature, nonce, ekp.getBaseKeyPair(), ps);
	}

	@Override
	public void init() throws IOException {
		// The prover orchestrator does not need to init.
		// Intentional No-Operation.
	}

	@Override
	public void executePreChallengePhase() throws ProofStoreException {
		this.tildeA = prover.executePreChallengePhase();
	}

	@Override
	public void executePostChallengePhase(BigInteger cChallenge) throws ProofStoreException {
		Map<URN, BigInteger> responses;
		responses = prover.executePostChallengePhase(cChallenge);
		this.hatd = responses.get(URN.createZkpgsURN(URNType.buildURNComponent(URNType.HATD, SigningQCorrectnessProver.class)));
		proofStore.add(URN.createZkpgsURN(URNType.buildURNComponent(URNType.HATD, SigningQCorrectnessProver.class)), this.hatd);
	}

	@Override
	public BigInteger computeChallenge() throws ProofStoreException, NoSuchAlgorithmException {
		challengeList = populateChallengeList();
		cPrime = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
		return cPrime;
	}

	@Override
	public ProofSignature createProofSignature() {
		HashMap<URN, Object> p2ProofSignatureElements = new HashMap<URN, Object>();
		p2ProofSignatureElements.put(URN.createZkpgsURN("P_2.hatd"), hatd);
		p2ProofSignatureElements.put(URN.createZkpgsURN("P_2.cPrime"), cPrime);

		ProofSignature P_2 = new ProofSignature(p2ProofSignatureElements);

		return P_2;
	}


	private List<String> populateChallengeList() {
		Assert.notNull(gsSignature.getA(), "Pre-signature value A has been found to be null.");
		Assert.notNull(tildeA, "Pre-signature verifier witness hatA has been found to be null.");
		Assert.notNull(nonce, "Pre-signature nonce n_2 has been found to be null.");

		List<String> ctxList = new ArrayList<String>();

		GSContext gsContext = new GSContext(epk);
		gsContext.addToChallengeContext(ctxList);

		ctxList.add(String.valueOf(gsSignature.getA().modPow(gsSignature.getE())));
		ctxList.add(String.valueOf(gsSignature.getA()));
		ctxList.add(String.valueOf(tildeA));
		ctxList.add(String.valueOf(nonce));

		return ctxList;
	}

	@Override
	public void close() throws IOException {
		// Intentional No-Operation.
	}
}
