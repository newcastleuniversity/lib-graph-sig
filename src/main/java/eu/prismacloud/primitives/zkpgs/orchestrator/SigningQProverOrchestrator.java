package eu.prismacloud.primitives.zkpgs.orchestrator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.prover.SigningQCorrectnessProver;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

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

	private Map<URN, GroupElement> tildeA;

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

	}

	@Override
	public void executePreChallengePhase() {
		try {
			this.tildeA = prover.executeCompoundPreChallengePhase();
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, "ProofStore elements not found.", e);
		}
	}

	@Override
	public void executePostChallengePhase(BigInteger cChallenge) {
		Map<URN, BigInteger> responses;
		try {
			responses = prover.executePostChallengePhase(cChallenge);
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, "ProofStore could not be successfully accessed.", e);
			return;
		}
		this.hatd = responses.get(URN.createZkpgsURN(URNType.buildURNComponent(URNType.HATD, SigningQCorrectnessProver.class)));
	}

	@Override
	public BigInteger computeChallenge() throws ProofStoreException {
		challengeList = populateChallengeList();
		try {
			cPrime = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
		} catch (NoSuchAlgorithmException e) {
			gslog.log(Level.SEVERE, "Could not compute the challenge.", e);
		}
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
