package uk.ac.ncl.cascade.zkpgs.orchestrator;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.context.GSContext;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.BaseIterator;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.verifier.GroupSetupVerifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class GroupSetupVerifierOrchestrator implements IVerifierOrchestrator {
	
	public static final String URNID = "groupsetupverifierorchestrator";
	
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;
	private final GraphEncodingParameters graphEncodingParameters;
	private final ExtendedPublicKey extendedPublicKey;
	private final BaseCollection baseCollection;
	private final GroupSetupVerifier gsVerifier;
	private final ProofSignature proofSignature;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private BigInteger cChallenge;
	private BigInteger hatc;
	private Map<URN, GroupElement> hatValues;

	public GroupSetupVerifierOrchestrator(
			final ProofSignature proofSignature,
			final ExtendedPublicKey extendedPublicKey,
			final ProofStore<Object> proofStore) {
		Assert.notNull(proofSignature, "Proof signature must not be null");
		Assert.notNull(extendedPublicKey, "Extended public key must not be null");
		Assert.notNull(proofStore, "Proof store must not be null");
		this.proofSignature = proofSignature;
		this.extendedPublicKey = extendedPublicKey;
		this.proofStore = proofStore;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
		this.gsVerifier = new GroupSetupVerifier(proofSignature, extendedPublicKey, proofStore);
		this.baseCollection = extendedPublicKey.getBaseCollection();
	}

	@Override
	public void init() throws IOException {
		
	}

	@Override
	public boolean executeVerification(BigInteger cChallenge) {
		this.cChallenge = cChallenge;

		if (!checkLengths()) {
			gslog.log(Level.SEVERE, "Length checks on inputs failed");
			return false;
		}

		hatValues = gsVerifier.executeCompoundVerification(cChallenge);

		try {
			computeChallenge();
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, "Computing challenge failed.", e);
			return false;
		}

		try {
			return verifyChallenge();
		} catch (VerificationException e) {
			gslog.log(Level.SEVERE, "Verification failed.", e);
			return false;
		}
	}

	private boolean verifyChallenge() throws VerificationException {
		if (!this.cChallenge.equals(hatc)) {
			throw new VerificationException("challenge verification failed");
		}
		return true;
	}

	@Override
	public BigInteger computeChallenge() throws ProofStoreException {
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

	private List<String> populateChallengeList() {
		GSContext gsContext = new GSContext(extendedPublicKey);
		List<String> ctxList = gsContext.computeChallengeContext();

		String hatZURN = URNType.buildURNComponent(URNType.HATZ, GroupSetupVerifier.class);
		GroupElement hatZ = hatValues.get(URN.createZkpgsURN(hatZURN));

		String hatRURN = URNType.buildURNComponent(URNType.HATBASER, GroupSetupVerifier.class);
		GroupElement hatR = hatValues.get(URN.createZkpgsURN(hatRURN));

		String hatR_0URN = URNType.buildURNComponent(URNType.HATBASER0, GroupSetupVerifier.class);
		GroupElement hatR_0 = hatValues.get(URN.createZkpgsURN(hatR_0URN));

		ctxList.add(String.valueOf(hatZ));
		ctxList.add(String.valueOf(hatR));
		ctxList.add(String.valueOf(hatR_0));

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation baseRepresentation : vertexIterator) {
			String hatR_iURN =
					URNType.buildURNComponent(
							URNType.HATBASERI, GroupSetupVerifier.class, baseRepresentation.getBaseIndex());
			ctxList.add(String.valueOf(hatValues.get(URN.createZkpgsURN(hatR_iURN))));
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			String hatR_i_jURN =
					URNType.buildURNComponent(
							URNType.HATBASERIJ, GroupSetupVerifier.class, baseRepresentation.getBaseIndex());
			ctxList.add(String.valueOf(hatValues.get(URN.createZkpgsURN(hatR_i_jURN))));
		}

		return ctxList;
	}

	@Override
	public boolean checkLengths() {
		return gsVerifier.checkLengths();
	}

	@Override
	public void close() throws IOException {
		// Intentional No-Operation
	}
}
