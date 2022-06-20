package uk.ac.ncl.cascade.zkpgs.orchestrator;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.context.GSContext;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.GroupSetupProver;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.BaseIterator;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GroupSetupProverOrchestrator implements IProverOrchestrator {
	
	public static final String URNID = "groupsetupproverorchestrator";
	

	private final ExtendedKeyPair extendedKeyPair;
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;
	private final GroupSetupProver gsProver;
	private final ExtendedPublicKey extendedPublicKey;
	private final BaseCollection baseCollection;
	private Logger gslog = GSLoggerConfiguration.getGSlog();

	public GroupSetupProverOrchestrator(
			final ExtendedKeyPair extendedKeyPair, final ProofStore<Object> proofStore) {
		Assert.notNull(extendedKeyPair, "Extended key pair must not be null");
		Assert.notNull(proofStore, "Proof store must not be null");

		this.extendedKeyPair = extendedKeyPair;
		this.extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
		this.proofStore = proofStore;
		this.keyGenParameters = extendedKeyPair.getExtendedPublicKey().getKeyGenParameters();
		this.gsProver = new GroupSetupProver(extendedKeyPair, proofStore);
		this.baseCollection = extendedKeyPair.getExtendedPublicKey().getBaseCollection();
	}

	public void init() throws IOException {

	}

	public void executePreChallengePhase() {

		try {
			gsProver.executeCompoundPreChallengePhase();
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}
	}

	public BigInteger computeChallenge() {
		gslog.info("compute challenge ");
		BigInteger cChallenge = null;
		try {
			List<String> challengeList = populateChallengeList();
			cChallenge = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
		} catch (NoSuchAlgorithmException e) {
			gslog.log(Level.SEVERE, "Fiat-Shamir challenge could not be computed.", e);
		}
		return cChallenge;
	}

	public List<String> populateChallengeList() {
		GSContext gsContext = new GSContext(extendedPublicKey);
		List<String> ctxList = gsContext.computeChallengeContext();

		GroupElement tildeZ =
				(GroupElement) proofStore.retrieve(gsProver.getProverURN(URNType.TILDEBASEZ));
		GroupElement basetildeR =
				(GroupElement) proofStore.retrieve(gsProver.getProverURN(URNType.TILDEBASER));
		GroupElement basetildeR_0 =
				(GroupElement) proofStore.retrieve(gsProver.getProverURN(URNType.TILDEBASER0));

		ctxList.add(String.valueOf(tildeZ));
		ctxList.add(String.valueOf(basetildeR));
		ctxList.add(String.valueOf(basetildeR_0));

		BigInteger tilder_i;
		BigInteger tilder_j;
		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);

		for (BaseRepresentation baseRepresentation : vertexIterator) {
			tilder_i =
					(BigInteger)
					proofStore.retrieve(
							gsProver.getProverURN(URNType.TILDEBASERI, baseRepresentation.getBaseIndex()));
			ctxList.add(String.valueOf(tilder_i));
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			tilder_j =
					(BigInteger)
					proofStore.retrieve(
							gsProver.getProverURN(URNType.TILDEBASERIJ, baseRepresentation.getBaseIndex()));
			ctxList.add(String.valueOf(tilder_j));
		}

		return ctxList;
	}

	public void executePostChallengePhase(BigInteger cChallenge) {
		try {
			gsProver.executePostChallengePhase(cChallenge);
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}
	}

	@Override
	public ProofSignature createProofSignature() {
		return gsProver.outputProofSignature();
	}

	@Override
	public void close() throws IOException {
		// Intentional No-Operation
	}
}
