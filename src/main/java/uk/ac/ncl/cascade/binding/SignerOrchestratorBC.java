package uk.ac.ncl.cascade.binding;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.context.GSContext;
import uk.ac.ncl.cascade.zkpgs.exception.ProofException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.zkpgs.graph.GraphRepresentation;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.GSMessage;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.IMessagePartner;
import uk.ac.ncl.cascade.zkpgs.orchestrator.SigningQProverOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigner;
import uk.ac.ncl.cascade.zkpgs.store.IURNGoverner;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.*;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.verifier.IssuingCommitmentVerifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;


/**
 * Issuing protocol between the S_{grs} and the Recipient (host with embedded TPM) for creating
 * a binding credential encoding as messages the split N_{G} and the generated prime e_{i}
 */
public class SignerOrchestratorBC implements IMessagePartner, IURNGoverner {
	public static final String URNID = "signervc";
	private final BigInteger pseudonym;
	private final BigInteger e_i;
	private final ExtendedKeyPair extendedKeyPair;
	private final ProofStore<Object> proofStore;
	private final SignerPublicKey signerPublicKey;
	private final GSSigner signer;
	private final KeyGenParameters keyGenParameters;
	private ProofSignature P_1;
	private BigInteger commitmentUproofChallenge;
	private BigInteger hatvPrime;
	private Map<URN, BigInteger> responses;
	private BigInteger hatm_0;
	private BigInteger n_2;
	private GroupElement hatU;
	private List<String> challengeList;
	private final Logger gslog = GSLoggerConfiguration.getGSlog();
	private BigInteger n_1;
	private final HashMap<URN, BaseRepresentation> basesMap = new LinkedHashMap<>();

	private class VCSignatureData {
		private BigInteger vPrimePrime;
		private GSCommitment comU;
		private BigInteger d;
		private BigInteger e;
		private GroupElement Q;
		private GroupElement A;
		private GroupElement basesProduct;
		private BaseCollection encodedBases;
		private GraphRepresentation graphRepresentation;

		GroupElement getQ() {
			Assert.notNull(this.Q, "The signature element Q has not been appropriately initialized, yet.");
			return Q;
		}

		/**
		 * Sets the signature element Q once and makes it final thereafter.
		 *
		 * @param messageQ Signature element Q.
		 * @throws IllegalStateException if the setter is called after Q was already established.
		 */
		void setQ(GroupElement messageQ) {
			if (Q == null) {
				Q = messageQ;
			} else {
				throw new IllegalStateException("The signature element Q can only be set once and is final thereafter");
			}
		}

		BigInteger getVPrimePrime() {
			Assert.notNull(this.vPrimePrime, "The signature element vPrimePrime has not been appropriately initialized, yet.");
			return vPrimePrime;
		}

		BigInteger computeVPrimePrimeRandomness() {
			if (this.vPrimePrime == null) {
				BigInteger vbar = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);
				this.vPrimePrime = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);
			} else {
				throw new IllegalStateException("The signature element vPrimePrime can only be set once and is final thereafter");
			}
			return this.vPrimePrime;
		}

		GSCommitment getComU() {
			// Is allowed to be null.
			return comU;
		}

		void setComU(GSCommitment comU) {
			if (this.comU == null) {
				this.comU = comU;
			} else {
				throw new IllegalStateException("The signature Recipient commitment U can only be set once and is final thereafter");
			}
		}

		BigInteger getD() {
			Assert.notNull(this.d, "The signature element d has not been appropriately initialized, yet.");
			return d;
		}

		void setD(BigInteger d) {
			if (this.d == null) {
				this.d = d;
			} else {
				throw new IllegalStateException("The signature element d can only be set once and is final thereafter");
			}
		}

		BigInteger getE() {
			Assert.notNull(this.e, "The signature element e has not been appropriately initialized, yet.");
			return e;
		}

		BigInteger computeRandomPrimeE() {
			if (this.e == null) {
				this.e = CryptoUtilsFacade.computePrimeInRange(
						keyGenParameters.getLowerBoundE(), keyGenParameters.getUpperBoundE());
			} else {
				throw new IllegalStateException("The signature element e can only be set once and is final thereafter");
			}
			return this.e;
		}

		BaseCollection getEncodedBases() {
			Assert.notNull(this.encodedBases, "The signature's encoded bases have not been appropriately initialized, yet.");
			return encodedBases;
		}

		void setEncodedBases(BaseCollection encodedBases) {
			if (this.encodedBases == null) {
				this.encodedBases = encodedBases;
			} else {
				throw new IllegalStateException("The signature's encoded bases can only be set once and is final thereafter");
			}
		}

		GroupElement getA() {
			Assert.notNull(this.A, "The signature element A has not been appropriately initialized, yet.");
			return A;
		}

		void setA(GroupElement elementA) {
			if (this.A == null) {
				A = elementA;
			} else {
				throw new IllegalStateException("The signature element A can only be set once and is final thereafter");
			}
		}

		GroupElement getBasesProduct() {
			Assert.notNull(this.basesProduct, "The preliminary bases product of the signature has not been appropriately initialized, yet.");
			return this.basesProduct;
		}

		void setBasesProduct(GroupElement basesProduct) {
			if (this.basesProduct == null) {
				this.basesProduct = basesProduct;
			} else {
				throw new IllegalStateException("The preliminary bases product can only be set once and is final thereafter");
			}
		}

		public GraphRepresentation getGraphRepresentation() {
			Assert.notNull(this.graphRepresentation, "The graph representation bases product of the signature has not been appropriately initialized, yet.");
			return graphRepresentation;
		}

		public void setGraphRepresentation(GraphRepresentation graphRepresentation) {
			if (this.graphRepresentation == null) {
				this.graphRepresentation = graphRepresentation;
			} else {
				throw new IllegalStateException("The graph representation can only be set once and is final thereafter");
			}
		}

	}


	public SignerOrchestratorBC(final BigInteger pseudonym, final BigInteger e_i, final ExtendedKeyPair extendedKeyPair, final IMessageGateway messageGateway) {
		this.pseudonym = pseudonym;
		this.e_i = e_i;
		this.extendedKeyPair = extendedKeyPair;
		this.proofStore = new ProofStore<Object>();
		this.signer = new GSSigner(extendedKeyPair, messageGateway);
		this.signerPublicKey = extendedKeyPair.getExtendedPublicKey().getPublicKey();
		this.keyGenParameters = this.extendedKeyPair.getKeyGenParameters();

	}

	@Override
	public void init() throws IOException {
		signer.init();
	}

	public void round0() throws IOException {
		n_1 = signer.computeNonce();
		HashMap<URN, Object> messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createZkpgsURN("nonces.n_1"), n_1);

		signer.sendMessage(new GSMessage(messageElements));
	}

	public void round2() throws IOException, ProofStoreException, VerificationException, NoSuchAlgorithmException {
		List<BigInteger> splitPseudonym = CryptoUtilsFacade.splitHexString(this.pseudonym.toString(16), 60);
		// encode split N_G pseudonym and e_{i}
		encodeHost(splitPseudonym, this.e_i);

		// Extracting incoming commitment and proof P_1.
		GSMessage msg = signer.receiveMessage();

		// New signature data container
		VCSignatureData sigmaData = new VCSignatureData();

		GSCommitment commitmentU = extractMessageElements(msg, sigmaData);

		verifyRecipientCommitment(commitmentU.getCommitmentValue(), commitmentU.getBaseCollection());
		// Post-Condition: commitmentU verified, accepted to use subsequently.

		sigmaData.setComU(commitmentU);
		BaseCollectionImpl baseCollection = new BaseCollectionImpl();
				baseCollection.addAll(basesMap.values());
		sigmaData.setEncodedBases(baseCollection);
//		sigmaData.setGraphRepresentation(new GraphRepresentation());

		// Preparing Signature computation
		sigmaData.computeVPrimePrimeRandomness();

		GSSignature preSigma = createPartialSignature(sigmaData, extendedKeyPair.getExtendedPublicKey());

		storeSecretSignatureElements(preSigma, sigmaData);

		// Initalizing proof of correctness of Q/A computation.
		HashMap<URN, Object> preSignatureElements = prepareProvingSigningQ(preSigma);

		GSMessage preSignatureMsg = new GSMessage(preSignatureElements);

		signer.sendMessage(preSignatureMsg);

		preSigma.getA(); // NOOP to catch debug state.
	}

	private void encodeHost(List<BigInteger> pseudonym, BigInteger e_i) {

		for (BigInteger element : pseudonym) {
			// Obtain a random base and exclude it from further selection
			encodeMessage(element);
		}
	}

	private void encodeMessage(BigInteger element) {
		Map<URN, BaseRepresentation> excludedBases = new HashMap<URN, BaseRepresentation>();
		BaseRepresentation base = this.extendedKeyPair.getExtendedPublicKey().getRandomVertexBase(excludedBases); // clone
		Assert.notNull(base, "Cannot obtain an appropriate random base.");
		excludedBases.put(URNType.buildURN(URNType.RV, ExtendedKeyPair.class, base.getBaseIndex()), base);

//		// Post-condition: getRandomVertexBase returns a clone that can be modified.
//		Map<BigInteger, Integer> encodedBasesByVertices = new HashMap<BigInteger, Integer>();
//		// Storing the base index of the vertex.
//		encodedBasesByVertices.put(element, base.getBaseIndex());


		base.setExponent(element);

		basesMap.put(URNType.buildURN(URNType.BASERI, this.getClass(), base.getBaseIndex()), base);
	}


	private HashMap<URN, Object> prepareProvingSigningQ(GSSignature preSigma) throws
			ProofStoreException, NoSuchAlgorithmException {
		SigningQProverOrchestrator signingQOrchestrator = new SigningQProverOrchestrator(preSigma, n_2, extendedKeyPair, proofStore);

		signingQOrchestrator.executePreChallengePhase();
		BigInteger cPrime = signingQOrchestrator.computeChallenge();
		signingQOrchestrator.executePostChallengePhase(cPrime);
		ProofSignature p_2 = signingQOrchestrator.createProofSignature();
		HashMap<URN, Object> preSignatureElements = new HashMap<URN, Object>();
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.A"), preSigma.getA());
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.e"), preSigma.getE());
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.vPrimePrime"), preSigma.getV());
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.P_2"), p_2);
		preSignatureElements.put(
				URN.createZkpgsURN("proofsignature.encoding.baseMap"), preSigma.getEncodedBases());

//		preSignatureElements.put(
//				URN.createZkpgsURN("proofsignature.encoding.GR"), preSigma.getGraphRepresentation());

		return preSignatureElements;

	}

	private void storeSecretSignatureElements(GSSignature preSigma, VCSignatureData sigmaData) throws ProofStoreException {

		proofStore.store("issuing.signer.A", preSigma.getA());
		proofStore.store("issuing.signer.Q", sigmaData.getQ());
		proofStore.store("issuing.signer.e", sigmaData.getE());
		proofStore.store("issuing.signer.d", sigmaData.getD());
		proofStore.store("issuing.signer.vPrimePrime", sigmaData.getVPrimePrime());
		// proofStore.store("issuing.signer.context", contextList);
	}

	private void verifyRecipientCommitment(GroupElement commitmentValue, BaseCollection commitmentBases) throws VerificationException, ProofStoreException, IOException, NoSuchAlgorithmException {
		IssuingCommitmentVerifier commitmentVerifier =
				new IssuingCommitmentVerifier(commitmentValue, commitmentBases, extendedKeyPair.getExtendedPublicKey(), proofStore);

		hatU = commitmentVerifier.executeVerification(commitmentUproofChallenge);
		BigInteger hatc = computeChallenge();

		if (!hatc.equals(commitmentUproofChallenge)) {
			gslog.info("throws verification exception");
			signer.close();
			throw new VerificationException("Challenge verification of the representation proof of Recipient commitment U failed.");
		}
	}

	public BigInteger computeChallenge() throws NoSuchAlgorithmException {
		challengeList = populateChallengeList();
		return CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
	}

	private List<String> populateChallengeList() {
		challengeList = new ArrayList<String>();
		GSContext gsContext =
				new GSContext(
						extendedKeyPair.getExtendedPublicKey());
		List<String> contextList = gsContext.computeChallengeContext();
		challengeList.addAll(contextList);

		String uCommitmentURN = "recipient.U";
		GSCommitment U = (GSCommitment) proofStore.retrieve(uCommitmentURN);
		GroupElement commitmentU = U.getCommitmentValue();

		challengeList.add(String.valueOf(commitmentU));
		challengeList.add(String.valueOf(hatU));
		challengeList.add(String.valueOf(n_1));

		return challengeList;
	}

	private GroupElement computeA(VCSignatureData sigmaData) {
		BigInteger d = sigmaData.getE().modInverse(extendedKeyPair.getPrivateKey().getOrder());
		sigmaData.setD(d);

		GroupElement A = sigmaData.getQ().modPow(d);
		sigmaData.setA(A);

		return A;
	}

	GroupElement computeQ(VCSignatureData sigmaData) {

		GroupElement basesProduct = signerPublicKey.getGroup().getOne();

		for (BaseRepresentation base : sigmaData.getEncodedBases().createIterator(BaseRepresentation.BASE.ALL)) {
			if (base.getBaseType().equals(BaseRepresentation.BASE.BASES))
				continue; // Treating randomness separately.

			basesProduct =
					basesProduct.multiply(
							base.getBase().modPow(base.getExponent()));
		}

		if (sigmaData.getComU() != null) {
			basesProduct = basesProduct.multiply(sigmaData.getComU().getCommitmentValue());
		}

		sigmaData.setBasesProduct(basesProduct);

		GroupElement Sv = signerPublicKey.getBaseS().modPow(sigmaData.getVPrimePrime());

		GroupElement result = Sv.multiply(basesProduct);

		GroupElement Q = signerPublicKey.getBaseZ().multiply(result.modInverse());
		sigmaData.setQ(Q);

		return Q;
	}

	private GSSignature createPartialSignature(VCSignatureData sigmaData, ExtendedPublicKey extendedPublicKey) {
		computeQ(sigmaData);

		sigmaData.computeRandomPrimeE();

		computeA(sigmaData);

		GSSignature preSigma =
				new GSSignature(
						extendedPublicKey, sigmaData.getComU(), sigmaData.getEncodedBases(), null,
						sigmaData.getA(), sigmaData.getE(), sigmaData.vPrimePrime);

		Boolean isValidSignature = preSigma.verify(signerPublicKey, sigmaData.getBasesProduct());

		if (!isValidSignature)
			throw new ProofException("the pre-signature is not valid");

		return preSigma;
	}

	protected GSCommitment extractMessageElements(GSMessage msg, VCSignatureData signatureData) throws
			ProofStoreException {
		Map<URN, Object> messageElements = msg.getMessageElements();

		GSCommitment commitmentU = (GSCommitment) messageElements.get(URN.createZkpgsURN("recipient.U"));
		//    proofStore.store("recipient.U", commitmentU );

		P_1 = (ProofSignature) messageElements.get(URN.createZkpgsURN("recipient.P_1"));
		Map<URN, Object> proofSignatureElements = P_1.getProofSignatureElements();

		commitmentUproofChallenge =
				(BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.challenge.c"));
		//    proofStore.store("proofsignature.P_1.challenge.c", cChallenge );

		hatvPrime =
				(BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.responses.hatvPrime"));
		// proofStore.store("issuing.commitmentverifier.responses.hatvPrime", hatvPrime);

		hatm_0 =
				(BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.responses.hatm_0"));
		//    proofStore.store("proofsignature.P_1.responses.hatm_0", hatm_0);

		responses =
				(Map<URN, BigInteger>)
						proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.responses.hatMap"));
		//    proofStore.store("proofsignature.P_1.responses.hatMap", responses);

		n_2 = (BigInteger) messageElements.get(URN.createZkpgsURN("recipient.n_2"));
		//    proofStore.store("recipient.n_2", n_2);

		storeMessageElements(P_1, commitmentU);

		return commitmentU;
	}

	private void storeMessageElements(ProofSignature p_1, GSCommitment commitmentU) throws ProofStoreException {
		for (Map.Entry<URN, BigInteger> response : responses.entrySet()) {
			proofStore.save(response.getKey(), response.getValue());
		}

		// TODO synchronize data
		proofStore.store("issuing.commitmentverifier.responses.hatvPrime", hatvPrime);
		proofStore.store("issuing.commitmentverifier.responses.hatm_0", hatm_0);

		proofStore.store("proofsignature.P_1.challenge.c", commitmentUproofChallenge);
		proofStore.store("proofsignature.P_1.responses.hatvPrime", hatvPrime);
		proofStore.store("proofsignature.P_1.responses.hatm_0", hatm_0);
		proofStore.store("recipient.P_1", P_1);
		proofStore.store("recipient.U", commitmentU);
		proofStore.store("recipient.n_2", n_2);

		// proofStore.store("issuing.commitmentverifier.responses.hatvprime", hatvPrime);

		//		// Storing all responses.
		//		Iterator<Entry<URN, BigInteger>> responseIterator = responses.entrySet().iterator();
		//		while (responseIterator.hasNext()) {
		//			Map.Entry<URN, BigInteger> entry = (Map.Entry<URN, BigInteger>) responseIterator
		//					.next();
		//			proofStore.add(entry.getKey(), entry.getValue());
		//		}
	}


	@Override
	public void close() throws IOException {
		signer.close();
	}
}
