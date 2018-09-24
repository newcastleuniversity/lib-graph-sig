package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.DefaultValues;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.graph.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.message.IMessagePartner;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.prover.SigningQCorrectnessProver;
import eu.prismacloud.primitives.zkpgs.recipient.GSRecipient;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigner;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.*;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.IssuingCommitmentVerifier;

import org.jgrapht.Graph;
import org.jgrapht.io.ImportException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Logger;

/**
 * Signing orchestrator
 */
public class SignerOrchestrator implements IMessagePartner {

	private final ExtendedKeyPair extendedKeyPair;
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;
	private final GraphEncodingParameters graphEncodingParameters;
	private final GSSigner signer;
	private final SignerPublicKey signerPublicKey;
	private BigInteger n_1;
	private BigInteger n_2;
	private ProofSignature P_1;
	private IMessageGateway messageGateway;
	private Map<URN, Object> messageElements;
	private GSRecipient recipient;
	private BigInteger commitmentUproofChallenge;
	private BigInteger hatvPrime;
	private BigInteger hatm_0;
	private Map<URN, BigInteger> responses;
	private GroupElement hatU;
	private List<String> challengeList;
	private BigInteger hatc;

	private GSGraph<GSVertex, GSEdge> gsGraph;
	private BigInteger cPrime;
	private Map<URN, Object> p2ProofSignatureElements;
	private ProofSignature P_2;
	private Map<URN, Object> correctnessMessageElements;
	private Graph<GSVertex, GSEdge> graph;
	private Logger gslog = GSLoggerConfiguration.getGSlog();

	private List<String> contextList;
	private final String graphFilename;

	/**
	 * Class encapsulating the private state data used in establishing a signature.
	 * The class enforces consistency in that elements can only be set once and are final thereafter.
	 * The class is entitled to throw NullPointerExceptions if a signature element is queried that
	 * has not been appropriately initialized yet.
	 */
	private class SignatureData {
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
		 * @param messageQ Signature element Q.
		 * 
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

		//		void setVPrimePrime(BigInteger vPrimePrime) {
		//			if (this.vPrimePrime == null) {
		//				this.vPrimePrime = vPrimePrime; 
		//			} else {
		//				throw new IllegalStateException("The signature element vPrimePrime can only be set once and is final thereafter");
		//			}
		//		}

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

		//		void setE(BigInteger e) {
		//			if (this.e == null) {
		//				this.e = e;
		//			} else {
		//				throw new IllegalStateException("The signature element e can only be set once and is final thereafter");
		//			}
		//		}

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
			if(this.basesProduct == null) {
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
			if(this.graphRepresentation == null) {
				this.graphRepresentation = graphRepresentation;
			} else {
				throw new IllegalStateException("The graph representation can only be set once and is final thereafter");
			}
		}

	}

	public SignerOrchestrator(String graphFilename,
			ExtendedKeyPair extendedKeyPair, IMessageGateway messageGateway) {
		this.graphFilename = graphFilename;
		this.extendedKeyPair = extendedKeyPair;
		this.keyGenParameters = this.extendedKeyPair.getKeyGenParameters();
		this.graphEncodingParameters = this.extendedKeyPair.getGraphEncodingParameters();
		this.proofStore = new ProofStore<Object>();
		this.signer = new GSSigner(extendedKeyPair, messageGateway);
		this.signerPublicKey = extendedKeyPair.getExtendedPublicKey().getPublicKey();
	}

	public SignerOrchestrator(ExtendedKeyPair extendedKeyPair, IMessageGateway messageGateway) {
		this(DefaultValues.SIGNER_GRAPH_FILE, extendedKeyPair, messageGateway);
	}

	@Override
	public void init() throws IOException {
		signer.init();
	}

	public void round0() throws IOException {
		n_1 = signer.computeNonce();
		messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createZkpgsURN("nonces.n_1"), n_1);

		signer.sendMessage(new GSMessage(messageElements));
	}

	public void round2() throws ImportException, IOException, ProofStoreException, NoSuchAlgorithmException, VerificationException, EncodingException {
		GraphRepresentation sigmaGraph = encodeSignerGraph();

		// Extracting incoming commitment and proof P_1.
		GSMessage msg = signer.receiveMessage();

		// New signature data container
		SignatureData sigmaData = new SignatureData();

		GSCommitment commitmentU = extractMessageElements(msg, sigmaData);

		verifyRecipientCommitment(commitmentU.getCommitmentValue(), commitmentU.getBaseCollection());
		// Post-Condition: commitmentU verified, accepted to use subsequently.

		sigmaData.setComU(commitmentU);
		sigmaData.setEncodedBases(sigmaGraph.getEncodedBaseCollection());
		sigmaData.setGraphRepresentation(sigmaGraph);

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

	private HashMap<URN, Object> prepareProvingSigningQ(GSSignature preSigma) throws ProofStoreException, NoSuchAlgorithmException {
		SigningQProverOrchestrator signingQOrchestrator = new SigningQProverOrchestrator(preSigma, n_2, extendedKeyPair, proofStore);

		signingQOrchestrator.executePreChallengePhase();

		cPrime = signingQOrchestrator.computeChallenge();

		signingQOrchestrator.executePostChallengePhase(cPrime);

		P_2 = signingQOrchestrator.createProofSignature();

		HashMap<URN, Object> preSignatureElements = new HashMap<URN, Object>();
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.A"), preSigma.getA());
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.e"), preSigma.getE());
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.vPrimePrime"), preSigma.getV());
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.P_2"), P_2);
		preSignatureElements.put(
				URN.createZkpgsURN("proofsignature.encoding.baseMap"), preSigma.getEncodedBases());

		preSignatureElements.put(
				URN.createZkpgsURN("proofsignature.encoding.GR"), preSigma.getGraphRepresentation());

		return preSignatureElements;
	}

	private void verifyRecipientCommitment(GroupElement commitmentValue, BaseCollection commitmentBases ) throws NoSuchAlgorithmException, IOException, VerificationException, ProofStoreException {
		IssuingCommitmentVerifier commitmentVerifier =
				new IssuingCommitmentVerifier(commitmentValue, commitmentBases, extendedKeyPair.getExtendedPublicKey(), proofStore);

		hatU = commitmentVerifier.executeVerification(commitmentUproofChallenge);

		hatc = computeChallenge();

		if (!hatc.equals(commitmentUproofChallenge)) {
			gslog.info("throws verification exception");
			signer.close();
			throw new VerificationException("Challenge verification of the representation proof of Recipient commitment U failed.");
		}
	}

	private GraphRepresentation encodeSignerGraph() throws ImportException, EncodingException {

		gsGraph = GSGraph.createGraph(graphFilename);
		Assert.notNull(gsGraph, "Graph could not be created from graphml file.");
		gsGraph.encodeGraph(extendedKeyPair.getEncoding());

		return GraphRepresentation.encodeGraph(gsGraph, extendedKeyPair.getExtendedPublicKey());
	}

	/**
	 * Compute challenge by hashing a constructed challenge list.
	 *
	 * @return the computed challenge
	 * @throws NoSuchAlgorithmException if the requested hash algorithm is not found
	 */
	public BigInteger computeChallenge() throws NoSuchAlgorithmException {
		challengeList = populateChallengeList();
		return CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
	}

	private GSCommitment extractMessageElements(GSMessage msg, SignatureData signatureData) throws ProofStoreException {
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

	private void storeMessageElements(ProofSignature P_1, GSCommitment commitmentU) throws ProofStoreException {
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

	private GSSignature createPartialSignature(SignatureData sigmaData, ExtendedPublicKey extendedPublicKey) {
		computeQ(sigmaData);

		sigmaData.computeRandomPrimeE();

		computeA(sigmaData);

		GSSignature preSigma =
				new GSSignature(
						extendedPublicKey, sigmaData.getComU(), sigmaData.getEncodedBases(), sigmaData.getGraphRepresentation(),
						sigmaData.getA(), sigmaData.getE(), sigmaData.vPrimePrime);

		Boolean isValidSignature = preSigma.verify(signerPublicKey, sigmaData.getBasesProduct());

		return preSigma;
	}

	public BigInteger computeVPrimePrimeRandomness() {
		BigInteger vbar = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);
		return NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);
	}

	private void storeSecretSignatureElements(GSSignature preSigma, SignatureData sigmaData) throws ProofStoreException {
		proofStore.store("issuing.signer.A", preSigma.getA());
		proofStore.store("issuing.signer.Q", sigmaData.getQ());
		proofStore.store("issuing.signer.e", sigmaData.getE());
		proofStore.store("issuing.signer.d", sigmaData.getD());
		proofStore.store("issuing.signer.vPrimePrime", sigmaData.getVPrimePrime());
		// proofStore.store("issuing.signer.context", contextList);
	}

	/**
	 * Computes pre-signature value Q with a Recipient-provided commitment U.
	 * The commitment U is to contain the Recipient's master secret key (msk/m_0)
	 * encoded in base R_0. However, this msk is not privy to the signer.
	 * 
	 *
	 * @return Pre-signature GroupElement Q.
	 */
	GroupElement computeQ(SignatureData sigmaData) {

		GroupElement basesProduct = signerPublicKey.getGroup().getOne();

		for (BaseRepresentation base : sigmaData.getEncodedBases().createIterator(BASE.ALL)) {
			if (base.getBaseType().equals(BASE.BASES)) continue; // Treating randomness separately.

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

	private GroupElement computeA(SignatureData sigmaData) {
		BigInteger d = sigmaData.getE().modInverse(extendedKeyPair.getPrivateKey().getOrder());
		sigmaData.setD(d);

		GroupElement A = sigmaData.getQ().modPow(d);
		sigmaData.setA(A);

		return A;
	}

	@Override
	public void close() throws IOException {
		signer.close();
	}

	private List<String> populateChallengeList() {
		challengeList = new ArrayList<String>();
		GSContext gsContext =
				new GSContext(
						extendedKeyPair.getExtendedPublicKey());
		contextList = gsContext.computeChallengeContext();

		challengeList.addAll(contextList);

		String uCommitmentURN = "recipient.U";
		GSCommitment U = (GSCommitment) proofStore.retrieve(uCommitmentURN);
		GroupElement commitmentU = U.getCommitmentValue();

		challengeList.add(String.valueOf(commitmentU));
		challengeList.add(String.valueOf(hatU));
		challengeList.add(String.valueOf(n_1));

		return challengeList;
	}
}
