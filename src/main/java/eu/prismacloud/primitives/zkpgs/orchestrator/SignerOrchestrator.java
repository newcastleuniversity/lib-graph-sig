package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.DefaultValues;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.graph.*;
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
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.*;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier.STAGE;
import org.jgrapht.Graph;
import org.jgrapht.io.ImportException;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Signing orchestrator
 */
public class SignerOrchestrator implements IMessagePartner {

	private final ExtendedKeyPair extendedKeyPair;
	private final ProofStore<Object> proofStore;
	private final GroupElement baseS;
	private final BigInteger modN;
	private final GroupElement baseZ;
	private final BaseCollection baseCollection;
	private final KeyGenParameters keyGenParameters;
	private final GraphEncodingParameters graphEncodingParameters;
	private final GSSigner signer;
	private final SignerPublicKey signerPublicKey;
	private BigInteger n_1;
	private BigInteger n_2;
	private ProofSignature P_1;
	private GSCommitment U;
	private IMessageGateway messageGateway;
	private Map<URN, Object> messageElements;
	private GSRecipient recipient;
	private GSCommitment commitmentU;
	private BigInteger cChallenge;
	private BigInteger hatvPrime;
	private BigInteger hatm_0;
	private Map<URN, BigInteger> responses;
	private GroupElement hatU;
	private List<String> challengeList;
	private BigInteger hatc;
	private GSSignature gsSignature;
	private BigInteger e;
	private BigInteger vbar;
	private BigInteger vPrimePrime;
	private GroupElement Q;
	private GroupElement R_i;
	private GroupElement R_i_j;
	private BigInteger d;
	private GroupElement A;
	private BaseCollection encodedBasesCollection;
	private GSGraph<GSVertex, GSEdge> gsGraph;
	private BigInteger order;
	private BigInteger hatd;
	private BigInteger cPrime;
	private Map<URN, Object> p2ProofSignatureElements;
	private ProofSignature P_2;
	private Map<URN, Object> correctnessMessageElements;
	private Graph<GSVertex, GSEdge> graph;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private GroupElement R_0;
	private BigInteger pPrime;
	private BigInteger qPrime;
	private GroupElement basesProduct;
	private List<String> contextList;
	private final String graphFilename;

	public SignerOrchestrator(String graphFilename,
			ExtendedKeyPair extendedKeyPair) {
		this.graphFilename = graphFilename;
		this.extendedKeyPair = extendedKeyPair;
		this.keyGenParameters = this.extendedKeyPair.getKeyGenParameters();
		this.graphEncodingParameters = this.extendedKeyPair.getGraphEncodingParameters();
		this.proofStore = new ProofStore<Object>();
		this.baseS = extendedKeyPair.getPublicKey().getBaseS();
		this.baseZ = extendedKeyPair.getPublicKey().getBaseZ();
		this.modN = extendedKeyPair.getPublicKey().getModN();
		this.baseCollection = extendedKeyPair.getExtendedPublicKey().getBaseCollection();
		this.signer = new GSSigner(extendedKeyPair);
		this.signerPublicKey = extendedKeyPair.getExtendedPublicKey().getPublicKey();
	}
	
	public SignerOrchestrator(ExtendedKeyPair extendedKeyPair) {
		this(DefaultValues.SIGNER_GRAPH_FILE, extendedKeyPair);
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

	public void round2() throws ImportException, IOException, ProofStoreException, NoSuchAlgorithmException, VerificationException, EncodingException  {
		encodeSignerGraph();

		// Extracting incoming commitment and proof P_1.
		GSMessage msg = signer.receiveMessage();
		extractMessageElements(msg);

		verifyRecipientCommitment();
		

		// Preparing Signature computation
		computeRandomness();
		createPartialSignature(extendedKeyPair.getExtendedPublicKey());
		storeSignatureElements();

		// Initalizing proof of correctness of Q/A computation.
		HashMap<URN, Object> preSignatureElements = prepareProvingSigningQ();

		GSMessage preSignatureMsg = new GSMessage(preSignatureElements);

		signer.sendMessage(preSignatureMsg);
	}

	private HashMap<URN, Object> prepareProvingSigningQ() throws ProofStoreException {
		SigningQProverOrchestrator signingQOrchestrator = new SigningQProverOrchestrator(gsSignature, n_2, extendedKeyPair, proofStore);

		signingQOrchestrator.executePreChallengePhase();

		cPrime = signingQOrchestrator.computeChallenge();

		signingQOrchestrator.executePostChallengePhase(cPrime);
		this.hatd = responses.get(URN.createZkpgsURN(URNType.buildURNComponent(URNType.HATD, SigningQCorrectnessProver.class)));

		P_2 = signingQOrchestrator.createProofSignature();

		HashMap<URN, Object> preSignatureElements = new HashMap<URN, Object>();
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.A"), A);
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.e"), e);
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.vPrimePrime"), vPrimePrime);
		preSignatureElements.put(URN.createZkpgsURN("proofsignature.P_2"), P_2);
		preSignatureElements.put(
				URN.createZkpgsURN("proofsignature.encoding"), this.encodedBasesCollection);
		return preSignatureElements;
	}

	private void verifyRecipientCommitment() throws NoSuchAlgorithmException, IOException, VerificationException {
		CommitmentVerifier commitmentVerifier =
				new CommitmentVerifier(STAGE.ISSUING, extendedKeyPair.getExtendedPublicKey(), proofStore);

		hatU =
				commitmentVerifier.computeWitness(
						cChallenge,
						responses);

		hatc = computeChallenge();

		if (!verifyChallenge()) {
			gslog.info("throws verification exception");
			signer.close();
			throw new VerificationException("Challenge verification failed");
		}
	}

	private void encodeSignerGraph() throws ImportException, EncodingException {
		File file = GraphMLProvider.getGraphMLFile(graphFilename);

		gsGraph = GSGraph.createGraph(graphFilename);
		gsGraph.encodeGraph(extendedKeyPair.getEncoding());

		GraphRepresentation graphRepresentation = GraphRepresentation.encodeGraph(gsGraph, extendedKeyPair.getExtendedPublicKey());



        this.encodedBasesCollection = graphRepresentation.getEncodedBaseCollection();
    }

    /**
     * Compute challenge.
     */
    public BigInteger computeChallenge() throws NoSuchAlgorithmException {
        challengeList = populateChallengeList();
        return CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
    }

    private Boolean verifyChallenge() {
        return hatc.equals(cChallenge);
    }

    private void extractMessageElements(GSMessage msg) throws ProofStoreException {
        Map<URN, Object> messageElements = msg.getMessageElements();

        commitmentU = (GSCommitment) messageElements.get(URN.createZkpgsURN("recipient.U"));
        //    proofStore.store("recipient.U", commitmentU );

        P_1 = (ProofSignature) messageElements.get(URN.createZkpgsURN("recipient.P_1"));
        Map<URN, Object> proofSignatureElements = P_1.getProofSignatureElements();

        cChallenge =
                (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.c"));
        //    proofStore.store("proofsignature.P_1.c", cChallenge );

        hatvPrime =
                (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatvPrime"));
        //    proofStore.store("proofsignature.P_1.hatvPrime", hatvPrime);

        hatm_0 =
                (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatm_0"));
        //    proofStore.store("proofsignature.P_1.hatm_0", hatm_0);

        responses =
                (Map<URN, BigInteger>)
                        proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.responses"));
        //    proofStore.store("proofsignature.P_1.responses", responses);

        n_2 = (BigInteger) messageElements.get(URN.createZkpgsURN("recipient.n_2"));
        //    proofStore.store("recipient.n_2", n_2);

        storeMessageElements(P_1);
    }

    private void storeMessageElements(ProofSignature P_1) throws ProofStoreException {
        for (Map.Entry<URN, BigInteger> response : responses.entrySet()) {
            proofStore.save(response.getKey(), response.getValue());
        }

        proofStore.store("proofsignature.P_1.c", cChallenge);
        proofStore.store("proofsignature.P_1.hatvPrime", hatvPrime);
        proofStore.store("proofsignature.P_1.hatm_0", hatm_0);
        proofStore.store("recipient.P_1", P_1);
        proofStore.store("recipient.U", commitmentU);
        proofStore.store("recipient.n_2", n_2);
    }

    public void createPartialSignature(ExtendedPublicKey extendedPublicKey) {
        computeQ();
        computeA();

        gsSignature =
                new GSSignature(
                        extendedPublicKey, U, encodedBasesCollection, keyGenParameters, A, e, vPrimePrime);
        Boolean isValidSignature = gsSignature.verify(signerPublicKey, basesProduct);

        gslog.info("signer isValidSignature: " + isValidSignature);
    }

    public void computeRandomness() {
        e =
                CryptoUtilsFacade.computePrimeInRange(
                        keyGenParameters.getLowerBoundE(), keyGenParameters.getUpperBoundE());
        vbar = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);
        vPrimePrime = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);
    }

    private void storeSignatureElements() throws ProofStoreException {
        proofStore.store("issuing.signer.A", A);
        proofStore.store("issuing.signer.Q", Q);
        proofStore.store("issuing.signer.d", d);
        proofStore.store("issuing.signer.vPrimePrime", vPrimePrime);
        proofStore.store("issuing.signer.context", contextList);
    }

    public GroupElement computeQ() {

        basesProduct = signerPublicKey.getQRGroup().getOne();
        for (BaseRepresentation baseRepresentation : encodedBasesCollection.createIterator(BASE.ALL)) {
            basesProduct =
                    basesProduct.multiply(
                            baseRepresentation.getBase().modPow(baseRepresentation.getExponent()));
        }

        basesProduct = basesProduct.multiply(U.getCommitmentValue());
        GroupElement Sv = baseS.modPow(vPrimePrime);

        GroupElement result = Sv.multiply(basesProduct);

        Q = baseZ.multiply(result.modInverse());
        return Q;
    }

    public GroupElement computeA() {
        pPrime = extendedKeyPair.getExtendedPrivateKey().getPrivateKey().getPPrime();
        qPrime = extendedKeyPair.getExtendedPrivateKey().getPrivateKey().getQPrime();

        d = e.modInverse(pPrime.multiply(qPrime));

        A = Q.modPow(d);
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

        R_0 = extendedKeyPair.getExtendedPublicKey().getPublicKey().getBaseR_0();
        GroupElement R = extendedKeyPair.getExtendedPublicKey().getPublicKey().getBaseR();

        challengeList.add(String.valueOf(modN));
        challengeList.add(String.valueOf(baseS));
        challengeList.add(String.valueOf(baseZ));
        challengeList.add(String.valueOf(R_0));

        //	    for (BaseRepresentation baseRepresentation : basesIterator) {
        //	      challengeList.add(String.valueOf(baseRepresentation.getBase().getValue()));
        //	    }

        String uCommitmentURN = "recipient.U";
        U = (GSCommitment) proofStore.retrieve(uCommitmentURN);
        GroupElement commitmentU = U.getCommitmentValue();

        challengeList.add(String.valueOf(commitmentU));
        /** TODO fix hatU computation */
        challengeList.add(String.valueOf(hatU));
        challengeList.add(String.valueOf(n_1));

        return challengeList;
    }
}
