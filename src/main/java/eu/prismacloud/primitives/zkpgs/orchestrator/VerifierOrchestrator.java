package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.GSInternalError;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.ProofRequest;
import eu.prismacloud.primitives.zkpgs.message.ProofType;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.*;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.GSVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.PairWiseDifferenceVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.PossessionVerifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class VerifierOrchestrator implements IVerifierOrchestrator {

    private ProofSignature P_3;
    private final GSVerifier verifier;
    private final ExtendedPublicKey extendedPublicKey;
    private final ProofStore<Object> proofStore;
    private final KeyGenParameters keyGenParameters;
    private final GraphEncodingParameters graphEncodingParameters;
    private ProofStore<Object> verifierStore = new ProofStore<Object>();
    private Logger gslog = GSLoggerConfiguration.getGSlog();
    private GroupElement aPrime;
    private Map<URN, GSCommitment> C_i;
    private BigInteger cChallenge;
    private BigInteger hate;
    private BigInteger hatvPrime;
    private BigInteger hatm_0;
    private List<CommitmentVerifier> commitmentVerifierList;
    private BigInteger tildem_i;
    private BigInteger n_3;
    private List<String> contextList;
    private List<String> challengeList;
    private GroupElement hatZ;
    private BigInteger hatc;
    private BaseCollection baseCollection;
    private Vector<Integer> vertexQueries;
    private ProofRequest proofRequest;
    private List<PairWiseDifferenceVerifier> pwVerifierList;
    private GroupElement baseHatR_Bari_Barj;

    public VerifierOrchestrator(
            final ExtendedPublicKey extendedPublicKey) {

        this.extendedPublicKey = extendedPublicKey;
        this.proofStore = new ProofStore<Object>();
        this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
        this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
        this.verifier = new GSVerifier(extendedPublicKey);
    }

    public void createQuery(Vector<Integer> vertexQueries) {
        this.vertexQueries = vertexQueries;
        this.proofRequest = new ProofRequest(ProofType.GEOLOCATION_SEPARATION, vertexQueries);
    }

    @Override
    public void init() throws IOException {
        this.verifier.init();

        //send proof request for geolocation separation proof
        Map<URN, Object> messageElements = new HashMap<URN, Object>();
        /** TODO add urn for proof request to URNType */
        messageElements.put(URN.createUnsafeZkpgsURN("proof.request"), this.proofRequest);
        verifier.sendMessage(new GSMessage(messageElements));

        /** TODO receive OK message from verifier */
        GSMessage proofReplyMsg = verifier.receiveMessage();


        n_3 = verifier.computeNonce();

        messageElements = new HashMap<URN, Object>();
        messageElements.put(URN.createZkpgsURN("verifier.n_3"), n_3);
        verifier.sendMessage(new GSMessage(messageElements));
    }

    public void receiveProverMessage() throws VerificationException, IOException {
        GSMessage proverMessage = verifier.receiveMessage();
        Map<URN, Object> proverMessageElements = proverMessage.getMessageElements();

        P_3 = (ProofSignature) proverMessageElements.get(URN.createZkpgsURN("prover.P_3"));
        aPrime = (GroupElement) proverMessageElements.get(URN.createZkpgsURN("prover.APrime"));

        C_i = (Map<URN, GSCommitment>) proverMessageElements.get(URN.createZkpgsURN("prover.commitments.C_iMap"));
        Map<URN, Object> proofSignatureElements = P_3.getProofSignatureElements();

        baseCollection = constructBaseCollection(proofSignatureElements);

        if (!checkLengths()) {
            /** TODO create a custom exception for lengths or return null */
            throw new VerificationException("Proof signature elements do not have correct length");
        }

        try {
            storePublicValues();
            storeProofSignature(proofSignatureElements);
        } catch (ProofStoreException e) {
            gslog.log(Level.SEVERE, e.getMessage());
        }
    }

    @Override
    public boolean checkLengths() {
        int l_hate = keyGenParameters.getL_prime_e() + keyGenParameters.getProofOffset();
        int l_hatvPrime = keyGenParameters.getL_v() + keyGenParameters.getProofOffset();
        int l_m = keyGenParameters.getL_m() + keyGenParameters.getProofOffset() + 1;
        int l_hatr = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

        hate =
                (BigInteger)
                        P_3.getProofSignatureElements().get(URN.createZkpgsURN("proofsignature.P_3.responses.hate"));
        hatvPrime =
                (BigInteger)
                        P_3.getProofSignatureElements().get(URN.createZkpgsURN("proofsignature.P_3.responses.hatvPrime"));
        hatm_0 =
                (BigInteger)
                        P_3.getProofSignatureElements().get(URN.createZkpgsURN("proofsignature.P_3.responses.hatm_0"));
        /** TODO check lengths for vertices, edges, and pair-wise different vertex encodings */
        return CryptoUtilsFacade.isInPMRange(hate, l_hate)
                && CryptoUtilsFacade.isInPMRange(hatvPrime, l_hatvPrime)
                && CryptoUtilsFacade.isInPMRange(hatm_0, l_m);
    }

    private void storeProofSignature(Map<URN, Object> proofSignatureElements)
            throws ProofStoreException {

        cChallenge =
                (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.challenge.c"));
        proofStore.store("verifier.c", cChallenge);

        aPrime =
                (GroupElement) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.signature.APrime"));
        proofStore.store("verifier.APrime", aPrime);

        hate = (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.responses.hate"));
        proofStore.store("verifier.responses.hate", hate);

        hatvPrime =
                (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.responses.hatvPrime"));
        proofStore.store("verifier.responses.hatvPrime", hatvPrime);

        hatm_0 =
                (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.responses.hatm_0"));
        proofStore.store("verifier.responses.hatm_0", hatm_0);

        /** TODO store vertices from proof signature */
        int baseIndex;
        String hatm_iPath = "possessionprover.responses.vertex.hatm_i_";
        String hatr_iPath = "commitmentverifier.responses.vertex.hatr_i_";
        String hatm_iURN;
        BigInteger hatm_i;
        BigInteger hatr_i;
        String hatr_iURN;

        BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
        for (BaseRepresentation vertexBase : vertexIterator) {
            baseIndex = vertexBase.getBaseIndex();
            hatm_iURN = hatm_iPath + baseIndex;
            hatm_i =
                    (BigInteger)
                            proofSignatureElements.get(
                                    URN.createZkpgsURN("proofsignature.P_3.responses.hatm_i_" + baseIndex));

            proofStore.store(hatm_iURN, hatm_i);
            hatr_iURN = hatr_iPath + baseIndex;
            hatr_i =
                    (BigInteger)
                            proofSignatureElements.get(
                                    URN.createZkpgsURN("proofsignature.P_3.responses.hatr_i_" + baseIndex));
            proofStore.store(hatr_iURN, hatr_i);
        }

        String hatm_i_jPath = "possessionprover.responses.edge.hatm_i_j_";
        String hatr_i_jPath = "commitmentverifier.responses.edge.hatr_i_j_";
        BigInteger hatm_i_j;
        BigInteger hatr_i_j;
        BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
        for (BaseRepresentation vertexBase : edgeIterator) {
            baseIndex = vertexBase.getBaseIndex();
            String hatm_i_jURN = hatm_i_jPath + baseIndex;
            hatm_i_j =
                    (BigInteger)
                            proofSignatureElements.get(
                                    URN.createZkpgsURN("proofsignature.P_3.responses.hatm_i_j_" + baseIndex));

            proofStore.store(hatm_i_jURN, hatm_i_j);
            String hatr_i_jURN = hatr_i_jPath + baseIndex;
            hatr_i_j =
                    (BigInteger)
                            proofSignatureElements.get(
                                    URN.createZkpgsURN("proofsignature.P_3.responses.hatr_i_j_" + baseIndex));
            proofStore.store(hatr_i_jURN, hatr_i_j);
        }

        /** TODO store pair-wise different vertex encodings from the proof signature */
        /** TODO add iterator when more than one pairwise diference provers */
        /** TODO add safe URNs */
        int pwProverIndex = 0;
        BigInteger hata_Bari_Barj = (BigInteger) proofSignatureElements.get(URN.createUnsafeZkpgsURN("proofsignature.P_3.hata_Bari_Barj_" + pwProverIndex));
        proofStore.storeUnsafe("pairwisedifferenceverifier.responses.hata_BariBarj_" + pwProverIndex, hata_Bari_Barj);

        BigInteger hatb_Bari_Barj = (BigInteger) proofSignatureElements.get(URN.createUnsafeZkpgsURN("proofsignature.P_3.hatb_Bari_Barj_" + pwProverIndex));
        proofStore.storeUnsafe("pairwisedifferenceverifier.responses.hatb_BariBarj_" + pwProverIndex, hatb_Bari_Barj);

        BigInteger hatr_Bari_Barj = (BigInteger) proofSignatureElements.get(URN.createUnsafeZkpgsURN("proofsignature.P_3.hatr_Bari_Barj_" + pwProverIndex));
        proofStore.storeUnsafe("pairwisedifferenceverifier.responses.hatr_BariBarj_" + pwProverIndex, hatr_Bari_Barj);
        PairWiseCommitments pairWiseCommitments = (PairWiseCommitments) proofSignatureElements.get(URN.createUnsafeZkpgsURN("proofsignature.P_3.C_Bari_C_Barj_" +  pwProverIndex));
        proofStore.storeUnsafe("pairwiseprover.C_Bari_C_Barj_" + pwProverIndex, pairWiseCommitments);

    }

    public void preChallengePhase() throws VerificationException, ProofStoreException {

        PossessionVerifier possessionVerifier = new PossessionVerifier(baseCollection, extendedPublicKey, proofStore);

        try {

            Map<URN, GroupElement> responses = possessionVerifier.executeCompoundVerification(cChallenge);
            String hatZURN = URNType.buildURNComponent(URNType.HATZ, PossessionVerifier.class);
            hatZ = responses.get(URN.createZkpgsURN(hatZURN));

        } catch (ProofStoreException e) {
            gslog.log(Level.SEVERE, "Could not access the challenge in the ProofStore.", e);
        }
        gslog.info("hatZ : " + hatZ);

        computeCommitmentVerifiers();

        computePairWiseVerifiers();
    }

    private void computePairWiseVerifiers() {
        PairWiseDifferenceVerifier pairWiseDifferenceVerifier;
        pwVerifierList = new ArrayList<>();

        String witnessRandomnessURN;
        /** TODO add iterator for more than on pair of vertex indices */
        /** TODO use safe URNs */
        int pwProverIndex = 0;
//        BigInteger hata_Bari_Barj = (BigInteger) proofStore.retrieve("pairwiseprover.responses.hata_Bari_Barj_" + pwProverIndex);
//
//        BigInteger hatb_Bari_Barj = (BigInteger) proofStore.retrieve("pairwiseprover.responses.hatb_Bari_Barj_" + pwProverIndex);
//
//        BigInteger hatr_Bari_Barj = (BigInteger) proofStore.retrieve("pairwiseprover.responses.hatr_Bari_Barj_" + pwProverIndex);

        PairWiseCommitments pairWiseCommitments = (PairWiseCommitments) proofStore.retrieveUnsafe("pairwiseprover.C_Bari_C_Barj_" + pwProverIndex);

        pairWiseDifferenceVerifier = new PairWiseDifferenceVerifier(pairWiseCommitments.getC_i(), pairWiseCommitments.getC_j(), pwProverIndex, extendedPublicKey, proofStore);

         baseHatR_Bari_Barj = null;
        try {
            baseHatR_Bari_Barj = pairWiseDifferenceVerifier.executeVerification(cChallenge);
        } catch (ProofStoreException e) {
            gslog.log(Level.SEVERE, "Could not save in ProofStore", e.getMessage());
        }
        String hatR_i_jURN = "pairwisedifferenceverifier.witnesses.hatR_BariBarj";
        try {
            proofStore.store(hatR_i_jURN, baseHatR_Bari_Barj);
        } catch (Exception e) {
            gslog.log(Level.SEVERE, e.getMessage());
        }


    }

    @Override
    public BigInteger computeChallenge() {
        gslog.info("compute challenge ");
        challengeList = populateChallengeList();
        try {
            hatc = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
        } catch (NoSuchAlgorithmException e) {
            gslog.log(Level.SEVERE, "Could not find the hash algorithm.", e);
        }
        return hatc;
    }

    public void verifyChallenge() throws VerificationException {
        if (!cChallenge.equals(hatc)) {
            throw new VerificationException("challenge verification failed");
        }
    }

    private List<String> populateChallengeList() {
        challengeList = new ArrayList<>();

        GSContext gsContext = new GSContext(extendedPublicKey);
        contextList = gsContext.computeChallengeContext();
        challengeList.addAll(contextList);
        challengeList.add(String.valueOf(aPrime));
        challengeList.add(String.valueOf(extendedPublicKey.getPublicKey().getBaseZ().getValue()));

        for (GSCommitment gsCommitment : C_i.values()) {
            challengeList.add(String.valueOf(gsCommitment.getCommitmentValue()));
        }

		challengeList.add(String.valueOf(hatZ));

        GroupElement commitment;
        String hatC_iURN;
        BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
        gslog.info("baseCollection size: " + baseCollection.size());
        for (BaseRepresentation vertex : vertexIterator) {
            hatC_iURN = "commitmentverifier.commitments.hatC_i_" + vertex.getBaseIndex();
            commitment = (GroupElement) proofStore.retrieve(hatC_iURN);
//            gslog.info(hatC_iURN + " " + commitment);
			challengeList.add(String.valueOf(commitment));
        }

        /** TODO add pair-wise hatR_BariBarj iterator for challenge */
        //    for (GroupElement witness : pairWiseWitnesses.values()) {
        //      challengeList.add(String.valueOf(witness));
        //    }

        challengeList.add(String.valueOf(baseHatR_Bari_Barj));

        gslog.info("n3: " + n_3);
        challengeList.add(String.valueOf(n_3));

        return challengeList;
    }

    private void computeCommitmentVerifiers() throws VerificationException, ProofStoreException {
        CommitmentVerifier commitmentVerifier;
        commitmentVerifierList = new ArrayList<>();

        String witnessRandomnessURN;
        String hatC_iURN;
        String comC_iURN;
        BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
        for (BaseRepresentation vertex : vertexIterator) {
            witnessRandomnessURN = "possessionprover.responses.vertex.hatm_i_" + vertex.getBaseIndex();
            BigInteger hatm_i = (BigInteger) proofStore.retrieve(witnessRandomnessURN);

            comC_iURN = "prover.commitments.C_i_" + vertex.getBaseIndex();
            GSCommitment commitment = (GSCommitment) proofStore.retrieve(comC_iURN);

            BaseCollection expectedBases = new BaseCollectionImpl();
            BaseRepresentation base = new BaseRepresentation(extendedPublicKey.getPublicKey().getBaseR(), -1, BASE.BASER);
            base.setExponent(hatm_i);
            expectedBases.add(base);

            commitmentVerifier = new CommitmentVerifier(commitment.getCommitmentValue(), expectedBases, vertex.getBaseIndex(), extendedPublicKey, proofStore);

            GroupElement hatCommitment = commitmentVerifier.executeVerification(cChallenge);

            commitmentVerifierList.add(commitmentVerifier);
            hatC_iURN = "commitmentverifier.commitments.hatC_i_" + vertex.getBaseIndex();

            try {
                proofStore.store(hatC_iURN, hatCommitment);
            } catch (Exception e) {
                gslog.log(Level.SEVERE, e.getMessage());
            }
        }
    }

    public void storePublicValues() throws ProofStoreException {
        String ZURN = "verifier.baseZ";
        String APrimeURN = "verifier.signature.APrime";
        //    String C_iURN = "verifier.C_i";

        verifierStore.store(ZURN, extendedPublicKey.getPublicKey().getBaseZ());
        verifierStore.store(APrimeURN, P_3.get("proofsignature.P_3.signature.APrime"));
        /** TODO check storage of C_i */
        //    verifierStore.store(C_iURN, P_3.get("proofsignature.P_3.C_i"));

        for (Entry<URN, GSCommitment> commitmentEntry : C_i.entrySet()) {
            URN commitmentKey = commitmentEntry.getKey();
            GSCommitment commitment = commitmentEntry.getValue();
            proofStore.save(commitmentKey, commitment);
        }
    }

    @Override
    public void close() throws IOException {
        verifier.close();
    }

    @Override
    public boolean executeVerification(BigInteger cChallenge) {
        // TODO Auto-generated method stub
        return false;
    }

    private BaseCollection constructBaseCollection(Map<URN, Object> proofSignatureElements) {
        BaseCollection collection = new BaseCollectionImpl();

        String vertexPrefix = "proofsignature.P_3.responses.hatm_i_";
        String edgePrefix = "proofsignature.P_3.responses.hatm_i_j_";
        Iterator<Entry<URN, Object>> candidateEntries = proofSignatureElements.entrySet().iterator();
        while (candidateEntries.hasNext()) {
            Map.Entry<URN, java.lang.Object> entry =
                    (Map.Entry<URN, java.lang.Object>) candidateEntries.next();
            URN key = entry.getKey();

            // Retrieving Matching Vertex Bases
            if (key.matchesPrefix(vertexPrefix)) {
                int baseIndex = key.getIndex();
                if (baseIndex < 0) {
                    throw new GSInternalError("The hatm_i values were not indexed correctly: " + key.getSuffix() + " / base index: " + baseIndex);
                }

                BaseRepresentation vertexBase = extendedPublicKey.getVertexBase(baseIndex);
                BigInteger hatm_i = (BigInteger) entry.getValue();
                vertexBase.setExponent(hatm_i);
                collection.add(vertexBase);
            }
            // Retrieving Matching Edge Bases
            if (key.matchesPrefix(edgePrefix)) {
                int baseIndex = key.getIndex();
                if (baseIndex < 0) {
                    throw new GSInternalError("The hatm_i_j values were not indexed correctly.");
                }

                BaseRepresentation edgeBase = extendedPublicKey.getEdgeBase(baseIndex);
                BigInteger hatm_i_j = (BigInteger) entry.getValue();
                edgeBase.setExponent(hatm_i_j);
                collection.add(edgeBase);
            }
        }


        return collection;
    }
}
