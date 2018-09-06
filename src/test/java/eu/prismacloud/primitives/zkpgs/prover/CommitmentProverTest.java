package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.*;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class CommitmentProverTest {
    private Logger log = GSLoggerConfiguration.getGSlog();

    private KeyGenParameters keyGenParameters;
    private GraphEncodingParameters graphEncodingParameters;
    private SignerKeyPair skp;
    private ExtendedKeyPair extendedKeyPair;
    private ExtendedPublicKey epk;
    private BigInteger testM;
    private ProofStore<Object> proofStore;

    private BaseCollection baseCollection;
    private CommitmentProver cprover;
    private BaseRepresentation baseR0;
    private BigInteger tilder_i;
    private Logger gslog = GSLoggerConfiguration.getGSlog();
    private BigInteger r_i;
    //  private GSUtils gsUtils;

    @BeforeAll
    void setUpKey() throws IOException, ClassNotFoundException, EncodingException {
        BaseTest baseTest = new BaseTest();
        baseTest.setup();
        baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
        skp = baseTest.getSignerKeyPair();
        graphEncodingParameters = baseTest.getGraphEncodingParameters();
        keyGenParameters = baseTest.getKeyGenParameters();
        extendedKeyPair = new ExtendedKeyPair(skp, graphEncodingParameters, keyGenParameters);
        extendedKeyPair.generateBases();
        extendedKeyPair.setupEncoding();
        extendedKeyPair.createExtendedKeyPair();

        epk = extendedKeyPair.getExtendedPublicKey();
    }

    @BeforeEach
    void setUp() throws Exception {
        proofStore = new ProofStore<Object>();
        testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
        //    log.info("Creating test signature with GSSigningOracle on testM: " + testM);
        //    sigmaM = oracle.sign(testM).blind();

        baseR0 = new BaseRepresentation(epk.getPublicKey().getBaseR_0(), 0, BASE.BASE0);
        baseR0.setExponent(testM);

        baseCollection = new BaseCollectionImpl();
        baseCollection.add(baseR0);
        
        GSCommitment C_i = GSCommitment.createCommitment(baseCollection, r_i, epk);

        cprover = new CommitmentProver(C_i, 0, extendedKeyPair.getPublicKey(), proofStore);
    }


    @Test
    @DisplayName("Test pre challenge phase for the commitment prover during issuing")
    void testPrechallengePhase() {


    }

    @Test
    @DisplayName("Test pre challenge phase for the commmimtment prover during proving")
    void testPreChallengePhaseProving() throws ProofStoreException {
        String tildem_iURN = URNType.buildURNComponent(URNType.TILDEMI, PossessionProver.class, 0);
        BigInteger tildem_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
        proofStore.store(tildem_iURN, tildem_i);
        String tildeC_iURN = URNType.buildURNComponent(URNType.TILDEU, CommitmentProver.class);
        GroupElement tildeC_i = cprover.executePreChallengePhase();

        assertNotNull(tildeC_i);
        String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, 0);
        gslog.info("tilder_iUrn: " + tilder_iURN);
        tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);
        assertNotNull(tilder_i);
    }

    @Test
    @DisplayName("Test witness randomness is in the correct range")
    void testCreateWitnessRandomness() throws ProofStoreException {
        String tildem_iURN = URNType.buildURNComponent(URNType.TILDEMI, PossessionProver.class, 0);
        BigInteger tildem_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
        proofStore.store(tildem_iURN, tildem_i);
        cprover.executePreChallengePhase();

        String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, 0);
        gslog.info("tilder_iUrn: " + tilder_iURN);
        tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);
        assertNotNull(tilder_i);

        int l_tilderi = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

        BigInteger maxTilderi = NumberConstants.TWO.getValue().pow(l_tilderi);
        BigInteger minTilderi = maxTilderi.negate();

        assertTrue(CryptoUtilsFacade.isInRange(tilder_i, minTilderi, maxTilderi));
    }

    @Test
    void testComputeWitness() throws ProofStoreException {

        String tildem_iURN = URNType.buildURNComponent(URNType.TILDEMI, PossessionProver.class, 0);
        BigInteger tildem_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());

        proofStore.store(tildem_iURN, tildem_i);

        String tildeC_iURN = URNType.buildURNComponent(URNType.TILDEU, CommitmentProver.class);
        GroupElement tildeC_i = cprover.executePreChallengePhase();

        assertNotNull(tildeC_i);
        String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, 0);
        gslog.info("tilder_iUrn: " + tilder_iURN);
        tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);
        assertNotNull(tilder_i);

        GroupElement baseS = epk.getPublicKey().getBaseS();
        GroupElement baseR = epk.getPublicKey().getBaseR();
        GroupElement comm = baseR.modPow(tildem_i).multiply(baseS.modPow(tilder_i));

        assertEquals(comm, tildeC_i);
    }


    @Test
    void computeResponses() {
    }

    @Test
    void testPostChallengePhase() throws ProofStoreException {
        GroupElement baseR = epk.getPublicKey().getBaseR();
        BigInteger m_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
        GSCommitment C_i = GSCommitment.createCommitment(m_i, baseR, epk);
        Map<URN, GSCommitment> commitmentMap = new HashMap<>();
        commitmentMap.put(URN.createZkpgsURN("prover.commitments.C_0"), C_i);

        proofStore.store("prover.commitments", commitmentMap);
        String tildem_iURN = URNType.buildURNComponent(URNType.TILDEMI, PossessionProver.class, 0);
        BigInteger tildem_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
        proofStore.store(tildem_iURN, tildem_i);
        GroupElement tildeC_i = cprover.executePreChallengePhase();

        assertNotNull(tildeC_i);
        String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, 0);
        gslog.info("tilder_iUrn: " + tilder_iURN);
        tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);
        assertNotNull(tilder_i);
        BigInteger cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
        Map<URN, BigInteger> responses = cprover.executePostChallengePhase(cChallenge);

        assertNotNull(responses);
        assertTrue(responses.size() > 0);
    }
}
