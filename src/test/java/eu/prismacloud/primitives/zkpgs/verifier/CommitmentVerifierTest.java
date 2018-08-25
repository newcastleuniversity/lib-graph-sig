package eu.prismacloud.primitives.zkpgs.verifier;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.CommitmentProver;
import eu.prismacloud.primitives.zkpgs.prover.PossessionProver;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
public class CommitmentVerifierTest {

  private SignerKeyPair skp;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private ExtendedKeyPair extendedKeyPair;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private ExtendedPublicKey epk;
  private ProofStore<Object> proofStore;
  private BigInteger testM;
  private BaseRepresentation baseR0;
  private BaseCollectionImpl baseCollection;
  private CommitmentVerifier cverifier;
  private CommitmentProver cprover;
  private BigInteger tilder_i;
  private BigInteger hatr_i;
  private BigInteger cChallenge;
  private BigInteger hatm_i;
  private GroupElement tildeC_i;

  @BeforeAll
  void setUpKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    skp = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(skp, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();

    epk = extendedKeyPair.getExtendedPublicKey();
  }

  @BeforeEach
  void setUp() throws Exception {
    proofStore = new ProofStore<Object>();
    testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());

    baseR0 = new BaseRepresentation(epk.getPublicKey().getBaseR_0(), 0, BASE.BASE0);
    baseR0.setExponent(testM);

    baseCollection = new BaseCollectionImpl();
    baseCollection.add(baseR0);

    GroupElement R0 = epk.getPublicKey().getBaseR_0();
    BigInteger m_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
    GSCommitment C_i = GSCommitment.createCommitment(m_i, R0, epk);

    cprover = new CommitmentProver(C_i, 0, extendedKeyPair.getPublicKey(), proofStore);

    String tildem_iURN = URNType.buildURNComponent(URNType.TILDEMI, PossessionProver.class, 0);
    BigInteger tildem_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
    proofStore.store(tildem_iURN, tildem_i);

    tildeC_i =
        cprover.executePreChallengePhase();

    String tilder_iURN = URNType.buildURNComponent(URNType.TILDERI, CommitmentProver.class, 0);
    gslog.info("tilder_iUrn: " + tilder_iURN);
    tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);
    GroupElement baseR = epk.getPublicKey().getBaseR();
    
    m_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
    C_i = GSCommitment.createCommitment(m_i, baseR, epk);
    Map<URN, GSCommitment> commitmentMap = new HashMap<>();
    commitmentMap.put(URN.createZkpgsURN("prover.commitments.C_0"), C_i);

    proofStore.store("prover.commitments", commitmentMap);
    proofStore.store("prover.commitments.C_0", C_i);

    cChallenge = cprover.computeChallenge();

    String hatm_iURN = URNType.buildURNComponent(URNType.HATMI, PossessionProver.class, 0);
    hatm_i = tildem_i.add(cChallenge.multiply(testM));
    proofStore.store(hatm_iURN, tildem_i);

    Map<URN, BigInteger> responses = cprover.executePostChallengePhase(cChallenge);
    String hatr_iURN = URNType.buildURNComponent(URNType.HATRI, CommitmentProver.class, 0);
    gslog.info("hariUrn: " + hatr_iURN);

    hatr_i = responses.get(URN.createZkpgsURN(hatr_iURN));
    gslog.info("hatr_i: " + hatr_i);
    cverifier = new CommitmentVerifier();
  }

  @Test
  @DisplayName("Test witness computation for the commitment verifier")
  void computeWitness() {
    gslog.info("compute witness");
    GroupElement hatC_i =
        cverifier.computeWitness(
            cChallenge,
            baseR0,
            proofStore,
            extendedKeyPair.getExtendedPublicKey(),
            keyGenParameters);

    assertNotNull(hatC_i);
    assertEquals(tildeC_i, hatC_i);
  }

  @Test
  void testCheckLengths() {
    gslog.info("compute witness");
    GroupElement hatC_i =
        cverifier.computeWitness(
            cChallenge,
            baseR0,
            proofStore,
            extendedKeyPair.getExtendedPublicKey(),
            keyGenParameters);

    boolean isCorrectLength = cverifier.checkLengthsVerifying();

    assertTrue(isCorrectLength);
  }

  @Test
  void testComputeHatC() {
	  fail("Test not implemented yet.");
  }

  @Test
  void testComputeUHat() {
	  fail("Test not implemented yet.");
  }
}
