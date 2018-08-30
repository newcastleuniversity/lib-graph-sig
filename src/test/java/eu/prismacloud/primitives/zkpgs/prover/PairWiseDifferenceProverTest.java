package eu.prismacloud.primitives.zkpgs.prover;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
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
class PairWiseDifferenceProverTest {

  private Logger log = GSLoggerConfiguration.getGSlog();

  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private SignerKeyPair skp;
  private ExtendedKeyPair extendedKeyPair;
  private ExtendedPublicKey epk;
  private PairWiseDifferenceProver prover;
  private ProofStore<Object> proofStore;

  private GSCommitment c1, c2coprime;
  private BigInteger m1, m2coprime;
  private BigInteger a_BariBarj, b_BariBarj, r_BariBarj;
  private BigInteger tildea_BariBarj, tildeb_BariBarj, tilder_BariBarj;
  private BigInteger hata_BariBarj, hatb_BariBarj, hatr_BariBarj;

  private GroupElement tildeR;

  private int testIndex;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException, EncodingException {
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
    int minLength = Math.floorDiv(keyGenParameters.getL_m(), 2);
    m1 = CryptoUtilsFacade.computeRandomNumber(minLength);
    c1 = GSCommitment.createCommitment(m1, epk.getPublicKey().getBaseR(), epk);

    // Exponent m2coprime is guaranteed to be coprime with m1: prime number larger than m1.
    m2coprime = CryptoUtilsFacade.computePrimeWithLength(minLength + 1, keyGenParameters.getL_m());
    c2coprime = GSCommitment.createCommitment(m2coprime, epk.getPublicKey().getBaseR(), epk);

    testIndex = 0;
    prover = new PairWiseDifferenceProver(c1, c2coprime, testIndex, epk, proofStore);
    prover.executePrecomputation();
  }

  /**
   * Tests whether the precomputation establishes the coefficients of Bezout's Identity correctly.
   */
  @Test
  void testEEAPrecomputation() {
    a_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.ABARIBARJ, testIndex));

    b_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.BBARIBARJ, testIndex));

    BigInteger d = (a_BariBarj.multiply(m1)).add(b_BariBarj.multiply(m2coprime));
    assertEquals(
        BigInteger.ONE,
        d,
        "EEA did not compute the coefficients of " + "Bezout's Identity correctly, expected d=1.");
  }

  /** Tests the correctness of the differential randomness. */
  @Test
  void testDifferentialRandomness() {
    a_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.ABARIBARJ, testIndex));

    b_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.BBARIBARJ, testIndex));

    r_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.RBARIBARJ, testIndex));

    BigInteger rDiff =
        a_BariBarj.multiply(c1.getRandomness()).add(b_BariBarj.multiply(c2coprime.getRandomness()));
    assertEquals(
        rDiff.negate(),
        r_BariBarj,
        "EEA did not compute the coefficients of " + "Bezout's Identity correctly, expected d=1.");
  }

  /**
   * The test case is responsible for checking the computation of the witness randomness
   * (tilde-values). It retrieves these values from the ProofStore. The computation of the overall
   * witness tildeR is done in testComputeWiteness(). The correct range of the witness randomness is
   * checked by testCreateWitnessRandomness().
   *
   * @throws ProofStoreException
   */
  @Test
  void testPreChallengePhase() throws ProofStoreException {
    prover.executeCompoundPreChallengePhase();
    tildea_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEABARIBARJ, testIndex));
    assertNotNull(tildea_BariBarj);
    tildeb_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEBBARIBARJ, testIndex));
    assertNotNull(tildeb_BariBarj);
    tilder_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDERBARIBARJ, testIndex));
    assertNotNull(tilder_BariBarj);
  }

  /**
   * The test checks the correct range of the witness randomness.
   *
   * @throws ProofStoreException
   */
  @Test
  @DisplayName("Test witness randomness is in correct range")
  void testCreateWitnessRandomness() throws ProofStoreException {
    int bitLengthR = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

    BigInteger maxR = CryptoUtilsFacade.getUpperPMBound(bitLengthR);
    BigInteger minR = CryptoUtilsFacade.getLowerPMBound(bitLengthR);
    log.info(
        "tildeR:"
            + "\n  maximum positive random number for witnesses: "
            + maxR
            + "\n  minimum negative random number for witnesses: "
            + minR
            + "\n  bitLength: "
            + bitLengthR);

    prover.executeCompoundPreChallengePhase();
    tildea_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEABARIBARJ, testIndex));
    assertNotNull(tildea_BariBarj);
    assertTrue(inRange(tildea_BariBarj, minR, maxR));

    tildeb_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEBBARIBARJ, testIndex));
    assertNotNull(tildeb_BariBarj);
    assertTrue(inRange(tildeb_BariBarj, minR, maxR));

    tilder_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDERBARIBARJ, testIndex));
    assertNotNull(tilder_BariBarj);
    assertTrue(inRange(tilder_BariBarj, minR, maxR));
  }

  boolean inRange(BigInteger number, BigInteger min, BigInteger max) {
    return (number.compareTo(min) >= 0) && (number.compareTo(max) <= 0);
  }

  /**
   * The test checks whether witness TildeR is computed correctly. It has a dependency on the
   * ProofStore, retrieving the tilde values from it.
   *
   * @throws ProofStoreException
   */
  @Test
  @DisplayName("Test computing witness TildeR")
  void testComputeWitness() throws ProofStoreException {
    log.info("PairWiseDifferenceProverTest: Computing witness TildeR.");
    String basetildeR_BariBarjURN = "pairwiseprover.basetildeR_BariBarj_" + testIndex;
    Map<URN, GroupElement> witnesses = prover.executeCompoundPreChallengePhase();
    tildeR = witnesses.get(URN.createZkpgsURN(basetildeR_BariBarjURN));

    assertNotNull(tildeR);

    tildea_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEABARIBARJ, testIndex));
    GroupElement C_iTildea_BariBarj = c1.getCommitmentValue().modPow(tildea_BariBarj);
    log.info("tildea: " + tildea_BariBarj);

    tildeb_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEBBARIBARJ, testIndex));
    GroupElement C_jTildeb_BariBarj = c2coprime.getCommitmentValue().modPow(tildeb_BariBarj);
    log.info("tildeb: " + tildeb_BariBarj);

    tilder_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDERBARIBARJ, testIndex));
    GroupElement blindingAdjustment = epk.getPublicKey().getBaseS().modPow(tilder_BariBarj);
    log.info("tilder: " + tilder_BariBarj);

    GroupElement hatR =
        C_iTildea_BariBarj.multiply(C_jTildeb_BariBarj).multiply(blindingAdjustment);

    log.info("PairWiseDifferenceProverTest: Comparing tildeR against independent computation.");
    assertEquals(
        tildeR, hatR, "PairWiseDifferenceProver Witness tildeR was not computed correctly.");
  }

  /**
   * This test establishes the correctness of the response computation (hat-values). The test
   * executes the pre-challenge phase first and computes a random challenge subsequently.
   *
   * <p>After executing the post-challenge phase, the hat-values are retrieved from the ProofStore.
   * It is checked that these hat-values are consistent with witness randomness (tilde-values) and
   * the secrets.
   *
   * <p>Finally, the test case calls the self-verification of the PairWiseDifferenceProver for a
   * white-box test of the verification equation on the hat values.
   *
   * @throws ProofStoreException
   * @throws NoSuchAlgorithmException
   * @throws InterruptedException
   */
  @Test
  @DisplayName("Test post challenge phase")
  void testPostChallengePhase()
      throws ProofStoreException, NoSuchAlgorithmException, InterruptedException {

    prover.executeCompoundPreChallengePhase();
    tildea_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEABARIBARJ, testIndex));

    tildeb_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDEBBARIBARJ, testIndex));

    tilder_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.TILDERBARIBARJ, testIndex));

    assertNotNull(tildea_BariBarj);
    assertNotNull(tildeb_BariBarj);
    assertNotNull(tilder_BariBarj);

    BigInteger cChallenge = prover.computeChallenge();
    log.info("challenge: " + cChallenge);

    log.info("challenge bitlength: " + cChallenge.bitLength());

    prover.executePostChallengePhase(cChallenge);

    Thread.sleep(3000);

    log.info("Checking hat-values");
    hata_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATABARIBARJ, testIndex));
    hatb_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATBBARIBARJ, testIndex));
    hatr_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.HATRBARIBARJ, testIndex));

    assertNotNull(hata_BariBarj);
    assertNotNull(hatb_BariBarj);
    assertNotNull(hatr_BariBarj);

    log.info(
        "Hat Values:"
            + "\n   hata = "
            + hata_BariBarj
            + "\n   hatb = "
            + hatb_BariBarj
            + "\n   hatr = "
            + hatr_BariBarj);

    log.info("Checking correspondence between hat and tilde values");
    a_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.ABARIBARJ, testIndex));

    b_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.BBARIBARJ, testIndex));

    r_BariBarj =
        (BigInteger) proofStore.retrieve(prover.getProverURN(URNType.RBARIBARJ, testIndex));

    assertEquals(tildea_BariBarj, hata_BariBarj.subtract(cChallenge.multiply(a_BariBarj)));
    assertEquals(tildeb_BariBarj, hatb_BariBarj.subtract(cChallenge.multiply(b_BariBarj)));
    assertEquals(tilder_BariBarj, hatr_BariBarj.subtract(cChallenge.multiply(r_BariBarj)));

    log.info("hate bitLength " + hata_BariBarj.bitLength());
    log.info("hatvPrime bitLength " + hatb_BariBarj.bitLength());
    log.info("hatm_0 bitLength " + hatr_BariBarj.bitLength());

    log.info("Calling Prover self-verification.");
    assertTrue(
        prover.verify(), "PairWiseDifferenceProver self-verification post-challenge failed.");
  }
}
