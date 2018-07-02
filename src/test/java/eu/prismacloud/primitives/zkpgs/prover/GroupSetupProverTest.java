package eu.prismacloud.primitives.zkpgs.prover;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/** */
class GroupSetupProverTest {

  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private Logger log = GSLoggerConfiguration.getGSlog();
  private SignerKeyPair gsk;
  private ExtendedKeyPair extendedKeyPair;
  private GroupSetupProver groupSetupProver;
  private ProofStore<Object> proofStore;
  private BigInteger tilder;
  private BigInteger tilder_0;
  private BigInteger tilder_Z;
  private BigInteger hatr_Z;
  private BigInteger hatr;
  private BigInteger hatr_0;
  private BigInteger tildeZ;

  @BeforeEach
  void setUp() {
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    graphEncodingParameters = parameters.getGraphEncodingParameters();
    log.info("@Test: key generation");
    gsk = SignerKeyPair.KeyGen(keyGenParameters);
    assertNotNull(gsk);
    assertNotNull(gsk.getPrivateKey());
    assertNotNull(gsk.getPublicKey());
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());

    groupSetupProver = new GroupSetupProver();
    proofStore = new ProofStore<Object>();
  }

  @Test
  void preChallengePhase() {

    groupSetupProver.preChallengePhase(
        extendedKeyPair, proofStore, keyGenParameters, graphEncodingParameters);
    tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");
    assertNotNull(tilder);
    tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");
    assertNotNull(tilder_0);
    tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");
    assertNotNull(tilder_Z);
  }

  @Test
  @DisplayName("Test witness randomness is in range [-2^bitLength, 2^bitlength]")
  void createWitnessRandomness() {
    int bitLength =
        keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
    BigInteger max = NumberConstants.TWO.getValue().pow(bitLength);
    BigInteger min = max.negate();
    log.info("maximum positive random number: " + max);
    log.info("minimum negative random number: " + min);
    log.info("bitLength: " + bitLength);

    groupSetupProver.preChallengePhase(
        extendedKeyPair, proofStore, keyGenParameters, graphEncodingParameters);
    tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");
    assertNotNull(tilder);
    assertTrue(inRange(tilder, min, max));

    tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");
    assertNotNull(tilder_0);
    assertTrue(inRange(tilder_0, min, max));

    tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");
    assertNotNull(tilder_Z);
    assertTrue(inRange(tilder_Z, min, max));
  }

  boolean inRange(BigInteger number, BigInteger min, BigInteger max) {
    return (number.compareTo(min) >= 0) && (number.compareTo(max) <= 0);
  }

  @Test
  @DisplayName("Test witness randomness bit length")
  void computeWitnessRandomnessBitLength() {
    int bitLength =
        keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
    BigInteger max = NumberConstants.TWO.getValue().pow(bitLength);
    BigInteger min = max.negate();
    log.info("maximum positive random number: " + max);
    log.info("minimum negative random number: " + min);
    log.info("bitLength: " + bitLength);

    groupSetupProver.preChallengePhase(
        extendedKeyPair, proofStore, keyGenParameters, graphEncodingParameters);
    tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");
    assertNotNull(tilder);
    assertTrue(inRange(tilder, min, max));
    log.info("bitLength tilder: " + tilder.bitLength());
    assertEquals(bitLength, tilder.bitLength());

    tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");
    assertNotNull(tilder_0);
    assertTrue(inRange(tilder_0, min, max));
    log.info("bitLength tilder_0: " + tilder_0.bitLength());
    assertEquals(bitLength, tilder_0.bitLength());

    tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");
    assertNotNull(tilder_Z);
    assertTrue(inRange(tilder_Z, min, max));
    log.info("bitLength tilder_Z: " + tilder_Z.bitLength());
    assertEquals(bitLength, tilder_Z.bitLength());
  }

  @Test
  @DisplayName("Test computing witnesses")
  void computeWitness() {
    groupSetupProver.preChallengePhase(
        extendedKeyPair, proofStore, keyGenParameters, graphEncodingParameters);
    tildeZ = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.tildeZ");
    assertNotNull(tildeZ);
    /** TODO test that it is congruent */
  }

  @Test
  @DisplayName("Test challenge bitLength")
  @RepeatedTest(5)
  void computeChallenge() throws NoSuchAlgorithmException {

    groupSetupProver.preChallengePhase(
        extendedKeyPair, proofStore, keyGenParameters, graphEncodingParameters);
    BigInteger cChallenge = groupSetupProver.computeChallenge();
    assertEquals(keyGenParameters.getL_H(), cChallenge.bitLength());
  }

  @Test
  @DisplayName("Test post challenge phase")
  @RepeatedTest(15)
  void postChallengePhase() throws ProofStoreException, NoSuchAlgorithmException {

    groupSetupProver.preChallengePhase(
        extendedKeyPair, proofStore, keyGenParameters, graphEncodingParameters);
    tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

    tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

    tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

    assertNotNull(tilder);
    assertNotNull(tilder_0);
    assertNotNull(tilder_Z);

    BigInteger cChallenge = groupSetupProver.computeChallenge();
    log.info("challenge: " + cChallenge);

    byte[] result = cChallenge.toByteArray();

    log.info("byte array length: " + result.length);
    log.info("challenge bitlength: " + cChallenge.bitLength());

    assertEquals(keyGenParameters.getL_H(), cChallenge.bitLength());

    groupSetupProver.postChallengePhase();

    hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
    hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
    hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

    assertNotNull(hatr_Z);
    assertNotNull(hatr);
    assertNotNull(hatr_0);

    int bitLength = computeBitLength();

    log.info("hatrZ bitLength " + hatr_Z.bitLength());
    log.info("hatr bitLength " + hatr.bitLength());
    log.info("hatr0 bitLength " + hatr_0.bitLength());

    assertEquals(bitLength, hatr_Z.bitLength()+1);
    assertEquals(bitLength, hatr.bitLength()+1);
    assertEquals(bitLength, hatr_0.bitLength()+1);
  }

  @Test
  @DisplayName("Test output proof signature")
  void outputProofSignature() throws NoSuchAlgorithmException, ProofStoreException {
    groupSetupProver.preChallengePhase(
        extendedKeyPair, proofStore, keyGenParameters, graphEncodingParameters);
    tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

    tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

    tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

    assertNotNull(tilder);
    assertNotNull(tilder_0);
    assertNotNull(tilder_Z);

    BigInteger cChallenge = groupSetupProver.computeChallenge();

    //    assertEquals(cChallenge.bitLength(), keyGenParameters.getL_H());

    groupSetupProver.postChallengePhase();

    hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
    hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
    hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

    assertNotNull(hatr_Z);
    assertNotNull(hatr);
    assertNotNull(hatr_0);

    int bitLength = computeBitLength();

    assertEquals(bitLength, hatr_Z.bitLength());
    assertEquals(bitLength, hatr.bitLength());
    assertEquals(bitLength, hatr_0.bitLength());

    ProofSignature proofSignature = groupSetupProver.outputProofSignature();
    Map<URN, Object> proofElements = proofSignature.getProofSignatureElements();
    assertNotNull(proofSignature);
    assertNotNull(proofSignature.getProofSignatureElements());

    for (Object element : proofElements.values()) {
      assertNotNull(element);
    }

    BigInteger phatr = (BigInteger) proofSignature.get("proofsignature.P.hatr");
    assertEquals(bitLength, phatr.bitLength());

    BigInteger phatr_0 = (BigInteger) proofSignature.get("proofsignature.P.hatr_0");
    assertEquals(bitLength, phatr_0.bitLength());
    BigInteger phatr_Z = (BigInteger) proofSignature.get("proofsignature.P.hatr_Z");
    assertEquals(bitLength, phatr_Z.bitLength());

    Map<URN, BigInteger> edgeResponses =
        (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i");
    Map<URN, BigInteger> vertexResponses =
        (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i_j");

    for (BigInteger vertexResponse : vertexResponses.values()) {
      assertEquals(bitLength, vertexResponse.bitLength());
    }

    for (BigInteger edgeResponse : edgeResponses.values()) {
      assertEquals(bitLength, edgeResponse.bitLength());
    }
  }

  private int computeBitLength() {
    return keyGenParameters.getL_n()
        + keyGenParameters.getL_statzk()
        + keyGenParameters.getL_H()
        + 1;
  }
}