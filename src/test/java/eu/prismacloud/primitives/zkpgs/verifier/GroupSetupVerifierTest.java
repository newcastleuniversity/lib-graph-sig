package eu.prismacloud.primitives.zkpgs.verifier;

import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** Test group setup verifier */
@TestInstance(Lifecycle.PER_CLASS)
class GroupSetupVerifierTest {

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
  private GroupSetupVerifier groupSetupVerifier;
  private ProofSignature proofSignature;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    gsk = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
  }

  @BeforeEach
  void setUp() throws NoSuchAlgorithmException, ProofStoreException {

    proofStore = new ProofStore<Object>();
    groupSetupProver = new GroupSetupProver(extendedKeyPair, proofStore);

    groupSetupProver.executePreChallengePhase();
    tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

    tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

    tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

    assertNotNull(tilder);
    assertNotNull(tilder_0);
    assertNotNull(tilder_Z);

    BigInteger cChallenge = groupSetupProver.computeChallenge();

    //    assertEquals(cChallenge.bitLength(), keyGenParameters.getL_H());

    groupSetupProver.executePostChallengePhase(cChallenge);

    hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
    hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
    hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

    assertNotNull(hatr_Z);
    assertNotNull(hatr);
    assertNotNull(hatr_0);

    int bitLength = computeBitLength();

    //    assertEquals(bitLength, hatr_Z.bitLength());
    //    assertEquals(bitLength, hatr.bitLength());
    //    assertEquals(bitLength, hatr_0.bitLength());

    proofSignature = groupSetupProver.outputProofSignature();
    Map<URN, Object> proofElements = proofSignature.getProofSignatureElements();
    assertNotNull(proofSignature);
    assertNotNull(proofSignature.getProofSignatureElements());

    for (Object element : proofElements.values()) {
      assertNotNull(element);
    }

    BigInteger phatr = (BigInteger) proofSignature.get("proofsignature.P.hatr");
    //    assertEquals(bitLength, phatr.bitLength());

    BigInteger phatr_0 = (BigInteger) proofSignature.get("proofsignature.P.hatr_0");
    //    assertEquals(bitLength, phatr_0.bitLength());
    BigInteger phatr_Z = (BigInteger) proofSignature.get("proofsignature.P.hatr_Z");
    //    assertEquals(bitLength, phatr_Z.bitLength());

    Map<URN, BigInteger> edgeResponses =
        (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i");
    Map<URN, BigInteger> vertexResponses =
        (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i_j");

    for (BigInteger vertexResponse : vertexResponses.values()) {
      //      assertEquals(bitLength, vertexResponse.bitLength());
    }

    for (BigInteger edgeResponse : edgeResponses.values()) {
      //      assertEquals(bitLength, edgeResponse.bitLength());
    }

    groupSetupVerifier = new GroupSetupVerifier();
  }

  private int computeBitLength() {
    return keyGenParameters.getL_n()
        + keyGenParameters.getL_statzk()
        + keyGenParameters.getL_H()
        + 1;
  }

  @Test
  void preChallengePhase() {

    groupSetupVerifier.preChallengePhase(
        extendedKeyPair.getExtendedPublicKey(),
        proofSignature,
        proofStore,
        keyGenParameters,
        graphEncodingParameters);

    groupSetupVerifier.checkLengths();
  }

  @Test
  void checkLengths() {
	  fail("Test not implemented yet.");
  }

  @Test
  void computeHatValues() {

    groupSetupVerifier.preChallengePhase(
        extendedKeyPair.getExtendedPublicKey(),
        proofSignature,
        proofStore,
        keyGenParameters,
        graphEncodingParameters);

    groupSetupVerifier.checkLengths();

    groupSetupVerifier.computeHatValues();
  }

  @Test
  void computeVerificationChallenge() throws NoSuchAlgorithmException {

    groupSetupVerifier.preChallengePhase(
        extendedKeyPair.getExtendedPublicKey(),
        proofSignature,
        proofStore,
        keyGenParameters,
        graphEncodingParameters);

    groupSetupVerifier.checkLengths();

    groupSetupVerifier.computeHatValues();

    groupSetupVerifier.computeVerificationChallenge();
  }

  @Test
  void verifyChallenge() throws NoSuchAlgorithmException, VerificationException {

    groupSetupVerifier.preChallengePhase(
        extendedKeyPair.getExtendedPublicKey(),
        proofSignature,
        proofStore,
        keyGenParameters,
        graphEncodingParameters);

    groupSetupVerifier.checkLengths();

    groupSetupVerifier.computeHatValues();

    groupSetupVerifier.computeVerificationChallenge();

    groupSetupVerifier.verifyChallenge();
  }
}
