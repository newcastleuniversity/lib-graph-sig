package uk.ac.ncl.cascade;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.orchestrator.GroupSetupProverOrchestrator;
import uk.ac.ncl.cascade.zkpgs.orchestrator.GroupSetupVerifierOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.GroupSetupProver;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.NumberConstants;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** Group Setup integration testing using a 2048 modulus length with a persisted SignerKeyPair. */
@TestInstance(Lifecycle.PER_CLASS)
public class GroupSetupIT {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private ExtendedKeyPair extendedKeyPair;
  private SignerKeyPair gsk;
  private GroupSetupProver groupSetupProver;
  private ProofStore<Object> proofStore;
  private GroupSetupProverOrchestrator gpsOrchestrator;
  private BigInteger cChallenge;
  private ProofSignature proofSig;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException, EncodingException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    gsk = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
    extendedKeyPair.createExtendedKeyPair();
  }

  @Test
  @DisplayName("Test group setup proving proccess should output a proof signature")
  void testGroupSetupProverOrchestrator() {
    ProofStore proofStore = new ProofStore<Object>();
    int bitLength =
        keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
    BigInteger max = NumberConstants.TWO.getValue().pow(bitLength);
    BigInteger min = max.negate();

    gpsOrchestrator = new GroupSetupProverOrchestrator(extendedKeyPair, proofStore);

    gpsOrchestrator.executePreChallengePhase();
    BigInteger tilder =
        (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

    BigInteger tilder_0 =
        (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

    BigInteger tilder_Z =
        (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

    assertNotNull(tilder);
    assertNotNull(tilder_0);
    assertNotNull(tilder_Z);
    assertTrue(inRange(tilder, min, max));
    assertTrue(inRange(tilder_0, min, max));
    assertTrue(inRange(tilder_Z, min, max));

    cChallenge = gpsOrchestrator.computeChallenge();
    assertNotNull(cChallenge);
    assertEquals(cChallenge.bitLength(), keyGenParameters.getL_H());

    gpsOrchestrator.executePostChallengePhase(cChallenge);

    proofSig = gpsOrchestrator.createProofSignature();

    assertNotNull(proofSig);
    assertTrue(!proofSig.getProofSignatureElements().isEmpty());

    BigInteger hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
    BigInteger hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
    BigInteger hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

    assertNotNull(hatr_Z);
    assertNotNull(hatr);
    assertNotNull(hatr_0);

    assertTrue(inRange(hatr_Z, min, max));
    assertTrue(inRange(hatr, min, max));
    assertTrue(inRange(hatr_0, min, max));
  }

  boolean inRange(BigInteger number, BigInteger min, BigInteger max) {
    return (number.compareTo(min) >= 0) && (number.compareTo(max) <= 0);
  }

  @Test
  @DisplayName("Test group setup verifying process")
  void testGroupSetupVerifierOrchestrator() {
    ProofStore proofStore = new ProofStore<Object>();
    int bitLength =
        keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
    BigInteger max = NumberConstants.TWO.getValue().pow(bitLength);
    BigInteger min = max.negate();

    // start group setup proving
    gpsOrchestrator = new GroupSetupProverOrchestrator(extendedKeyPair, proofStore);

    gpsOrchestrator.executePreChallengePhase();
    BigInteger tilder =
        (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

    BigInteger tilder_0 =
        (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

    BigInteger tilder_Z =
        (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

    assertNotNull(tilder);
    assertNotNull(tilder_0);
    assertNotNull(tilder_Z);
    assertTrue(inRange(tilder, min, max));
    assertTrue(inRange(tilder_0, min, max));
    assertTrue(inRange(tilder_Z, min, max));

    cChallenge = gpsOrchestrator.computeChallenge();
    assertNotNull(cChallenge);
    assertEquals(cChallenge.bitLength(), keyGenParameters.getL_H());

    gpsOrchestrator.executePostChallengePhase(cChallenge);

    proofSig = gpsOrchestrator.createProofSignature();

    assertNotNull(proofSig);
    assertTrue(!proofSig.getProofSignatureElements().isEmpty());

    BigInteger hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
    BigInteger hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
    BigInteger hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

    assertNotNull(hatr_Z);
    assertNotNull(hatr);
    assertNotNull(hatr_0);

    assertTrue(inRange(hatr_Z, min, max));
    assertTrue(inRange(hatr, min, max));
    assertTrue(inRange(hatr_0, min, max));

    // start group setup verifying

    ProofStore<Object> vproofStore = new ProofStore<Object>();

    GroupSetupVerifierOrchestrator groupSetupVerifierOrchestrator =
        new GroupSetupVerifierOrchestrator(
            proofSig, extendedKeyPair.getExtendedPublicKey(), vproofStore);
    boolean isVerified = groupSetupVerifierOrchestrator.executeVerification(cChallenge);
    assertTrue(isVerified);
  }
}
