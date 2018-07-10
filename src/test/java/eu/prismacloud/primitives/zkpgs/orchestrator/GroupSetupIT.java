package eu.prismacloud.primitives.zkpgs.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.verifier.GroupSetupVerifier;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Group Setup integration testing using a 2048 modulus length with a persisted SignerKeyPair. */
public class GroupSetupIT {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private ExtendedKeyPair extendedKeyPair;
  private SignerKeyPair gsk;
  private GroupSetupProver groupSetupProver;
  private ProofStore<Object> proofStore;

  @BeforeEach
  void setUp()
      throws NoSuchAlgorithmException, ProofStoreException, IOException, ClassNotFoundException {
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    graphEncodingParameters = parameters.getGraphEncodingParameters();
  }

  @ParameterizedTest(name = "{index} => bitLength=''{0}''")
  @ValueSource(strings = {"2048"})
  void shouldCreateASignerKeyPair(String bitLength) throws IOException, ClassNotFoundException {

    if (bitLength.equals("2048")) {
      FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
      gsk = (SignerKeyPair) persistenceUtil.read("SignerKeyPair-" + bitLength + ".ser");
    } else {
      gsk.keyGen(keyGenParameters);
    }

    assertNotNull(gsk);
    assertNotNull(gsk.getPrivateKey());
    assertNotNull(gsk.getPublicKey());
  }

  private int computeBitLength() {
    return keyGenParameters.getL_n()
        + keyGenParameters.getL_statzk()
        + keyGenParameters.getL_H()
        + 1;
  }

  @Test
  void testExtendedKeyPair() throws IOException, ClassNotFoundException {
    shouldCreateASignerKeyPair("2048");

    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());
  }

  @Test
  void testGroupSetup()
      throws ProofStoreException, NoSuchAlgorithmException, IOException, ClassNotFoundException {
    testExtendedKeyPair();
    testGroupSetupProver();

    ProofSignature proofSignature = groupSetupProver.outputProofSignature();
    Map<URN, Object> proofElements = proofSignature.getProofSignatureElements();
    assertNotNull(proofSignature);
    assertNotNull(proofSignature.getProofSignatureElements());

    for (Object element : proofElements.values()) {
      assertNotNull(element);
    }

    int bitLength = computeBitLength();

    BigInteger phatr = (BigInteger) proofSignature.get("proofsignature.P.hatr");
    assertEquals(bitLength, phatr.bitLength() + 1);

    BigInteger phatr_0 = (BigInteger) proofSignature.get("proofsignature.P.hatr_0");
    assertEquals(bitLength, phatr_0.bitLength() + 1);
    BigInteger phatr_Z = (BigInteger) proofSignature.get("proofsignature.P.hatr_Z");
    assertEquals(bitLength, phatr_Z.bitLength() + 1);

    Map<URN, BigInteger> edgeResponses =
        (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i");
    Map<URN, BigInteger> vertexResponses =
        (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i_j");

    for (BigInteger vertexResponse : vertexResponses.values()) {
      assertEquals(bitLength, vertexResponse.bitLength() + 1);
    }

    for (BigInteger edgeResponse : edgeResponses.values()) {
      assertEquals(bitLength, edgeResponse.bitLength() + 1);
    }

    testGroupSetupVerifier(proofSignature);
  }

  private void testGroupSetupVerifier(ProofSignature proofSignature)
      throws NoSuchAlgorithmException {
    GroupSetupVerifier groupSetupVerifier = new GroupSetupVerifier();

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

  private void testGroupSetupProver() throws NoSuchAlgorithmException, ProofStoreException {
    groupSetupProver = new GroupSetupProver();
    proofStore = new ProofStore<Object>();

    groupSetupProver.preChallengePhase(
        extendedKeyPair, proofStore, keyGenParameters, graphEncodingParameters);
    BigInteger tilder =
        (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

    BigInteger tilder_0 =
        (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

    BigInteger tilder_Z =
        (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

    assertNotNull(tilder);
    assertNotNull(tilder_0);
    assertNotNull(tilder_Z);

    BigInteger cChallenge = groupSetupProver.computeChallenge();

    assertEquals(cChallenge.bitLength(), keyGenParameters.getL_H());

    groupSetupProver.postChallengePhase();

    BigInteger hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
    BigInteger hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
    BigInteger hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

    assertNotNull(hatr_Z);
    assertNotNull(hatr);
    assertNotNull(hatr_0);

    int bitLength = computeBitLength();

    assertEquals(bitLength, hatr_Z.bitLength()+1);
    assertEquals(bitLength, hatr.bitLength()+1);
    assertEquals(bitLength, hatr_0.bitLength()+1);
  }
}
