package eu.prismacloud.primitives.zkpgs.orchestrator;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class GroupSetupProverOrchestratorTest {

  private SignerKeyPair gsk;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private ExtendedKeyPair extendedKeyPair;
  private ProofStore<Object> proofStore;
  private GroupSetupProverOrchestrator gsProverOrchestrator;

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
    proofStore = new ProofStore<Object>();
    gsProverOrchestrator = new GroupSetupProverOrchestrator(extendedKeyPair, proofStore);
  }

  @Test
  void executePreChallengePhase() {
    gsProverOrchestrator.executePreChallengePhase();

  }

  @Test
  void computeChallenge() {
    BigInteger cChallenge = gsProverOrchestrator.computeChallenge();
    assertNotNull(cChallenge);
  }

  @Test
  void executePostChallengePhase() {
    gsProverOrchestrator.executePreChallengePhase();
    BigInteger cChallenge = gsProverOrchestrator.computeChallenge();
    gsProverOrchestrator.executePostChallengePhase(cChallenge);
  }

  @Test
  void createProofSignature() {
    gsProverOrchestrator.executePreChallengePhase();
    BigInteger cChallenge = gsProverOrchestrator.computeChallenge();
    gsProverOrchestrator.executePostChallengePhase(cChallenge);
    ProofSignature proofSignature = gsProverOrchestrator.createProofSignature();
    assertNotNull(proofSignature);
    Map<URN, Object> proofElements = proofSignature
        .getProofSignatureElements();

    assertNotNull(proofElements);
    assertTrue(proofElements.size() > 0);

  }
}
