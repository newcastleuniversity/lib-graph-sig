package eu.prismacloud.primitives.zkpgs.integration;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.orchestrator.VerifierOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
@TestInstance(Lifecycle.PER_CLASS)
public class GSVerifierClientTest {

  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private ExtendedPublicKey extendedPublicKey;
  private ProofStore<Object> proofStore;
  private VerifierOrchestrator verifierOrchestrator;

  @BeforeAll
  void setupKey() throws InterruptedException, IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();

    Thread.sleep(3000);
    gslog.info("read ExtendedPublicKey...");

    String extendedPublicKeyFileName = "ExtendedPublicKey-" + keyGenParameters.getL_n() + ".ser";
    extendedPublicKey = (ExtendedPublicKey) persistenceUtil.read(extendedPublicKeyFileName);

    //    gslog.info("read persisted graph signature");
    //    A = (GroupElement) persistenceUtil.read("A.ser");
    //    e = (BigInteger) persistenceUtil.read("e.ser");
    //    v = (BigInteger) persistenceUtil.read("v.ser");

    //    gslog.info("read encoded base collection");
    //    baseCollection = (BaseCollection) persistenceUtil.read("baseCollection.ser");
  }

  @EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
  @Test
  void testProverSide() throws Exception {

    proofStore = new ProofStore<Object>();
    verifierOrchestrator =
        new VerifierOrchestrator(
            extendedPublicKey, proofStore, keyGenParameters, graphEncodingParameters);
    verifierOrchestrator.init();
    verifierOrchestrator.receiveProverMessage();
    verifierOrchestrator.preChallengePhase();
    verifierOrchestrator.computeChallenge();
    verifierOrchestrator.verifyChallenge();
  }
}
