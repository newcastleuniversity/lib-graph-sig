package eu.prismacloud.primitives.zkpgs.integration;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.orchestrator.ProverOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** Testing the prover side of the geo-location separation proof */
@TestInstance(Lifecycle.PER_CLASS)
//@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
public class GSProverServerTest {

  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private ProverOrchestrator proverOrchestrator;
  private ExtendedPublicKey extendedPublicKey;
  private FilePersistenceUtil persistenceUtil;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private GroupElement A;
  private BigInteger e;
  private BigInteger v;
  private BaseCollection baseCollection;

  @BeforeAll
  void setup1Key() throws IOException, ClassNotFoundException, InterruptedException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();

    Thread.sleep(3000);
    gslog.info("read ExtendedPublicKey...");

    String extendedPublicKeyFileName = "ExtendedPublicKey-" + keyGenParameters.getL_n() + ".ser";
    extendedPublicKey = (ExtendedPublicKey) persistenceUtil.read(extendedPublicKeyFileName);
    extendedPublicKey.getBaseCollection();

    gslog.info("read persisted graph signature");
    A = (GroupElement) persistenceUtil.read("A.ser");
    e = (BigInteger) persistenceUtil.read("e.ser");
    v = (BigInteger) persistenceUtil.read("v.ser");

    gslog.info("read encoded base collection");
    baseCollection = (BaseCollection) persistenceUtil.read("baseCollection.ser");
  }


//  @EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
  @Test
  void testProverSide() throws Exception {

    ProofStore<Object> proofStore = new ProofStore<>();
    proofStore.store("graphsignature.A", A);
    proofStore.store("graphsignature.e", e);
    proofStore.store("graphsignature.v", v);
    proofStore.store("encoded.bases", baseCollection );

    proverOrchestrator = new ProverOrchestrator(extendedPublicKey, proofStore, keyGenParameters, graphEncodingParameters);
    proverOrchestrator.init();
    proverOrchestrator.computePreChallengePhase();
    proverOrchestrator.computeChallenge();
    proverOrchestrator.computePostChallengePhase();
  }
}
