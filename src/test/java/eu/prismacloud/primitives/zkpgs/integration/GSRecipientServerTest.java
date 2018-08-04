package eu.prismacloud.primitives.zkpgs.integration;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.orchestrator.RecipientOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/**
 * Testing the signer side of the Issuing protocol with a 2048 modulus bitlength using a persisted
 * and serialised extendedPublicKey to perform computations.
 */
@TestInstance(Lifecycle.PER_CLASS)
@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
public class GSRecipientServerTest {
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private RecipientOrchestrator recipientOrchestrator;
  private ExtendedPublicKey extendedPublicKey;
  private FilePersistenceUtil persistenceUtil;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

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
  }

  @EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
  @Test
  void test1RecipientSide() throws Exception {

    recipientOrchestrator =
        new RecipientOrchestrator(extendedPublicKey, keyGenParameters, graphEncodingParameters);

    recipientOrchestrator.round1();
    recipientOrchestrator.round3();
    recipientOrchestrator.close();

    assertNotNull(extendedPublicKey);
  }
}
