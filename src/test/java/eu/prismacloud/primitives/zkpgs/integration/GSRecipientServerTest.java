package eu.prismacloud.primitives.zkpgs.integration;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.orchestrator.RecipientOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
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
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private FilePersistenceUtil persistenceUtil;

  @BeforeAll
  void setup1Key() throws IOException, ClassNotFoundException, InterruptedException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
     persistenceUtil = new FilePersistenceUtil();
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
        new RecipientOrchestrator(extendedPublicKey);

    recipientOrchestrator.round1();
    recipientOrchestrator.round3();
    recipientOrchestrator.close();
    GSSignature gsSignature = recipientOrchestrator.getGraphSignature();

    // persist graph signature for testing the geo-location separation proof
    gslog.info("persist graph signature");
    GroupElement A = gsSignature.getA();
    persistenceUtil.write(A, "A.ser");
    BigInteger e = gsSignature.getE();
    persistenceUtil.write(e, "e.ser");
    BigInteger v = gsSignature.getV();
    persistenceUtil.write(v, "v.ser");

    // persist encoded base collection to be used in subsequent proofs
    gslog.info("persist encoded base collection");
    BaseCollection baseCollection = recipientOrchestrator.getEncodedBasesCollection();
    persistenceUtil.write(baseCollection, "baseCollection.ser");

    assertNotNull(extendedPublicKey);
  }
}
