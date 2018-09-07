package eu.prismacloud.primitives.zkpgs.signer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.DefaultValues;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.recipient.GSRecipient;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
@TestInstance(Lifecycle.PER_CLASS)
public class GSSignerTest {

  private SignerKeyPair signerKeyPair;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private SignerPrivateKey privateKey;
  private QRGroupPQ qrGroup;
  private ExtendedKeyPair extendedKeyPair;
  private GSSigner signer;
  private GSRecipient recipient;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException, InterruptedException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    signerKeyPair = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    privateKey = signerKeyPair.getPrivateKey();
    qrGroup = (QRGroupPQ) privateKey.getQRGroup();
    extendedKeyPair = new ExtendedKeyPair(signerKeyPair, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.createExtendedKeyPair();

    signer = new GSSigner(extendedKeyPair);
    signer.init();
  }

  @Test
  void initGraph() throws ImportException {
    GSGraph<GSVertex, GSEdge> gsGraph = signer.initGraph(DefaultValues.SIGNER_GRAPH_FILE);
    assertNotNull(gsGraph);
    assertNotNull(gsGraph.getGraph());
  }

  @EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
  @Test
  void testSignerMessaging() throws IOException {

    gslog.info("test send message to recipient");
    Map<URN, Object> msgList = new HashMap<>();
    msgList.put(URN.createUnsafeZkpgsURN("test1"), BigInteger.valueOf(999999));
    GSMessage msg = new GSMessage(msgList);

    signer.sendMessage(msg);

    gslog.info("test receive message from recipient");
    GSMessage recMsg = signer.receiveMessage();
    assertNotNull(recMsg);

    //    assertNotNull(signer.receiveMessage());
    Map<URN, Object> msgElements = recMsg.getMessageElements();

    for (Object value : msgElements.values()) {
      assertEquals(BigInteger.valueOf(888888), value);
      gslog.info("received message from recipient: " + value);
    }
  }

  @Test
  void computeNonce() {
    BigInteger nonce = signer.computeNonce();
    assertNotNull(nonce);
    Boolean bitLengthRange = nonce.bitLength() <= keyGenParameters.getL_H();
    assertTrue(bitLengthRange);
  }

  @AfterAll
  void tearDown() throws IOException {
    signer.close();
  }
}
