package eu.prismacloud.primitives.zkpgs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.recipient.GSRecipient;
import eu.prismacloud.primitives.zkpgs.signer.GSSigner;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
@TestInstance(Lifecycle.PER_CLASS)
public class GSRecipientTest {

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

    recipient = new GSRecipient(extendedKeyPair.getExtendedPublicKey(), keyGenParameters);
  }

  @EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
  @Test
  void testRecipientMessaging() {
    GSMessage recMsg = recipient.receiveMessage();
    assertNotNull(recMsg);

    Map<URN, Object> msgElements = recMsg.getMessageElements();

    for (Object value : msgElements.values()) {
      assertEquals(BigInteger.valueOf(999999), value);
      gslog.info("received message from signer: " + value);
    }

    //    assertNotNull(recipient.receiveMessage());

    Map<URN, Object> msgList = new HashMap<>();
    msgList.put(URN.createZkpgsURN("test1"), BigInteger.valueOf(888888));
    GSMessage msg = new GSMessage(msgList);

    recipient.sendMessage(msg);
  }
@AfterAll
  void tearDown(){
    recipient.close();
}
}
