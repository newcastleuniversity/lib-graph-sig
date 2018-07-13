package eu.prismacloud.primitives.zkpgs.signer;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
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
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.math.BigInteger;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class GSSignerTest {

  private SignerKeyPair signerKeyPair;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private SignerPrivateKey privateKey;
  private QRGroupPQ qrGroup;
  private ExtendedKeyPair extendedKeyPair;
  private GSSigner signer;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    signerKeyPair = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    privateKey = signerKeyPair.getPrivateKey();
    qrGroup = (QRGroupPQ) signerKeyPair.getQRGroup();
    extendedKeyPair = new ExtendedKeyPair(signerKeyPair, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.createExtendedKeyPair();
    signer = new GSSigner(extendedKeyPair, keyGenParameters);
  }

  @Test
  void initGraph() throws ImportException {
    GSGraph<GSVertex, GSEdge> gsGraph = signer.initGraph();
    assertNotNull(gsGraph);
    assertNotNull(gsGraph.getGraph());
  }

  @Test
  void sendMessage() {
    GSMessage msg = new GSMessage();
    msg.addCommitment(
            new GSCommitment(
                new QRElement(qrGroup, BigInteger.valueOf(10)),
                BigInteger.valueOf(11),
                BigInteger.valueOf(23),
                new QRElement(qrGroup, BigInteger.valueOf(10)),
                BigInteger.valueOf(32)));

    signer.sendMessage(
        msg, new GSRecipient(extendedKeyPair.getExtendedPublicKey(), keyGenParameters));
//   assertNotNull(signer.getMessage());
  }

  @Test
  void computeNonce() {
    BigInteger nonce = signer.computeNonce();
    assertNotNull(nonce);
    Boolean bitLengthRange = nonce.bitLength() <= keyGenParameters.getL_H();
    assertTrue(bitLengthRange);
  }

  @Test
  void receiveMessage() {
    GSMessage msg = new GSMessage();
        msg.addCommitment(
                new GSCommitment(
                    new QRElement(qrGroup, BigInteger.valueOf(10)),
                    BigInteger.valueOf(11),
                    BigInteger.valueOf(23),
                    new QRElement(qrGroup, BigInteger.valueOf(10)),
                    BigInteger.valueOf(32)));

        signer.sendMessage(
            msg, new GSRecipient(extendedKeyPair.getExtendedPublicKey(), keyGenParameters));
        GSSigner.receiveMessage(msg);
       assertNotNull(signer.getMessage());
  }

  @Test
  void getMessage() {
    GSMessage msg = new GSMessage();
            msg.addCommitment(
                    new GSCommitment(
                        new QRElement(qrGroup, BigInteger.valueOf(10)),
                        BigInteger.valueOf(11),
                        BigInteger.valueOf(23),
                        new QRElement(qrGroup, BigInteger.valueOf(10)),
                        BigInteger.valueOf(32)));

            signer.sendMessage(
                msg, new GSRecipient(extendedKeyPair.getExtendedPublicKey(), keyGenParameters));
            GSSigner.receiveMessage(msg);
            GSMessage recMsg = signer.getMessage();
           assertNotNull(recMsg);
           
  }
}
