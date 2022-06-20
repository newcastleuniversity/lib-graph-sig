package uk.ac.ncl.cascade.signer;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.DefaultValues;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.graph.GSEdge;
import uk.ac.ncl.cascade.zkpgs.graph.GSGraph;
import uk.ac.ncl.cascade.zkpgs.graph.GSVertex;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPrivateKey;
import uk.ac.ncl.cascade.zkpgs.message.GSMessage;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.recipient.GSRecipient;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigner;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRGroupPQ;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

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
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 8888;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, InterruptedException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		signerKeyPair = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		privateKey = signerKeyPair.getPrivateKey();
		qrGroup = (QRGroupPQ) privateKey.getGroup();
		extendedKeyPair = new ExtendedKeyPair(signerKeyPair, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.createExtendedKeyPair();
		IMessageGateway messageGateway = new MessageGatewayProxy(DefaultValues.CLIENT, HOST, PORT);
		signer = new GSSigner(extendedKeyPair, messageGateway);
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
