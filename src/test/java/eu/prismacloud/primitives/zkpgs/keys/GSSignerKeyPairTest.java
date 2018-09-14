package eu.prismacloud.primitives.zkpgs.keys;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.InfoFlowUtil;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementPQ;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** Test Signer Key Pair */
@TestInstance(Lifecycle.PER_CLASS)
class GSSignerKeyPairTest {
	private Logger log = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private GroupElement baseS;
	private SignerKeyPair signerKeyPair;
	private SignerPublicKey signerPublicKey;
	private SignerPrivateKey signerPrivateKey;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		signerKeyPair = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		signerPublicKey = signerKeyPair.getPublicKey();
		signerPrivateKey = signerKeyPair.getPrivateKey();
	}

	@Test
	@DisplayName("Test key generation")
	void keyGen() {
		log.info("@Test: key generation");
		SignerPublicKey pk = signerKeyPair.getPublicKey();

		assertNotNull(signerKeyPair);
		assertNotNull(signerKeyPair.getPrivateKey());
		assertNotNull(signerKeyPair.getPublicKey());
	}

	@Test
	@DisplayName("Test base S")
	void testBaseS() {
		log.info("@Test: baseS");
		baseS = (GroupElement) signerPublicKey.getBaseS();
		assertNotNull(baseS);
		QRGroupPQ qrGroup = (QRGroupPQ) signerPrivateKey.getGroup();

		assertTrue(qrGroup.isElement(baseS.getValue()));
		assertTrue(
				qrGroup.verifySGenerator(
						baseS.getValue(), signerPrivateKey.getPPrime(), signerPrivateKey.getQPrime()));
	}

	@Test
	void getPrivateKey() {
		log.info("@Test: getPrivateKey");
		assertNotNull(signerKeyPair.getPrivateKey());

		assertNotNull(signerKeyPair.getPrivateKey().getPPrime());
		assertTrue(signerKeyPair.getPrivateKey().getPPrime().isProbablePrime(80));

		assertNotNull(signerKeyPair.getPrivateKey().getQPrime());
		assertTrue(signerKeyPair.getPrivateKey().getQPrime().isProbablePrime(80));

		assertNotNull(signerKeyPair.getPrivateKey().getX_r());
		assertNotNull(signerKeyPair.getPrivateKey().getX_r0());
		assertNotNull(signerKeyPair.getPrivateKey().getX_rZ());
	}

	@Test
	void getPublicKey() {
		log.info("@Test: getPublickKey");
		signerPublicKey = signerKeyPair.getPublicKey();
		assertNotNull(signerKeyPair.getPublicKey());
		assertNotNull(signerPublicKey.getModN());
		assertNotNull(signerPublicKey.getBaseS());
		assertNotNull(signerPublicKey.getBaseZ());
		assertNotNull(signerPublicKey.getBaseR_0());
		assertNotNull(signerPublicKey.getBaseR());
	}

	@Test
	void testInformationFlowPublicKey() {
		signerPublicKey = signerKeyPair.getPublicKey();
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(signerPublicKey.getBaseS()));
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(signerPublicKey.getBaseZ()));
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(signerPublicKey.getBaseR_0()));
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(signerPublicKey.getBaseR()));
		assertFalse(InfoFlowUtil.doesGroupLeakPrivateInfo(signerPublicKey.getGroup()));
	}
	
}
