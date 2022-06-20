package uk.ac.ncl.cascade.keys;

import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRElementPQ;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class SignerPublicKeyTest {
	private Logger log = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters keyGenParameters;
	private SignerKeyPair signerKeyPair;
	private SignerPublicKey signerPublicKey;
	private QRGroupPQ group;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		signerKeyPair = baseTest.getSignerKeyPair();
		keyGenParameters = baseTest.getKeyGenParameters();
		signerPublicKey = signerKeyPair.getPublicKey();
		group = (QRGroupPQ) signerKeyPair.getPrivateKey().getGroup();
	}

	@Test
	void getN() {
		BigInteger modN = signerPublicKey.getModN();
		assertNotNull(modN);
	}

	@Test
	void getR_0() {
		GroupElement baseR_0 = signerPublicKey.getBaseR_0();
		assertNotNull(baseR_0);
		assertTrue(group.isElement(baseR_0.getValue()));

		try {
			QRElementPQ baseR_0PQ = (QRElementPQ) baseR_0;
			QRGroupPQ baseR_0GroupPQ = (QRGroupPQ) baseR_0.getGroup();
			BigInteger baseR_0Order = baseR_0.getElementOrder();
		} catch (ClassCastException e) {
			// Expected exception
			return;
		} catch (UnsupportedOperationException e) {
			// Expected exception
			return;
		}
		fail("The signer public key base R_0 leaked private information PQ/order.");
	}

	@Test
	void getR() {
		GroupElement baseR = signerPublicKey.getBaseR();
		assertNotNull(baseR);
		assertTrue(group.isElement(baseR.getValue()));
	}
	
	@Test
	void testInformationLeakageRPQ() {
		GroupElement baseR = signerPublicKey.getBaseR();
		try {
			QRElementPQ baseRPQ = (QRElementPQ) baseR;
		} catch (ClassCastException e) {
			// Expected exception
			return;
		} 
		fail("The signer public key base R leaked private information PQ.");
	}
	
	@Test
	void testInformationLeakageRGroupPQ() {
		GroupElement baseR = signerPublicKey.getBaseR();
		try {
			QRGroupPQ baseRGroupPQ = (QRGroupPQ) baseR.getGroup();
		} catch (ClassCastException e) {
			// Expected exception
			return;
		}
		fail("The signer public key base R's group leaked private information PQ.");
	}
	
	@Test
	void testInformationLeakageROrderPQ() {
		GroupElement baseR = signerPublicKey.getBaseR();
		try {
			BigInteger baseROrder = baseR.getElementOrder();
		} catch (UnsupportedOperationException e) {
			// Expected exception
			return;
		}
		fail("The signer public key base R leaked private information order.");
	}

	@Test
	void getS() {
		GroupElement baseS = signerPublicKey.getBaseS();
		assertNotNull(baseS);
		assertTrue(
				group.verifySGenerator(
						baseS.getValue(),
						signerKeyPair.getPrivateKey().getPPrime(),
						signerKeyPair.getPrivateKey().getQPrime()));
		assertTrue(group.isElement(baseS.getValue()));
	}
	
	@Test
	void testInformationLeakageSPQ() {
		GroupElement baseS = signerPublicKey.getBaseS();
		try {
			QRElementPQ baseSPQ = (QRElementPQ) baseS;
		} catch (ClassCastException e) {
			// Expected exception
			return;
		} 
		fail("The signer public key base S leaked private information PQ.");
	}
	
	@Test
	void testInformationLeakageSGroupPQ() {
		GroupElement baseS = signerPublicKey.getBaseS();
		try {
			QRGroupPQ baseSGroupPQ = (QRGroupPQ) baseS.getGroup();
		} catch (ClassCastException e) {
			// Expected exception
			return;
		} 
		fail("The signer public key base S's group leaked private information PQ.");
	}
	
	@Test
	void testInformationLeakageSOrder() {
		GroupElement baseS = signerPublicKey.getBaseS();
		try {
			BigInteger baseSOrder = baseS.getElementOrder();
		} catch (UnsupportedOperationException e) {
			// Expected exception
			return;
		}
		fail("The signer public key base S leaked private information order.");
	}

	@Test
	void getZ() {
		GroupElement baseZ = signerPublicKey.getBaseZ();
		assertNotNull(baseZ);

		assertTrue(group.isElement(baseZ.getValue()));
	}
	
	@Test 
	void testInformationLeakageZPQ() {
		GroupElement baseZ = signerPublicKey.getBaseZ();
		try {
			QRElementPQ baseZPQ = (QRElementPQ) baseZ;
		} catch (ClassCastException e) {
			// Expected exception
			return;
		} 
		fail("The signer public key base Z leaked private information PQ.");
	}
	
	@Test 
	void testInformationLeakageZGroupPQ() {
		GroupElement baseZ = signerPublicKey.getBaseZ();
		try {
			QRGroupPQ baseZGroupPQ = (QRGroupPQ) baseZ.getGroup();
		} catch (ClassCastException e) {
			// Expected exception
			return;
		} 
		fail("The signer public key base Z's group leaked private information PQ.");
	}
	
	@Test 
	void testInformationLeakageZOrder() {
		GroupElement baseZ = signerPublicKey.getBaseZ();
		try {
			BigInteger baseZOrder = baseZ.getElementOrder();
		} catch (UnsupportedOperationException e) {
			// Expected exception
			return;
		}
		fail("The signer public key base Z leaked private information order.");
	}
}
