package uk.ac.ncl.cascade.keys;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.BaseIterator;
import uk.ac.ncl.cascade.zkpgs.util.InfoFlowUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class ExtendedPublicKeyTest {

	private KeyGenParameters keyGenParameters;
	private SignerKeyPair gsk;
	private GraphEncodingParameters graphEncodingParameters;
	private ExtendedKeyPair extendedKeyPair;
	private ExtendedPublicKey extendedPublicKey;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, EncodingException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		gsk = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.setupEncoding();
		extendedKeyPair.createExtendedKeyPair();
		extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
	}

	@Test
	@DisplayName("Test creation of ExtentedPublicKey")
	void testExtendedPublicKey() {
		assertNotNull(extendedPublicKey);
	}

	@Test
	void getPublicKey() {
		SignerPublicKey signerPublicKey = extendedPublicKey.getPublicKey();
		assertNotNull(signerPublicKey);
	}

	@Test
	void getBases() {
		Map<URN, BaseRepresentation> bases = extendedPublicKey.getBases();
		assertNotNull(bases);
		assertTrue(bases.size() > 0);
	}

	@Test
	void getBaseCollection() {
		BaseCollection bases = extendedPublicKey.getBaseCollection();
		assertNotNull(bases);
		assertTrue(bases.size() > 0);
	}

	@Test
	void getLabelRepresentatives() {
		Map<URN, BigInteger> labels = extendedPublicKey.getLabelRepresentatives();
		assertNotNull(labels);
	}

	@Test
	void getVertexRepresentatives() {
		Map<URN, BigInteger> vertexRepresentatives = extendedPublicKey.getLabelRepresentatives();
		assertNotNull(vertexRepresentatives);
	}

	@Test
	void getKeyGenParameters() {
		KeyGenParameters keyGenParameters = extendedPublicKey.getKeyGenParameters();
		assertNotNull(keyGenParameters);
	}

	@Test
	void getGraphEncodingParameters() {
		GraphEncodingParameters graphEncodingParameters =
				extendedPublicKey.getGraphEncodingParameters();
		assertNotNull(graphEncodingParameters);
	}

	@Test
	void computeChallengeContext() {
		List<String> challengeList = extendedPublicKey.computeChallengeContext();
		assertNotNull(challengeList);
		assertTrue(challengeList.size() > 0);
	}

	@Test
	void addToChallengeContext() {
		List<String> ctxList = new ArrayList<String>();
		extendedPublicKey.addToChallengeContext(ctxList);
		assertTrue(ctxList.size() > 0);
	}

	@Test
	void testInformationFlowPublicKey() {
		SignerPublicKey signerPublicKey = extendedPublicKey.getPublicKey();
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(signerPublicKey.getBaseS()));
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(signerPublicKey.getBaseZ()));
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(signerPublicKey.getBaseR_0()));
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(signerPublicKey.getBaseR()));
		assertFalse(InfoFlowUtil.doesGroupLeakPrivateInfo(signerPublicKey.getGroup()));
	}

	@Test
	void testInformationFlowBases() {
		Iterator<BaseRepresentation> baseIterator = extendedPublicKey.getBases().values().iterator();
		while (baseIterator.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) baseIterator.next();
			assertFalse("Base " + base.getBaseIndex() + " contained a group element leaking private information.", InfoFlowUtil.doesBaseGroupElementLeakPrivateInfo(base));
		}
	}
	
	@Test
	void testInformationFlowBaseCollection() {
		BaseIterator baseIterator = extendedPublicKey.getBaseCollection().createIterator(BASE.ALL);
		for (BaseRepresentation base : baseIterator) {
			assertFalse("Base " + base.getBaseIndex() + " contained a group element leaking private information.", InfoFlowUtil.doesBaseGroupElementLeakPrivateInfo(base));
		}
	}
}
