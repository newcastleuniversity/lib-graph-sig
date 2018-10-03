package eu.prismacloud.primitives.zkpgs.signature;


import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.DefaultValues;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.graph.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.*;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.*;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementN;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupN;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class GSSignatureTest {
	private Logger log = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private SignerKeyPair gsk;
	private ExtendedKeyPair extendedKeyPair;
	private ProofStore<Object> proofStore;
	private BigInteger modN;
	private BigInteger m_0;
	private GroupElement baseS;
	private GroupElement baseZ;
	private GroupElement R_0;
	private BigInteger vbar;
	private GroupElement R_0com;
	private GroupElement baseScom;
	private GroupElement commitment;
	private GroupElement Q;
	private BigInteger e;
	private GroupElement A;
	private SignerPrivateKey privateKey;
	private SignerPublicKey publicKey;
	private BigInteger vPrimePrime;
	private GroupElement Sv;
	private GroupElement ZPrime;
	private BigInteger x_Z;
	private BigInteger vCommRandomness;
	private BigInteger d;
	private GroupElement R_0multi;
	private GroupElement Sv1;
	private GSSignature gsSignature;
	private SignerKeyPair signerKeyPair;
	private BaseTest baseTest;
	private GSSigningOracle oracle;
	private BigInteger testM;
	private BaseCollection baseCollection;
	private ExtendedPublicKey extendedPublicKey;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, EncodingException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		signerKeyPair = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(signerKeyPair, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.setupEncoding();
		extendedKeyPair.createExtendedKeyPair();
		extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
		oracle = new GSSigningOracle(signerKeyPair, keyGenParameters);
	}

	@BeforeEach
	void setup() throws EncodingException, ImportException, ProofStoreException {
		testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		assertNotNull(testM, "Test message, a random number, could not be generated.");
		log.info("Creating test signature with GSSigningOracle on testM: " + testM);

		GraphRepresentation gr = GraphUtils.createGraph(DefaultValues.SIGNER_GRAPH_FILE, extendedPublicKey);
		baseCollection = gr.getEncodedBaseCollection();

		BaseRepresentation baseR0 =
				new BaseRepresentation(extendedKeyPair.getPublicKey().getBaseR_0(), -1, BASE.BASE0);
		baseR0.setExponent(testM);

		baseCollection.add(baseR0);

		assertNotNull(baseCollection);
		assertTrue(baseCollection.size() > 0);
		gsSignature = oracle.sign(baseCollection);
		assertNotNull(gsSignature);

	}

	private boolean checkQRGenerator(BigInteger candidate) {
		return (modN.gcd(candidate.subtract(BigInteger.ONE))).equals(BigInteger.ONE);
	}

	@Test
	void testSignatureGeneration() throws Exception {
		//    N =77, l_n = 7
		//    p = 11, p’ =5; q = 7, q’ = 3
		//
		//    \phi(N) = 60
		//    S = 60; QR_N = <60>; order of QR_N = 15
		//    R = 58
		//
		//    l_m = 2; l_e =4 (of course there are only 2 primes e possible fitting these parameters, 11
		// and 13, and the only messages possible: 1, 2 or 3).

		modN = BigInteger.valueOf(77);
		QRGroupN group = new QRGroupN(modN);
		m_0 = BigInteger.valueOf(2);
		baseS = new QRElementN(group, BigInteger.valueOf(60));

		x_Z = CryptoUtilsFacade.computeRandomNumber(BigInteger.valueOf(2), BigInteger.valueOf(14));
		baseZ = baseS.modPow(x_Z);

		R_0 = new QRElementN(group, BigInteger.valueOf(58));

		vCommRandomness = BigInteger.valueOf(1);
		R_0com = R_0.modPow(m_0);
		baseScom = baseS.modPow(vCommRandomness);
		commitment = R_0com.multiply(baseScom);

		e = BigInteger.valueOf(11);
		vbar = CryptoUtilsFacade.computeRandomNumberMinusPlus(429 - 1);
		vPrimePrime = NumberConstants.TWO.getValue().pow(429 - 1).add(vbar);

		Sv = baseS.modPow(vPrimePrime);
		R_0multi = R_0.modPow(m_0);
		Sv1 = Sv.multiply(R_0multi);

		Q = baseZ.multiply(Sv1.modInverse());

		d = e.modInverse(BigInteger.valueOf(15));
		A = Q.modPow(d);
		// verify signature
		GroupElement hatZ = baseS.modPow(vPrimePrime);
		GroupElement hatA = this.A.modPow(this.e);
		hatZ = hatZ.multiply(hatA).multiply(R_0multi);
		hatZ.equals(baseZ);

		assertEquals(baseZ, hatZ);
	}

	@Test
	void getA() throws Exception {
		assertNotNull(gsSignature.getA());
	}


	@Test
	void getE() throws Exception {
		assertNotNull(gsSignature.getE());
		assertTrue(gsSignature.getE().isProbablePrime(80));
	}

	@Test
	void getV() throws Exception {
		assertNotNull(gsSignature.getV());
	}

	@Test
	void blind() throws IOException, ClassNotFoundException {

		GSSignature blindSignature = gsSignature.blind();
		assertNotNull(blindSignature);
		assertNotNull(blindSignature.getA());
		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(blindSignature.getA()));

		assertNotNull(blindSignature.getE());
		assertNotNull(blindSignature.getEPrime());
		assertNotNull(blindSignature.getV());

		assertTrue(blindSignature.verify(extendedPublicKey, baseCollection));

	}

	@Test
	void testInformationFlow() throws ClassNotFoundException, IOException {

		assertFalse(InfoFlowUtil.doesGroupElementLeakPrivateInfo(gsSignature.getA()));

		BaseIterator baseIterator = gsSignature.getEncodedBases().createIterator(BASE.ALL);
		for (BaseRepresentation base : baseIterator) {
			assertFalse(InfoFlowUtil.doesBaseGroupElementLeakPrivateInfo(base));
		}


		if (gsSignature.getGraphRepresentation() != null) {
			BaseIterator grBaseIterator = gsSignature.getGraphRepresentation().getEncodedBaseCollection().createIterator(BASE.ALL);
			for (BaseRepresentation base : grBaseIterator) {
				assertFalse(InfoFlowUtil.doesBaseGroupElementLeakPrivateInfo(base));
			}

			Iterator<BaseRepresentation> bases =
					gsSignature.getGraphRepresentation().getEncodedBases().values().iterator();
			while (bases.hasNext()) {
				BaseRepresentation base = (BaseRepresentation) bases.next();
				assertFalse(InfoFlowUtil.doesBaseGroupElementLeakPrivateInfo(base));
			}
		}
	}

}
