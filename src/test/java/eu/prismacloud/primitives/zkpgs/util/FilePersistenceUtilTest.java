package eu.prismacloud.primitives.zkpgs.util;


import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.DefaultValues;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.graph.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;

import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class FilePersistenceUtilTest {
	private Logger log = GSLoggerConfiguration.getGSlog();
	// set flag to true to generate a new signer key pair and a new signer public key
	private Boolean generateKeys = false;
	private FilePersistenceUtil persistenceUtil;
	private KeyGenParameters keyGenParameters;
	private String signerKeyPairFileName;
	private String signerPublicKeyFileName;
	private GraphEncodingParameters graphEncodingParameters;
	private ExtendedKeyPair extendedKeyPair;
	private String extendedPublicKeyFileName;

	private String graphSignatureFileName;
	private String extendedKeyPairFileName;

	@BeforeAll
	void setUp() {
		JSONParameters parameters = new JSONParameters();
		keyGenParameters = parameters.getKeyGenParameters();
		graphEncodingParameters = parameters.getGraphEncodingParameters();
		persistenceUtil = new FilePersistenceUtil();
		signerKeyPairFileName = "SignerKeyPair-" + keyGenParameters.getL_n() + ".ser";
		signerPublicKeyFileName = "SignerPublicKey-" + keyGenParameters.getL_n() + ".ser";
		extendedPublicKeyFileName = "ExtendedPublicKey-" + keyGenParameters.getL_n() + ".ser";
		extendedKeyPairFileName = "ExtendedKeyPair-" + keyGenParameters.getL_n() + ".ser";

		graphSignatureFileName = "signer-infra.gs.ser";
	}

	@Test
	@DisplayName("Generate a new signer key pair and signer public key")
	void writeKeyPairAndPublicKey() throws IOException, EncodingException {

		if (generateKeys) {
			log.info("Test writeSignerKeyPair: generating new SignerKeyPair...");

			SignerKeyPair gsk = new SignerKeyPair();
			gsk.keyGen(keyGenParameters);

			log.info("Test writeSignerPublicKey: writing new SignerKeyPair...");
			persistenceUtil.write(gsk, signerKeyPairFileName);

			log.info("Test writeSignerPublicKey: writing new SignerPublicKey...");
			persistenceUtil.write(gsk.getPublicKey(), signerPublicKeyFileName);

			extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
			extendedKeyPair.generateBases();
			extendedKeyPair.setupEncoding();
			extendedKeyPair.createExtendedKeyPair();

			log.info("Test writeExtendedPublicKey: writing new ExtendedKeyPair...");
			persistenceUtil.write(extendedKeyPair, extendedKeyPairFileName);
			
			log.info("Test writeExtendedPublicKey: writing new ExtendedPublicKey...");
			String extendedPublicKeyFileName = "ExtendedPublicKey-" + keyGenParameters.getL_n() + ".ser";
			persistenceUtil.write(extendedKeyPair.getExtendedPublicKey(), extendedPublicKeyFileName);
		}
	}

	@Test
	void readSignerKeyPair() throws IOException, ClassNotFoundException {

		SignerKeyPair signerKeyPair = (SignerKeyPair) persistenceUtil.read(signerKeyPairFileName);

		assertNotNull(signerKeyPair);
		assertNotNull(signerKeyPair.getPrivateKey());
		assertNotNull(signerKeyPair.getPublicKey());

		SignerPublicKey signerPublicKey = signerKeyPair.getPublicKey();
		SignerPrivateKey signerPrivateKey = signerKeyPair.getPrivateKey();
		assertNotNull(signerPublicKey.getGroup());
		assertNotNull(signerPrivateKey.getGroup());
		QRGroupPQ group = (QRGroupPQ) signerPrivateKey.getGroup();
		GroupElement baseS = signerPublicKey.getBaseS();

		assertTrue(
				group.verifySGenerator(
						baseS.getValue(), signerPrivateKey.getPPrime(), signerPrivateKey.getQPrime()));

		assertTrue(group.isElement(baseS.getValue()));
		assertTrue(group.isElement(signerPublicKey.getBaseZ().getValue()));
		assertTrue(group.isElement(signerPublicKey.getBaseR().getValue()));
		assertTrue(group.isElement(signerPublicKey.getBaseR_0().getValue()));
	}

	@Test
	void readSignerPublidKey() throws IOException, ClassNotFoundException {
		SignerPublicKey signerPublicKey =
				(SignerPublicKey) persistenceUtil.read(signerPublicKeyFileName);
		assertNotNull(signerPublicKey);
		assertNotNull(signerPublicKey.getBaseR());
		assertNotNull(signerPublicKey.getBaseR_0());
		assertNotNull(signerPublicKey.getBaseS());
		assertNotNull(signerPublicKey.getBaseZ());
	}


	@Test
	void readExtendedPublicKey() throws IOException, ClassNotFoundException {
		ExtendedPublicKey extendedPublicKey =
				(ExtendedPublicKey) persistenceUtil.read(extendedPublicKeyFileName);
		assertNotNull(extendedPublicKey);
		assertNotNull(extendedPublicKey.getPublicKey());
		assertNotNull(extendedPublicKey.getBaseCollection());
		assertNotNull(extendedPublicKey.getVertexRepresentatives());
		assertNotNull(extendedPublicKey.getLabelRepresentatives());
	}
	
	@Test
	void readExtendedKeyPair() throws IOException, ClassNotFoundException {
		ExtendedKeyPair readExtendedKeyPair =
				(ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFileName);
		assertNotNull(readExtendedKeyPair);
		assertNotNull(readExtendedKeyPair.getPublicKey());
		assertNotNull(readExtendedKeyPair.getPrivateKey());
		assertNotNull(readExtendedKeyPair.getBaseKeyPair());
		
		assertNotNull(readExtendedKeyPair.getVertexRepresentatives());
		assertNotNull(readExtendedKeyPair.getLabelRepresentatives());
	}

	@Test
	void writeGraphSignature() throws IOException, ImportException, EncodingException, ClassNotFoundException {
		ExtendedKeyPair readExtendedKeyPair =
				(ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFileName);
		
		GSSigningOracle oracle = new GSSigningOracle(readExtendedKeyPair.getBaseKeyPair(), keyGenParameters, graphEncodingParameters); 

		BigInteger testM = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
		GraphRepresentation gr = GraphUtils.createGraph(DefaultValues.SIGNER_GRAPH_FILE, testM, readExtendedKeyPair.getExtendedPublicKey());
		
		GSSignature sigma = oracle.sign(gr);

		persistenceUtil.write(sigma, graphSignatureFileName);
	}

	@Test
	void readGraphSignature() throws IOException, ClassNotFoundException {
		ExtendedKeyPair readExtendedKeyPair =
				(ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFileName);
		
		GSSignature sigma =
				(GSSignature) persistenceUtil.read(graphSignatureFileName);

		assertNotNull(sigma);
		assertNotNull(sigma.getA());
		assertNotNull(sigma.getE());
		assertNotNull(sigma.getEPrime());
		assertNotNull(sigma.getV());
		assertNotNull(sigma.getEPrimeOffset());
		assertNotNull(sigma.getEncodedBases());
		
		BaseCollection encodedBases = sigma.getEncodedBases();
		assertTrue(encodedBases.size() > 0, "De-Serialized encoded bases collection was empty.");
		
		assertTrue(sigma.verify(readExtendedKeyPair.getExtendedPublicKey(), encodedBases), 
				"The de-serialized graph signature could not be self-verified.");
	}
}
