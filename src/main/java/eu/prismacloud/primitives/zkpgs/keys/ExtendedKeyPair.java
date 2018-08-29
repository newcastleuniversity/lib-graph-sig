package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.encoding.GraphEncoding;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.Base;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/** Class representing the extended key pair */
public final class ExtendedKeyPair implements IKeyPair {

	private final SignerPublicKey publicKey;
	private final SignerPrivateKey privateKey;
	private final GraphEncodingParameters graphEncodingParameters;
	private final KeyGenParameters keyGenParameters;
	private final GroupElement baseS;
	private final BigInteger modN;
	private final SignerKeyPair signerKeyPair;
	private final Group qrGroup;
	private final Map<URN, BigInteger> discLogOfBases;
	private ExtendedPublicKey extendedPublicKey;
	private ExtendedPrivateKey extendedPrivateKey;
	private Map<URN, BaseRepresentation> baseRepresentationMap;
	private Map<URN, BigInteger> vertexRepresentatives;
	private BigInteger vertexPrimeRepresentative;
	private Map<URN, BigInteger> labelRepresentatives;
	private GraphEncoding graphEncoding;
//	private GroupElement R_Z;
//	private BigInteger x_RZ;

	/**
	 * Instantiates a new Extended key pair.
	 *
	 * @param signerKeyPair the signer key pair
	 * @param graphEncodingParameters the graph encoding parameters
	 * @param keyGenParameters the key gen parameters
	 */
	public ExtendedKeyPair(
			final SignerKeyPair signerKeyPair,
			final GraphEncodingParameters graphEncodingParameters,
			final KeyGenParameters keyGenParameters) {

		this.signerKeyPair = signerKeyPair;
		this.publicKey = signerKeyPair.getPublicKey();
		this.privateKey = signerKeyPair.getPrivateKey();
		this.graphEncodingParameters = graphEncodingParameters;
		this.keyGenParameters = keyGenParameters;
		this.baseS = signerKeyPair.getPublicKey().getBaseS();
		this.modN = signerKeyPair.getPublicKey().getModN();
		this.qrGroup = publicKey.getQRGroup();
		this.baseRepresentationMap = new HashMap<URN, BaseRepresentation>();
		this.vertexRepresentatives = new HashMap<URN, BigInteger>();
		this.labelRepresentatives = new HashMap<URN, BigInteger>();
		this.discLogOfBases = new HashMap<URN, BigInteger>();
	}

	/**
	 * Gets extended public key.
	 *
	 * @return the extended public key
	 */
	public ExtendedPublicKey getExtendedPublicKey() {
		return extendedPublicKey;
	}

	/** Create extended key pair. */
	public void createExtendedKeyPair() {
		this.extendedPublicKey =
				new ExtendedPublicKey(
						signerKeyPair.getPublicKey(),
						baseRepresentationMap,
						vertexRepresentatives,
						labelRepresentatives,
						graphEncodingParameters);

		this.extendedPrivateKey = new ExtendedPrivateKey(signerKeyPair.getPrivateKey(), discLogOfBases);
	}

	/**
	 * Gets extended private key.
	 *
	 * @return the extended private key
	 */
	public ExtendedPrivateKey getExtendedPrivateKey() {
		return extendedPrivateKey;
	}

	/**
	 * Gets public key.
	 *
	 * @return the public key
	 */
	public SignerPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Gets private key.
	 *
	 * @return the private key
	 */
	public SignerPrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * Setups a new graph encoding.
	 *
	 * @return the graph encoding
	 */
	public void graphEncodingSetup() {

		graphEncoding =
				new GraphEncoding(
						baseRepresentationMap,
						vertexRepresentatives,
						publicKey,
						keyGenParameters,
						graphEncodingParameters);
		graphEncoding.setup();

	}

	/**
	 * Gets graph encoding.
	 *
	 * @return the graph encoding
	 */
	public GraphEncoding getGraphEncoding() {
		return this.graphEncoding;
	}

	/** Certify prime representatives. */
	public void certifyPrimeRepresentatives() {
		Group qrGroup = publicKey.getQRGroup();
		BigInteger x_R_V = qrGroup.createRandomElement().getValue();

		GroupElement R_V = baseS.modPow(x_R_V);

		BaseRepresentation baseV = new BaseRepresentation(R_V, 0, BASE.VERTEX);

		BigInteger x_R_L = qrGroup.createRandomElement().getValue();

		GroupElement R_L = baseS.modPow(x_R_L);

		BaseRepresentation baseL = new BaseRepresentation(R_L, 0, BASE.VERTEX);

		graphEncoding.certify(vertexRepresentatives, baseV, labelRepresentatives, baseL);
	}

	/**
	 * Generate edge baseRepresentationMap.
	 *
	 * @param S the quadratic group generator S
	 */
	public void generateEdgeBases(final GroupElement S) {
		BigInteger x_R_ij;
		GroupElement R_ij;

		for (int j = 0; j < graphEncodingParameters.getL_E(); j++) {
			x_R_ij =
					CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
			R_ij = S.modPow(x_R_ij);

			/* The base representation receives as global index the current 
			 * length of the overall base representation map plus 1, 
			 * making an index counting from 1;
			 */
			int index = baseRepresentationMap.size()+1;
			BaseRepresentation base = new BaseRepresentation(R_ij, index, BASE.EDGE);

			baseRepresentationMap.put(
					URN.createZkpgsURN("baseRepresentationMap.edge.R_E_" + index), base);
			discLogOfBases.put(URN.createZkpgsURN("discretelogs.edge.R_E_" + index), x_R_ij);
		}
	}

	/** Generate bases. */
	public void generateBases() {
		// TODO generateGroupBases(baseS); corresponding method does not work.
		generateVertexBasesWithRandomVertexRepresentatives(baseS);
		generateEdgeBases(baseS);
	}
	
	/**
	 * Generates the map of vertex representatives.
	 * 
	 * <p>The vertex representatives are chosen such that they start with the smallest permissible 
	 * prime value for vertex 0 and enumerate the successive primes to the successive 
	 * vertex representatives.
	 * 
	 * <p> The chosen vertex representatives are guaranteed not to collide with the
	 * label encoding space and are guaranteed to take at most lPrime_V space.
	 * 
	 * @complexity This method is resource-intensive as BigInteger.nextProbablePrime() will be
	 * called l_V times.
	 * 
	 * @throws EncodingException if the graph encoding attempted to create a prime representative
	 * outside of the range designated for vertex encoding. This will only occur if the
	 * graph encoding parameters lPrime_V and l_V are contradicting each other, e.g, if
	 * the encoding bitlength lPrime_V is too small to encode the number of vertices l_V. 
	 */
	public void generateVertexRepresentatives() throws EncodingException {
		BigInteger vertexPrimeRepresentative = graphEncodingParameters.getLeastVertexRepresentative();
		for (int i = 0; i < graphEncodingParameters.getL_V(); i++) {
			
			if (i == 0) {
				// The first vertex representative is chosen as the smallest prime possible.
				vertexPrimeRepresentative = graphEncodingParameters.getLeastVertexRepresentative();
			} else {
				// The subsequent representatives are chosen as the successive next primes.
				// This yields the most space/computation efficient encoding.
				vertexPrimeRepresentative = vertexPrimeRepresentative.nextProbablePrime();
			}
			
			if (!CryptoUtilsFacade.isInRange(vertexPrimeRepresentative, 
					graphEncodingParameters.getLeastVertexRepresentative(), graphEncodingParameters.getUpperBoundVertexRepresentatives())) {
				throw new EncodingException("The graph encoding attempted to "
						+ "create a vertex representative outside of the designated range.");
			}

			vertexRepresentatives.put(
					URN.createZkpgsURN("vertex.representative.e_i_" + i), vertexPrimeRepresentative);
		}
	}

// TODO METHOD FAULTY: Does not generate the right bases
// Z etc. should be part of the SignerKeyPair, not the ExtendedKeyPair
//	private void generateGroupBases(final GroupElement baseS) {
//
//		x_RZ = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
//		R_Z = baseS.modPow(x_RZ);
//
//		discLogOfBases.put(URN.createZkpgsURN("discretelogs.base.R_Z"), x_RZ);
//
//		x_RZ = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
//		R_Z = baseS.modPow(x_RZ);
//
//		discLogOfBases.put(URN.createZkpgsURN("discretelogs.base.R_Z"), x_RZ);
//	}

	/**
	 * Generates a map of a base representation with random vertex prime representatives.
	 * 
	 * <p>The method will lead to an inefficient encoding in that the public vertex 
	 * representatives will be random primes with full message length.
	 *
	 * @param S the quadratic group generator S
	 * @deprecated
	 */
	public void generateVertexBasesWithRandomVertexRepresentatives(final GroupElement S) {
		BigInteger x_Ri;
		GroupElement R_i;

		for (int i = 0; i < graphEncodingParameters.getL_V(); i++) {
			x_Ri = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
			R_i = S.modPow(x_Ri);
			
			/* The base representation receives as global index the current 
			 * length of the overall base representation map plus 1, 
			 * making an index counting from 1;
			 */
			int index = baseRepresentationMap.size()+1;
			
			BaseRepresentation base = new BaseRepresentation(R_i, index, BASE.VERTEX);
			baseRepresentationMap.put(
					URN.createZkpgsURN("baseRepresentationMap.vertex.R_V_" + index), base);

			vertexPrimeRepresentative =
					CryptoUtilsFacade.generateRandomPrime(graphEncodingParameters.getlPrime_L());

			vertexRepresentatives.put(
					URN.createZkpgsURN("vertex.representative.e_i_" + i), vertexPrimeRepresentative);

			discLogOfBases.put(URN.createZkpgsURN("discretelogs.vertex.R_V_" + index), x_Ri);
		}
	}
	
	/**
	 * Generates a map of a base representation drawn uniformly at random from the signer's 
	 * setup group. The discrete logarithms of the bases with respect to the main base S
	 * are stored for the signer's extended private key.
	 *
	 * @param S the quadratic group generator S
	 * 
	 * @complexity The method is computationally intensive as it is computing l_V modular exponentiations
	 * in the signer's group.
	 * 
	 * @post The vertex bases are stored in the keypair's baseRepresentationMap.
	 * The corresponding discrete logarithms are stored in DiscLogOfBases.
	 */
	public void generateVertexBases(final GroupElement S) {
		BigInteger x_Ri;
		GroupElement R_i;

		for (int i = 0; i < graphEncodingParameters.getL_V(); i++) {
			
			x_Ri = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
			R_i = S.modPow(x_Ri);
			
			/* The base representation receives as global index the current 
			 * length of the overall base representation map plus 1, 
			 * making an index counting from 1;
			 */
			int index = baseRepresentationMap.size()+1;
			
			BaseRepresentation base = new BaseRepresentation(R_i, index, BASE.VERTEX);
			baseRepresentationMap.put(
					URN.createZkpgsURN("baseRepresentationMap.vertex.R_V_" + index), base);
			
			discLogOfBases.put(URN.createZkpgsURN("discretelogs.vertex.R_V_" + index), x_Ri);
		}
	}

	/**
	 * Gets label representatives.
	 *
	 * @return the label representatives
	 */
	public Map<URN, BigInteger> getLabelRepresentatives() {
		return labelRepresentatives;
	}

	private void createExtendedPrivateKey() {
		this.extendedPrivateKey = new ExtendedPrivateKey(privateKey, discLogOfBases);
	}

	public KeyGenParameters getKeyGenParameters() {
		return this.keyGenParameters;
	}

	@Override
	public SignerKeyPair getBaseKeyPair() {
		return this.signerKeyPair;
	}
}
