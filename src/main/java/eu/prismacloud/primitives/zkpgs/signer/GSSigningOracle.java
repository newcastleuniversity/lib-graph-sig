package eu.prismacloud.primitives.zkpgs.signer;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;

import org.jgrapht.Graph;

/**
 * Oracle for Graph Signatures computed non-interactively with a valid SignerKeyPair, but without
 * involvement of a Recipient. The GSSigningOracle determines a master secret key randomly.
 */
public class GSSigningOracle {
	private final SignerKeyPair signerKeyPair;
	private final KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private final GroupElement baseS;
	private final GroupElement baseZ;

	/**
	 * Constructor for the GSSigningOracle for bare signatures without graph encoding.
	 *
	 * @param skp the SignerKeyPair to be used
	 * @param keyGenParameters parameters matching the SignerKeyPair
	 */
	public GSSigningOracle(SignerKeyPair skp, KeyGenParameters keyGenParameters) {
		this.signerKeyPair = skp;
		this.keyGenParameters = keyGenParameters;
		this.baseS = signerKeyPair.getPublicKey().getBaseS();
		this.baseZ = signerKeyPair.getPublicKey().getBaseZ();
	}

	/**
	 * Constructor for the GSSigningOracle preparing for signatures under a specific graph encoding.
	 *
	 * @param skp the SignerKeyPair to be used
	 * @param keyGenParameters Parameters matching the SignerKeyPair
	 * @param graphEncodingParameters Specification of the graph encoding
	 */
	public GSSigningOracle(
			SignerKeyPair skp,
			KeyGenParameters keyGenParameters,
			GraphEncodingParameters graphEncodingParameters) {
		this.signerKeyPair = skp;
		this.keyGenParameters = keyGenParameters;
		this.graphEncodingParameters = graphEncodingParameters;
		this.baseS = signerKeyPair.getPublicKey().getBaseS();
		this.baseZ = signerKeyPair.getPublicKey().getBaseZ();
	}

	/**
	 * Constructor for the GSSigningOracle preparing for signatures under an
	 * ExtendedKeyPair.
	 *
	 * @param ekp the ExtendedKeyPair to be used
	 */
	public GSSigningOracle(ExtendedKeyPair ekp) {
		this.signerKeyPair = ekp.getBaseKeyPair();
		this.keyGenParameters = ekp.getKeyGenParameters();
		this.graphEncodingParameters = ekp.getGraphEncodingParameters();
		this.baseS = signerKeyPair.getPublicKey().getBaseS();
		this.baseZ = signerKeyPair.getPublicKey().getBaseZ();
	}

	/**
	 * Creates a fresh signature with uniformly random blinding randomness, on a GroupElement Y,
	 * oblivious of the structure of Y.
	 *
	 * @param Y GroupElement to be signed
	 * @return valid GSSignature
	 */
	public GSSignature sign(GroupElement Y) {
		BigInteger v = generateBlindingV();
		GroupElement blindingS = this.baseS.modPow(v);

		GroupElement result = Y.multiply(blindingS);

		GroupElement Q = this.baseZ.multiply(result.modInverse());
		BigInteger e = generateSigningE();

		GroupElement A = computeA(Q, e);

		return new GSSignature(this.signerKeyPair.getPublicKey(), A, e, v);
	}

	/**
	 * Creates a fresh signature with uniformly random blinding randomness, on a zero message m, but
	 * without graph encoding.
	 *
	 * @param m BigInteger message for zero's base
	 * @return valid GSSignature
	 */
	public GSSignature sign(BigInteger m) {
		GroupElement mEncoded = this.signerKeyPair.getPublicKey().getBaseR_0().modPow(m);

		return this.sign(mEncoded);
	}

	/**
	 * Creates a fresh signature with uniformly random blinding randomness, 
	 * on an arbitrary BaseCollection.
	 * 
	 * <p>The method iterates over all bases of the base collection, computing the
	 * exponentiation over all bases and, finally, submits the product to
	 * the signing.
	 *
	 * @param baseCollection BaseCollection to be signed
	 * @return valid GSSignature
	 */
	public GSSignature sign(BaseCollection baseCollection) {
		GroupElement basesEncoded = signerKeyPair.getPublicKey().getQRGroup().getOne();
		BaseIterator baseIter = baseCollection.createIterator(BASE.ALL);
		while (baseIter.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) baseIter.next();
			basesEncoded = basesEncoded.multiply(base.getBase().modPow(base.getExponent()));
		}

		return this.sign(basesEncoded);
	}
	
	/**
	 * Creates a fresh signature with uniformly random blinding randomness, 
	 * on a given graph represented as (encoded) GraphRepresentation.
	 *
	 * @param graphRepresentation A graphRepresentation, readily encoded, to be signed.
	 * @return valid GSSignature
	 */
	public GSSignature sign(GraphRepresentation graphRepresentation) {
		BaseCollection collection = graphRepresentation.getEncodedBaseCollection();

		return this.sign(collection);
	}

	/**
	 * Generates the blinding randomness faithfully to the randomness combined by Recipient and
	 * signer, that is <tt>v = v' + v''</tt>.
	 *
	 * @return BigInteger Blinding Randomness v
	 */
	public BigInteger generateBlindingV() {
		BigInteger vPrime =
				CryptoUtilsFacade.computeRandomNumberMinusPlus(
						this.keyGenParameters.getL_n() + this.keyGenParameters.getL_statzk());
		BigInteger vbar = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);
		BigInteger vPrimePrime =
				NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);
		BigInteger v = vPrime.add(vPrimePrime);
		return v;
	}

	/**
	 * Generates a prime exponent e for signing.
	 *
	 * @return Probable Prime e in appropriate range.
	 */
	public BigInteger generateSigningE() {
		BigInteger e =
				CryptoUtilsFacade.computePrimeInRange(
						keyGenParameters.getLowerBoundE(), keyGenParameters.getUpperBoundE());
		return e;
	}

	/**
	 * Completes the signature by computing A.
	 *
	 * @param Q the prepared group element for signing
	 * @param e prime exponent part of the signature
	 * @return A GroupElement to complete the signature
	 */
	public GroupElement computeA(GroupElement Q, BigInteger e) {
		BigInteger pPrime = signerKeyPair.getPrivateKey().getpPrime();
		BigInteger qPrime = signerKeyPair.getPrivateKey().getqPrime();

		BigInteger d = e.modInverse(pPrime.multiply(qPrime));
		GroupElement A = Q.modPow(d);
		return A;
	}
}
