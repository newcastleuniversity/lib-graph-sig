package eu.prismacloud.primitives.zkpgs.signer;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.graph.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;

/**
 * Oracle for Graph Signatures computed non-interactively with a valid SignerKeyPair, but without
 * involvement of a Recipient. The GSSigningOracle determines a master secret key randomly.
 */
public class GSSigningOracle {
	private final SignerKeyPair signerKeyPair;
	private final KeyGenParameters keyGenParameters;
	@SuppressWarnings("unused")
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
	
		BaseRepresentation base = new BaseRepresentation(this.signerKeyPair.getPublicKey().getBaseR_0(), -1, BASE.BASE0);
		base.setExponent(m);
		BaseCollection collection = new BaseCollectionImpl();
		collection.add(base);

		GSSignature sigma = this.sign(mEncoded);
		
		sigma.setEncodedBases(collection);
		return sigma;
	}

	/**
	 * Creates a fresh signature with uniformly random blinding randomness, 
	 * on an arbitrary BaseCollection. The signature will include R_0 if present.
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
		BaseIterator vertexIter = baseCollection.createIterator(BASE.VERTEX);
		while (vertexIter.hasNext()) {
			BaseRepresentation vertexBase = vertexIter.next();
			if (vertexBase.getBase() != null && vertexBase.getExponent() != null) {
				basesEncoded = basesEncoded.multiply(vertexBase.getBase().modPow(vertexBase.getExponent()));
			}
		}
		
		BaseIterator edgeIter = baseCollection.createIterator(BASE.EDGE);
		while (edgeIter.hasNext()) {
			BaseRepresentation edgeBase = edgeIter.next();
			if (edgeBase.getBase() != null && edgeBase.getExponent() != null) {
				basesEncoded = basesEncoded.multiply(edgeBase.getBase().modPow(edgeBase.getExponent()));
			}
		}
		
		boolean completedBase0 = false;;
		BaseIterator baseR0Iter = baseCollection.createIterator(BASE.BASE0);
		for (BaseRepresentation r0Base : baseR0Iter) {
			// Testing that the base R_0 is only gone through once.
			if (completedBase0) throw new IllegalStateException("The Base R_0 responsible for "
					+ "encoding the master secret key msk should only be included once on a signature.");
			completedBase0 = true;
			
			if (r0Base.getBase() != null && r0Base.getExponent() != null) {
				basesEncoded = basesEncoded.multiply(r0Base.getBase().modPow(r0Base.getExponent()));
			}
		}
		
		boolean completedBaseR = false;
		BaseIterator baseRIter = baseCollection.createIterator(BASE.BASER);
		for (BaseRepresentation baseR : baseRIter) {
			// Testing that the base R is only gone through once.
			if (completedBaseR) throw new IllegalStateException("The Base R should only be included once on a signature.");
			completedBaseR = true;
			
			if (baseR.getBase() != null && baseR.getExponent() != null) {
				basesEncoded = basesEncoded.multiply(baseR.getBase().modPow(baseR.getExponent()));
			}
		}

		GSSignature sigma = this.sign(basesEncoded);
		sigma.setEncodedBases(baseCollection);
		return sigma;
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

		GSSignature sigma = this.sign(collection);
		sigma.setGraphRepresentation(graphRepresentation);
		return sigma;
		
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
		BigInteger pPrime = signerKeyPair.getPrivateKey().getPPrime();
		BigInteger qPrime = signerKeyPair.getPrivateKey().getQPrime();

		BigInteger d = e.modInverse(pPrime.multiply(qPrime));
		GroupElement A = Q.modPow(d);
		return A;
	}
	
	/**
	 * Establishes Q from a given signature.
	 * 
	 * @param sigma GSSignature to be analyzed.
	 * 
	 * @return Q
	 */
	public GroupElement computeQforSignature(GSSignature sigma) {
		GroupElement signatureContent = signerKeyPair.getPublicKey().getBaseS().modPow(sigma.getV());
		
		BaseIterator baseIterator = sigma.getEncodedBases().createIterator(BASE.ALL);
		for (BaseRepresentation base : baseIterator) {
			signatureContent = signatureContent.multiply(base.getBase().modPow(base.getExponent()));
		}
		
		GroupElement invertedContent = signatureContent.modInverse();
		
		return signerKeyPair.getPublicKey().getBaseZ().multiply(invertedContent);
	}
	
	/**
	 * Obtains the secret d for a given GSSignature.
	 * 
	 * @param sigma GSSignature to be reverse engineered.
	 * 
	 * @return secret exponent d.
	 */
	public BigInteger computeDforSignature(GSSignature sigma) {
		BigInteger pPrime = signerKeyPair.getPrivateKey().getPPrime();
		BigInteger qPrime = signerKeyPair.getPrivateKey().getQPrime();

		return sigma.getE().modInverse(pPrime.multiply(qPrime));
	}
}
