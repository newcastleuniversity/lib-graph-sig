package eu.prismacloud.primitives.zkpgs.signature;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Map;
import java.util.logging.Logger;

/**
 * The GSSignature class encapsulates the algebraic structure a graph signature along
 * with methods to verify itself as well as to blind itself, returning an unlinkably
 * randomized version of the same graph signature.
 * 
 * While a graph signature itself is a triple of <code>(A, e, v)</code>,
 * the graph signature is valid with respect to a SignerPublicKey and a
 * GraphRepresentation with an encoding specified in the signer's
 * ExtendedPublicKey.
 * 
 */
public class GSSignature implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 4811571232342405043L;
	private static Logger gslog = GSLoggerConfiguration.getGSlog();
	private final SignerPublicKey signerPublicKey;
	private GSCommitment U;
	private final KeyGenParameters keyGenParameters;
	private final GroupElement A;
	private final BigInteger e;
	private final BigInteger v;
	private GroupElement Q;
	private BigInteger vbar;
	private BigInteger vPrimePrime;
	private final GroupElement baseS;
	private final GroupElement baseZ;
	private BigInteger modN;
	private Map<URN, BaseRepresentation> encodedEdges;
	private BaseCollection encodedBases;
	private GroupElement R_i;
	private GroupElement R_i_j;
	private BigInteger d;
	private BigInteger eInverse;

	public GSSignature(
			final ExtendedPublicKey extendedPublicKey,
			GSCommitment U,
			BaseCollection encodedBases,
			KeyGenParameters keyGenParameters,
			GroupElement A, BigInteger e, BigInteger v) {
		this.signerPublicKey = extendedPublicKey.getPublicKey();
		this.A = A;
		this.e = e;
		this.v = v;
		this.U = U;
		this.encodedBases = encodedBases;
		this.keyGenParameters = keyGenParameters;
		this.baseS = this.signerPublicKey.getBaseS();
		this.baseZ = this.signerPublicKey.getBaseZ();
	}

	public GSSignature(final SignerPublicKey signerPublicKey, 
			GroupElement A, BigInteger e, BigInteger v) {
		this.signerPublicKey = signerPublicKey;
		this.keyGenParameters = signerPublicKey.getKeyGenParameters();
		this.baseS = signerPublicKey.getBaseS();
		this.baseZ = signerPublicKey.getBaseZ();
		this.A = A;
		this.e = e;
		this.v = v;
	}

	public GroupElement getA() {
		return A;
	}

	public BigInteger getE() {
		return e;
	}

	public BigInteger getV() {
		return v;
	}

	// TODO Lift computations to GSSigner; GSSignature should not have knowledge of the sk.

	/** 
	 * Computes a blinding on this graph signature, which will yield a new uniformly at random chosen
	 * A' and corresponding signature components <code>e</code> and <code>v</code>.
	 * 
	 *  The blinded signature is a signature on the same graph as the original signature.
	 * 
	 * @return GraphSignature with blinded public base <code>A'</code>. 
	 */
	public GSSignature blind() {
		int r_ALength = keyGenParameters.getL_n() + keyGenParameters.getL_statzk();
		BigInteger r_A = CryptoUtilsFacade.computeRandomNumber(r_ALength);
		GroupElement APrime = A.multiply(baseS.modPow(r_A));
		BigInteger vPrime = v.subtract(e.multiply(r_A));
		BigInteger ePrime =
				e.subtract(NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1));
		return new GSSignature(this.signerPublicKey,
				APrime, ePrime, vPrime);
	}

	/**
	 * Verifies that this graph signature is valid with respect to a given extended public key
	 * and graph encoding.
	 * 
	 * The method checks that this graph signature fulfills all 
	 * requirements on its tuple <code>(A, e, v)</code>
	 * and verifies correctly as <code>Z = R_i^enc[G] A^e S^v (mod N)</code>.
	 * 
	 * @param ExtendedPublicKey epk
	 * @param GraphEncoding enc
	 * 
	 * @return <code>true</code> if this graph signature verifies correctly for the given Extended Public Key 
	 * and Graph Encoding
	 */
	public boolean verify(ExtendedPublicKey epk, GraphRepresentation gr) {
		GroupElement Y = epk.getPublicKey().getQRGroup().getOne();
		BaseIterator baseIter = gr.getEncodedBaseCollection().createIterator(BASE.ALL);
		for (BaseRepresentation baseRepresentation : baseIter) {
			Y = Y.multiply(baseRepresentation.getBase().modPow(baseRepresentation.getExponent()));
		}
		
		return verify(epk.getPublicKey(), Y);
	}

	/**
	 * Verifies that this graph signature is valid with respect to a given signer public key 
	 * and a single message <code>m</code> to be encoded on base <code>R_0</code>.
	 * 
	 * The method checks that this graph signature fulfills all 
	 * requirements on its tuple <code>(A, e, v)</code>
	 * and verifies correctly as <code>Z = R_0^m A^e S^v (mod N)</code>.
	 * 
	 * @param SignerPublicKey pk
	 * @param BigInteger m
	 * 
	 * @return <code>true</code> if this graph signature verifies correctly for the given 
	 * Signer Public Key and a message <code>m</code>.
	 */
	public boolean verify(SignerPublicKey pk, BigInteger m) {
		GroupElement msgR = pk.getBaseR_0().modPow(m);
		// Delegates verification to verify() on group element Y.
		return verify(pk, msgR);
	}

	/**
	 * Verifies that this graph signature is valid with respect to a given signer public key 
	 * and a group element <code>Y</code>. The idea is that another method provides Y as encoding of
	 * one or multiple messages with bases R_i chosen internally.
	 * 
	 * The method checks that this graph signature fulfills all 
	 * requirements on its tuple <code>(A, e, v)</code>
	 * and verifies correctly as <code>Z = Y A^e S^v (mod N)</code>.
	 * 
	 * @param SignerPublicKey pk
	 * @param GroupElement Y
	 * 
	 * @return <code>true</code> if this graph signature verifies correctly for the given 
	 * Signer Public Key and a message-encoding group element <code>Y</code>.
	 */
	public boolean verify(SignerPublicKey pk, GroupElement Y) {
		// Check components of the signature for appropriate values.
		if (this.A == null || this.e == null || this.v == null) return false;
		
		// The following line temporarily deactivated to ensure length-checks work smoothly.
		if (!hasValidLengthV() || !hasValidE()) return false;
		
		// Computes hatZ = Y A^e S^v (mod N)
		GroupElement hatZ = pk.getBaseS().modPow(this.v);
		GroupElement hatA = this.A.modPow(this.e);
		hatZ = hatZ.multiply(hatA).multiply(Y);
		
		// Checks that hatZ
		return hatZ.equals(pk.getBaseZ());
	}

	/**
	 * Checks whether the prime number e included in this graph signature is valid,
	 * that is, is a prime number of appropriate length.
	 * 
	 * @return <code>true</code> if <code>e</code> is likely a prime of appropriate length.
	 */
	public boolean hasValidE() {
		return (this.e != null)
				&& (this.e.isProbablePrime(keyGenParameters.getL_pt()))
				&& (this.hasValidLengthE());
	}

	/**
	 * Checks that the prime number component of the graph signature <code>e</code> has the specified length.
	 * 
	 * @return <code>true</code> if <code>e</code> has the correct length
	 */
	public boolean hasValidLengthE() {
		
		return (this.e.compareTo(this.keyGenParameters.getLowerBoundE()) > 0) &&
			   (this.e.compareTo(this.keyGenParameters.getUpperBoundE()) < 0);
	}

	/**
	 * Checks that the blinding randomness <code>v</code> has the correct length.
	 * 
	 * @return true if the bit length of <code>v</code> is as specified.
	 */
	public boolean hasValidLengthV() {
		return (this.v.compareTo(this.keyGenParameters.getLowerBoundV()) > 0) &&
		   (this.v.compareTo(this.keyGenParameters.getUpperBoundV()) < 0);
	}
}
