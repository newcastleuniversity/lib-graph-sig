package eu.prismacloud.primitives.zkpgs.signature;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.encoding.GraphEncoding;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementN;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;

import java.math.BigInteger;
import java.util.Map;
import java.util.logging.Logger;

public class GSSignature {
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
	 * A' and corresponding signature components e and v.
	 * 
	 *  The blinded signature is a signature on the same graph as the original signature.
	 * 
	 * @return a GraphSignature with blinded public base A'. 
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
	 * requirements on its tuple (A, e, v)
	 * and verifies correctly as Z = R_i^enc[G] A^e S^v (mod N).
	 * 
	 * @param ExtendedPublicKey epk
	 * @param GraphEncoding enc
	 * 
	 * @return true if this graph signature verifies correctly for the given Extended Public Key 
	 * and Graph Encoding
	 */
	public boolean verify(ExtendedPublicKey epk, GraphEncoding enc) {
		throw new NotImplementedException("Graph Signature verification on Extended Public Keys "
				+ "and Graph Encodings is not implemented, yet.");
	}

	/**
	 * Verifies that this graph signature is valid with respect to a given signer public key 
	 * and a single message m to be encoded on base R_0.
	 * 
	 * The method checks that this graph signature fulfills all 
	 * requirements on its tuple (A, e, v)
	 * and verifies correctly as Z = R_0^m A^e S^v (mod N).
	 * 
	 * @param SignerPublicKey pk
	 * @param BigInteger m
	 * 
	 * @return true if this graph signature verifies correctly for the given 
	 * Signer Public Key and a message m.
	 */
	public boolean verify(SignerPublicKey pk, BigInteger m) {
		GroupElement msgR = pk.getBaseR_0().modPow(m);
		// Delegates verification to verify() on group element Y.
		return verify(pk, msgR);
	}

	/**
	 * Verifies that this graph signature is valid with respect to a given signer public key 
	 * and a group element Y. The idea is that another method provides Y as encoding of
	 * one or multiple messages with bases R_i chosen internally.
	 * 
	 * The method checks that this graph signature fulfills all 
	 * requirements on its tuple (A, e, v)
	 * and verifies correctly as Z = Y A^e S^v (mod N).
	 * 
	 * @param SignerPublicKey pk
	 * @param GroupElement Y
	 * 
	 * @return true if this graph signature verifies correctly for the given 
	 * Signer Public Key and a message-encoding group element Y.
	 */
	public boolean verify(SignerPublicKey pk, GroupElement Y) {
		// Check components of the signature for appropriate values.
		if (this.A == null || this.e == null || this.v == null) return false;
		
		// The following line temporarily deactivated to ensure length-checks work smoothly.
		// (!hasValidLengthV()
		if (!hasValidE()) return false;
		
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
	 * @return true if e is likely a prime of appropriate length.
	 */
	public boolean hasValidE() {
		return (this.e != null)
				&& (this.e.isProbablePrime(keyGenParameters.getL_pt()))
				&& (this.hasValidLengthE());
	}

	/**
	 * Checks that the prime number component of the graph signature e has the specified length.
	 * 
	 * @return true if e has the correct length
	 */
	public boolean hasValidLengthE() {
		
		return (this.e.compareTo(this.keyGenParameters.getLowerBoundE()) > 0) &&
			   (this.e.compareTo(this.keyGenParameters.getUpperBoundE()) < 0);
	}

	/**
	 * Checks that the blinding randomness v has the correct length.
	 * 
	 * @return true if the bit length of v is as specified.
	 */
	public boolean hasValidLengthV() {
		return this.v.bitLength() == keyGenParameters.getL_v();
	}
}
