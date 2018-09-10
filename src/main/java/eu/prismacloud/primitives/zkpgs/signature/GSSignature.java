package eu.prismacloud.primitives.zkpgs.signature;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroup;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * The GSSignature class encapsulates the algebraic structure a graph signature along with methods
 * to verify itself as well as to blind itself, returning an unlinkably randomized version of the
 * same graph signature.
 *
 * <p>While a graph signature itself is a triple of {@code (A, e, v)}, the graph signature is valid
 * with respect to a SignerPublicKey and a GraphRepresentation with an encoding specified in the
 * signer's ExtendedPublicKey.
 */
public class GSSignature implements Serializable {
	/** */
	private static final long serialVersionUID = 4811571232342405043L;

	private final SignerPublicKey signerPublicKey;
	private final KeyGenParameters keyGenParameters;
	private final BigInteger ePrimeOffset;
	private final GroupElement A;
	private final BigInteger e;
	private final BigInteger ePrime; // ePrime is e minus the l_E offset
	private final BigInteger v;
	private BaseCollection encodedBases;
	
	public GSSignature(
			final ExtendedPublicKey extendedPublicKey,
			GSCommitment U,
			BaseCollection encodedBases,
			GroupElement A,
			BigInteger e,
			BigInteger v) {
		this.signerPublicKey = extendedPublicKey.getPublicKey();
		this.keyGenParameters = signerPublicKey.getKeyGenParameters();
		this.ePrimeOffset = NumberConstants.TWO.getValue().pow(this.keyGenParameters.getL_e() - 1);
		this.A = A;
		this.e = e;
		this.ePrime = e.subtract(ePrimeOffset);
		this.v = v;
		this.encodedBases = encodedBases;
	}

	public GSSignature(
			final SignerPublicKey signerPublicKey, final GroupElement A, final BigInteger e, final BigInteger v) {
		this.signerPublicKey = signerPublicKey;
		this.keyGenParameters = signerPublicKey.getKeyGenParameters();
		this.ePrimeOffset = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1);
		this.A = A;
		this.e = e;
		this.ePrime = e.subtract(ePrimeOffset);
		this.v = v;
		this.encodedBases = new BaseCollectionImpl();
	}

	public GroupElement getA() {
		return A;
	}

	public BigInteger getE() {
		return e;
	}

	public BigInteger getEPrime() {
		return ePrime;
	}

	public BigInteger getEPrimeOffset() {
		return ePrimeOffset;
	}

	public BigInteger getV() {
		return v;
	}

	/**
	 * Computes a blinding on this graph signature, which will yield a new uniformly at random chosen
	 * A' and corresponding signature components {@code e} and {@code v}.
	 *
	 * <p>The blinded signature is a signature on the same graph as the original signature.
	 *
	 * @return GraphSignature with blinded public base {@code A'}.
	 */
	public GSSignature blind() {
		int r_ALength = keyGenParameters.getL_n() + keyGenParameters.getL_statzk();
		BigInteger r_A = CryptoUtilsFacade.computeRandomNumber(r_ALength);
		GroupElement APrime = A.multiply(signerPublicKey.getBaseS().modPow(r_A));
		BigInteger vPrime = v.subtract(e.multiply(r_A));
		GSSignature blindedSignature = new GSSignature(this.signerPublicKey, APrime, e, vPrime);
		blindedSignature.setEncodedBases(encodedBases);
		return blindedSignature;
	}

	/**
	 * Verifies that this graph signature is valid with respect to a given extended public key and
	 * graph encoding.
	 *
	 * <p>The method checks that this graph signature fulfills all requirements on its tuple {@code
	 * (A, e, v)} and verifies correctly as {@code Z = R_i^enc[G] A^e S^v (mod N)}.
	 *
	 * @param epk extended public key
	 * @param bc collection of bases representing a graph
	 * @return {@code true} if this graph signature verifies correctly for the given Extended Public
	 *     Key and Graph Encoding
	 */
	public boolean verify(ExtendedPublicKey epk, BaseCollection bc) {
		QRGroup qrGroup = (QRGroup) epk.getPublicKey().getQRGroup();
		QRElement Y = (QRElement) qrGroup.getOne();
		BaseIterator baseIter = bc.createIterator(BASE.ALL);
		for (BaseRepresentation baseRepresentation : baseIter) {
			if (baseRepresentation.getBaseType().equals(BASE.BASES)) continue;
			Y = Y.multiply(baseRepresentation.getBase().modPow(baseRepresentation.getExponent()));
		}
		return verify(epk.getPublicKey(), Y);
	}

	/**
	 * Verifies that this graph signature is valid with respect to a given signer public key and a
	 * single message {@code m} to be encoded on base {@code R_0}.
	 *
	 * <p>The method checks that this graph signature fulfills all requirements on its tuple {@code
	 * (A, e, v)} and verifies correctly as {@code Z = R_0^m A^e S^v (mod N)}.
	 *
	 * @param pk the signer's public key
	 * @param m single message
	 * @return {@code true} if this graph signature verifies correctly for the given Signer Public Key
	 *     and a message {@code m}.
	 */
	public boolean verify(SignerPublicKey pk, BigInteger m) {
		GroupElement msgR = pk.getBaseR_0().modPow(m);
		// Delegates verification to verify() on group element Y.
		return verify(pk, msgR);
	}

	/**
	 * Verifies that this graph signature is valid with respect to a given signer public key and a
	 * group element {@code Y}. The idea is that another method provides Y as encoding of one or
	 * multiple messages with bases R_i chosen internally.
	 *
	 * <p>The method checks that this graph signature fulfills all requirements on its tuple {@code
	 * (A, e, v)} and verifies correctly as {@code Z = Y A^e S^v (mod N)}.
	 *
	 * @param pk the signer's public key
	 * @param Y the group element
	 * @return {@code true} if this graph signature verifies correctly for the given Signer Public Key
	 *     and a message-encoding group element {@code Y}.
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
	 * Checks whether the prime number e included in this graph signature is valid, that is, is a
	 * prime number of appropriate length.
	 *
	 * @return {@code true} if {@code e} is likely a prime of appropriate length.
	 */
	public boolean hasValidE() {
		return (this.e != null)
				&& (this.e.isProbablePrime(keyGenParameters.getL_pt()))
				&& (this.hasValidLengthE());
	}

	/**
	 * Checks that the prime number component of the graph signature {@code e} has the specified
	 * length.
	 *
	 * @return {@code true} if {@code e} has the correct length
	 */
	public boolean hasValidLengthE() {
		return (this.e.compareTo(this.keyGenParameters.getLowerBoundE()) > 0)
				&& (this.e.compareTo(this.keyGenParameters.getUpperBoundE()) < 0);
	}

	/**
	 * Checks that the blinding randomness {@code v} has the correct length.
	 *
	 * @return true if the bit length of {@code v} is as specified.
	 */
	public boolean hasValidLengthV() {
		return (this.v.compareTo(this.keyGenParameters.getLowerBoundV()) > 0)
				&& (this.v.compareTo(this.keyGenParameters.getUpperBoundV()) < 0);
	}

	public BaseCollection getEncodedBases() {
		return encodedBases;
	}

	public void setEncodedBases(BaseCollection encodedBases) {
		this.encodedBases = encodedBases;
	}
}
