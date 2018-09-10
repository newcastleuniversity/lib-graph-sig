package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroup;
import java.io.Serializable;
import java.math.BigInteger;

public class SignerPrivateKey implements Serializable, IPrivateKey {
	private static final long serialVersionUID = -9134821806862114638L;

	private final KeyGenParameters keyGenParameters;

	private final BigInteger p;
	/** Safe prime <tt>q = 2*q' + 1</tt>. */
	private final BigInteger q;

	private final BigInteger x_r;
	private final BigInteger x_r0;
	/** Safe prime <tt>p'</tt>. */
	private final BigInteger pPrime;
	/** Safe prime <tt>q'</tt>. */
	private final BigInteger qPrime;

	private final BigInteger x_Z;
	private final QRGroup qrGroup;

	private final BigInteger order;

	public SignerPrivateKey(
			final BigInteger p,
			final BigInteger p_prime,
			final BigInteger q,
			final BigInteger q_Prime,
			final BigInteger x_R,
			final BigInteger x_R0,
			final BigInteger x_Z,
			final QRGroup qrGroup,
			final KeyGenParameters keyGenParameters) {

		this.keyGenParameters = keyGenParameters;

		this.p = p;
		this.pPrime = p_prime;
		this.q = q;
		this.qPrime = q_Prime;
		this.x_r = x_R;
		this.x_r0 = x_R0;
		this.x_Z = x_Z;
		this.qrGroup = qrGroup;
		this.order = this.pPrime.multiply(this.qPrime);
	}

	public BigInteger getPPrime() {
		return pPrime;
	}

	public BigInteger getQPrime() {
		return qPrime;
	}

	public BigInteger getX_r() {
		return x_r;
	}

	public BigInteger getX_r0() {
		return x_r0;
	}

	public BigInteger getX_rZ() {
		return x_Z;
	}

	public QRGroup getQRGroup() {
		return qrGroup;
	}

	public KeyGenParameters getKeyGenParameters() {
		return this.keyGenParameters;
	}

	public BigInteger getP() {
		return p;
	}

	public BigInteger getQ() {
		return q;
	}
	
	public BigInteger getOrder() {
		return this.order;
	}
}
