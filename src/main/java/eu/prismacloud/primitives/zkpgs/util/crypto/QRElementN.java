package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;
import java.util.List;

/**
 * Class that represents an element in Quadratic Residues group without knowing the factorization of
 * modulus N.
 */
public class QRElementN extends QRElement {
	/**
	 * 
	 */
	private static final long serialVersionUID = 6839986884678075378L;


	private final QRGroupN qrGroup;
	private final BigInteger value;

	/**
	 * Instantiates a new QR element n.
	 * 
	 * The corresponding group cannot efficiently check whether an element is actually a Quadratic
	 * Residue. BigInteger values provided must be in QR by construction.
	 *
	 * @param qrGroup the QR group
	 * @param value the number
	 */
	public QRElementN(final QRGroupN qrGroup, final BigInteger value) {
		super(qrGroup, value);

		this.qrGroup = qrGroup;
		this.value = value;
	}

	/**
	 * Instantiates a new QR element n.
	 * 
	 * Without factorization of the modulus, the constructor cannot efficiently check whether a
	 * value provided is actually a Quadratic Residue. Hence, the BigInteger supplied must be
	 * in QR by construction.
	 *
	 * @param group the group
	 * @param value the value
	 */
	public QRElementN(final Group group, final BigInteger value) {
		super(group, value);

		if(!(group instanceof QRGroup)) {
			throw new IllegalArgumentException("The provided group is not a Quadratic Residues group.");
		} else if (group instanceof QRGroupN) {
			this.qrGroup = (QRGroupN) group;
		} else if (group instanceof QRGroupPQ) {
			QRGroupPQ groupPQ = (QRGroupPQ) group;
			QRGroupN absGroup = groupPQ.getPublicQRGroup();
			this.qrGroup = absGroup;
		} else {
			throw new IllegalArgumentException("The provided group is not a known type of Quadratic Residues realizations.");
		}

		this.value = value;
	}

	@Override
	public Group getGroup() {
		return qrGroup;
	}

	@Override
	public BigInteger getValue() {
		return value;
	}

	@Override
	public QRElementN multiply(GroupElement multiplier) {
		if (!this.getGroup().equals(multiplier.getGroup())) {
			throw new UnsupportedOperationException("The two elements are from different groups.");
			// TODO Graceful exit strategy if elements are not part of the same group?
			// Exception
		}

		BigInteger product = (this.value.multiply(multiplier.getValue())).mod(this.getGroup().getModulus());
		return new QRElementN(this.getGroup(), product);
	}

	@Override
	public QRElement modPow(BigInteger exponent) {
		return super.modPow(exponent);
	}

	/**
	 * Multi base exp big integer.
	 *
	 * @param bases the bases
	 * @param exponents the exponents
	 * @return the big integer
	 */
	public QRElementN multiBaseExp(List<GroupElement> bases, List<BigInteger> exponents) {
		return (QRElementN) super.multiBaseExp(bases, exponents);
	}

	@Override
	public String toString() {
		final StringBuilder sb =
				new StringBuilder("eu.prismacloud.primitives.zkpgs.util.crypto.QRElementN{");
		sb.append("qrGroup=").append(qrGroup);
		sb.append(", number=").append(value);
		sb.append(", group=").append(getGroup());
		sb.append(", value=").append(getValue());
		sb.append('}');
		return sb.toString();
	}
}
