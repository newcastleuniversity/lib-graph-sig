package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;
import java.util.List;

/**
 * This class represents an element of a group G with prime order,
 * which is a subgroup of Z^{*}_{p} where p is a prime number.
 */
public class PrimeOrderGroupElement extends GroupElement {
	private final PrimeOrderGroup group;
	private final BigInteger value;
	private BigInteger order;

	/**
	 * Instantiates a new element in group G. Evaluates if the group instance provided is a group G.
	 *
	 * @param group the group the element belongs to
	 * @param value the value of the element in the group
	 */
	public PrimeOrderGroupElement(final PrimeOrderGroup group, final BigInteger value) {
		if (!(group instanceof PrimeOrderGroup)) {
			throw new IllegalArgumentException("The group provided does not match group G");
		}
		this.group = group;
		this.value = value;
	}

	@Override
	public Group getGroup() {
		return this.group;
	}

	@Override
	public BigInteger getElementOrder() throws UnsupportedOperationException {
		// TODO check if the order can be computed efficiently for the group element
		return this.order;
	}

	@Override
	public boolean isOrderKnown() {
		// TODO check if the order of the group element in G is known
		return false;
	}

	@Override
	public BigInteger getValue() {
		return this.value;
	}

	@Override
	public PrimeOrderGroupElement modPow(final BigInteger exponent) {
		BigInteger result = this.value.modPow(exponent, this.getGroup().getModulus());

		return new PrimeOrderGroupElement((PrimeOrderGroup) this.getGroup(), result);
	}

	@Override
	public PrimeOrderGroupElement multiply(final GroupElement element) {
		if (!this.getGroup().equals(element.getGroup())) {
			throw new UnsupportedOperationException("The two elements are from different groups.");
		}
		BigInteger prod = (this.value.multiply(element.getValue())).mod(this.getGroup().getModulus());
		return new PrimeOrderGroupElement(this.group, prod);
	}

	@Override
	public GroupElement multiBaseExp(List<GroupElement> bases, List<BigInteger> exponents) {
		//TODO implement multibase exponentiations

		return null;
	}

	@Override
	public PrimeOrderGroupElement modInverse() {
		BigInteger inv = this.value.modInverse(this.getGroup().getModulus());
		return new PrimeOrderGroupElement((PrimeOrderGroup) this.getGroup(), inv);
	}

	@Override
	public int bitLength() {
		return value.bitLength();
	}

	@Override
	public int bitCount() {
		return value.bitCount();
	}

	@Override
	public int compareTo(final BigInteger val) {
		return value.compareTo(val);
	}

	@Override
	public int compareTo(final GroupElement val) {
		return value.compareTo(val.getValue());
	}

	@Override
	public GroupElement publicClone() {
		return new PrimeOrderGroupElement((PrimeOrderGroup) this.getGroup().publicClone(), value);
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder("eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroupElement{");
		sb.append(", value=").append(getValue());
		sb.append(", bitLength=").append(bitLength());
		sb.append(", bitCount=").append(bitCount());
		sb.append('}');
		return sb.toString();
	}
}
