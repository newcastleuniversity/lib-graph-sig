package uk.ac.ncl.cascade.zkpgs.util.crypto;

import uk.ac.ncl.cascade.zkpgs.exception.GSInternalError;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/** Element of Quadratic Residue Group. */
public class QRElement extends GroupElement {

	private static final long serialVersionUID = 197876973241169380L;

	private final Group group;

	private final BigInteger value;

	public QRElement(final Group group, final BigInteger value) {
		this.group = group;
		this.value = value;
	}

	@Override
	public BigInteger getElementOrder() throws UnsupportedOperationException {
		throw new UnsupportedOperationException("Element order is not efficiently computable.");
	}

	@Override
	public boolean isOrderKnown() {
		return false;
	}

	@Override
	public BigInteger getValue() {
		return value;
	}

	@Override
	public QRElement multiBaseExp(List<GroupElement> bases, List<BigInteger> exponents) {
		List<BigInteger> baseList = new ArrayList<BigInteger>(bases.size());
		Iterator<GroupElement> baseIter = bases.iterator();
		while (baseIter.hasNext()) {
			GroupElement groupElement = (GroupElement) baseIter.next();
			BigInteger bigInteger = groupElement.getValue();
			baseList.add(bigInteger);
		}
		// TODO Provide a CryptoUtils function that operates directly on GroupElements!
		BigInteger expProduct = CryptoUtilsFacade.computeMultiBaseExp(baseList, exponents, this.group.getModulus());
		return new QRElement(this.getGroup(), expProduct);
	}

	public QRElement multiBaseExpMap(Map<URN, GroupElement> bases, Map<URN, BigInteger> exponents) {
		BigInteger expProduct = CryptoUtilsFacade.computeMultiBaseExpMap(bases, exponents, this.group.getModulus());
		return new QRElement(this.getGroup(), expProduct);
	}

	@Override
	public QRElement multiply(GroupElement value) {
		if (!this.getGroup().equals(value.getGroup())) {
			throw new UnsupportedOperationException("The two elements are from different groups.");
			// TODO Graceful exit strategy if elements are not part of the same group?
			// Exception
		}

		BigInteger product = (this.value.multiply(value.getValue())).mod(this.getGroup().getModulus());
		return new QRElement(this.group, product);
	}

	BigInteger divide(BigInteger val) {
		return value.divide(val);
	}

	BigInteger[] divideAndRemainder(BigInteger val) {
		return value.divideAndRemainder(val);
	}

	BigInteger remainder(BigInteger val) {
		return value.remainder(val);
	}

	BigInteger gcd(BigInteger val) {
		return value.gcd(val);
	}

	BigInteger abs() {
		return value.abs();
	}

	BigInteger negate() {
		return value.negate();
	}

	int signum() {
		return value.signum();
	}

	BigInteger mod(BigInteger m) {
		return value.mod(m);
	}

	@Override
	public QRElement modPow(BigInteger exponent) {
		BigInteger result = this.value.modPow(exponent, this.getGroup().getModulus());
		return new QRElement(this.getGroup(), result);
	}

	@Override
	public QRElement modInverse() {
		BigInteger inverse = this.value.modInverse(this.getGroup().getModulus());
		return new QRElement(this.getGroup(), inverse);
	}

	int getLowestSetBit() {
		return value.getLowestSetBit();
	}

	@Override
	public int bitLength() {
		return value.bitLength();
	}

	@Override
	public int bitCount() {
		return value.bitCount();
	}

	public boolean isProbablePrime(int certainty) {
		return value.isProbablePrime(certainty);
	}

	@Override
	public int compareTo(BigInteger val) {
		return value.compareTo(val);
	}

	@Override
	public int compareTo(GroupElement val) {
		return this.value.compareTo(val.getValue());
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof QRElement))
			return false;
		QRElement other = (QRElement) obj;
		if (group == null) {
			if (other.group != null)
				return false;
		} else if (!group.equals(other.group))
			return false;
		if (value == null) {
			if (other.value != null)
				return false;
		} else if (!value.equals(other.value))
			return false;
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((group == null) ? 0 : group.hashCode());
		result = prime * result + ((value == null) ? 0 : value.hashCode());
		return result;
	}

	public BigInteger min(BigInteger val) {
		return value.min(val);
	}

	public BigInteger max(BigInteger val) {
		return value.max(val);
	}

	public String toString(int radix) {
		return value.toString(radix);
	}

	@Override
	public String toString() {
		return value.toString();
	}

	public byte[] toByteArray() {
		return value.toByteArray();
	}

	@Override
	public Group getGroup() {
		return group;
	}

	@Override
	public GroupElement publicClone() {
		return new QRElement((Group) this.getGroup().publicClone(), value);
	}


	@Override
	public QRElement clone() {
		QRElement theClone = null;

		try {
			theClone = (QRElement) super.clone();
		} catch (CloneNotSupportedException e) {
			// Should never happen
			throw new GSInternalError(e);
		}

		return theClone;
	}
	
}
