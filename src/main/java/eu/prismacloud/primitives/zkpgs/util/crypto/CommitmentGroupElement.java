package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;
import java.util.List;

import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;


/** Commitment Group Element class */
public final class CommitmentGroupElement extends GroupElement {

  private final CommitmentGroup group;
  private final BigInteger value;

  public CommitmentGroupElement(final CommitmentGroup group, final BigInteger value) {
    this.group = group;
    this.value = value;
  }

  @Override
  public Group getGroup() {
    return this.group;
  }

  public BigInteger getOrder() {
    // TODO implement get Order
    throw new NotImplementedException("not implemented");
  }

  @Override
  public BigInteger getValue() {
    return value;
  }

  @Override
  public CommitmentGroupElement multiply(GroupElement val) {
    return null;
  }

  @Override
  public CommitmentGroupElement multiBaseExp(List<GroupElement> bases, List<BigInteger> exponents) {
    // TODO implement multibase exponentiations
       throw new NotImplementedException("not implemented");
  }

  @Override
  public GroupElement modInverse() {
    throw new NotImplementedException("not implemented");
  }

@Override
public BigInteger getElementOrder() throws UnsupportedOperationException {
	// TODO Auto-generated method stub
	return null;
}

@Override
public boolean isOrderKnown() {
	// TODO Auto-generated method stub
	return false;
}

@Override
public GroupElement modPow(BigInteger exponent) {
	// TODO Auto-generated method stub
	return null;
}

@Override
public int bitLength() {
	// TODO Auto-generated method stub
	return 0;
}

@Override
public int bitCount() {
	// TODO Auto-generated method stub
	return 0;
}

@Override
public int compareTo(BigInteger val) {
	// TODO Auto-generated method stub
	return 0;
}

@Override
public int compareTo(GroupElement val) {
	// TODO Auto-generated method stub
	return 0;
}
}
