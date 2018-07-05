package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;

public abstract class QRGroup extends Group {
	
	@Override
	public abstract BigInteger getOrder();

	@Override
	public abstract GroupElement getGenerator();

	@Override
	public abstract BigInteger getModulus();

	@Override
	public abstract boolean isElement(BigInteger value);

	@Override
	public abstract GroupElement createGenerator();

	@Override
	public abstract GroupElement createRandomElement();

	@Override
	public abstract GroupElement createElement(BigInteger value);
	
	public abstract GroupElement getOne();
}
