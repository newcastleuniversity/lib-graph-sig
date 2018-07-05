package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import java.math.BigInteger;
import java.util.ArrayList;

/** Quadratic Residue Group where we don't know the modulus factorization in \(Z^*_p \) */
public final class QRGroupN extends QRGroup {

	private final BigInteger modulus;
	private QRElementN generator;
	private QRElementN one;

	public QRGroupN(final BigInteger modulus) {
		this.modulus = modulus;
		this.one = new QRElementN(this, BigInteger.ONE);
	}

	@Override
	public BigInteger getOrder() {
		throw new UnsupportedOperationException("Order not known.");
	}

	@Override
	public GroupElement getGenerator() {
		return this.generator;
	}

	@Override
	public QRElement createGenerator() {
		return this.generator =
				new QRElementN(this, CryptoUtilsFacade.computeQRNGenerator(this.modulus).getValue());
	}

	@Override
	public QRElement createRandomElement() {
		QRElement qrElement = new QRElementN(this, CryptoUtilsFacade.computeQRNElement(this.modulus).getValue());

		return qrElement;
	}


	@Override
	public GroupElement createElement(BigInteger value) {
		throw new UnsupportedOperationException("Checking the group membership is intractable.");
	}

	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}

	@Override
	public boolean isElement(final BigInteger value) {
		return false;
	}

	@Override
	public boolean isKnownOrder() {
		return false;
	}

	@Override
	public GroupElement getOne() {
		
		return this.one;
	}
}
