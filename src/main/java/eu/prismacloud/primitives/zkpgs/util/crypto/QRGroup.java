package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;

public abstract class QRGroup extends Group {

	private final BigInteger modulus;
	private QRElementN generator;
	private final QRElementN one;

	public QRGroup(BigInteger modulus) {
		super();
		this.modulus = modulus;
		this.one = new QRElementN(this, BigInteger.ONE);
	}

	@Override
	public abstract BigInteger getOrder();

	@Override
	public GroupElement getGenerator() {
		return generator;
	}

	@Override
	public BigInteger getModulus() {
		return this.modulus;
	}

	@Override
	public abstract boolean isElement(BigInteger value);

	/**
	 * Algorithm <tt>alg:generator_QR_N</tt> - topocert-doc Create generator of QRN Input: Special RSA
	 * modulus modN, p', q' Output: generator S of QRN Dependencies: createElementOfZNS(),
	 * verifySGenerator()
	 */
	@Override
	public QRElement createGenerator() {

		BigInteger s;
		BigInteger s_prime;

		do {
			s_prime = CryptoUtilsFacade.createElementOfZNS(this.getModulus());
			s = s_prime.modPow(NumberConstants.TWO.getValue(), this.getModulus());

		} while (!CryptoUtilsFacade.verifySGeneratorOfQRN(s, this.getModulus()));

		this.generator = new QRElementN(this, s);
		return generator;
	}

	public QRElement createElement() {
		BigInteger s;
		BigInteger s_prime;

		s_prime = CryptoUtilsFacade.createElementOfZNS(this.getModulus());
		s = s_prime.modPow(NumberConstants.TWO.getValue(), this.getModulus());

		QRElement qrElement = new QRElement(this, s);

		return qrElement;
	}
	
	@Override
	public QRElement createRandomElement() {
//		BigInteger s;
//		BigInteger s_prime;
//
//		s_prime = CryptoUtilsFacade.createElementOfZNS(this.getModulus());
//		s = s_prime.modPow(NumberConstants.TWO.getValue(), this.getModulus());
		
		BigInteger x = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());

		QRElement qrElement = this.generator.modPow(x);

		return qrElement;
	}

	@Override
	public abstract GroupElement createElement(BigInteger value);

	public GroupElement getOne() {
		return one;
	}
}
