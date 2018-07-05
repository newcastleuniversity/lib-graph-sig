package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;

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
	
	  /**
	   * Algorithm <tt>alg:generator_QR_N</tt> - topocert-doc Create generator of QRN Input: Special RSA
	   * modulus modN, p', q' Output: generator S of QRN Dependencies: createElementOfZNS(),
	   * verifySGenerator()
	   */
	  @Override
	  public QRElement createQRNGenerator() {

		  BigInteger s;
	    BigInteger s_prime;

	    do {
	      s_prime = CryptoUtilsFacade.createElementOfZNS(this.modulus);
	      s = s_prime.modPow(NumberConstants.TWO.getValue(), this.modulus);

	    } while (!CryptoUtilsFacade.verifySGeneratorOfQRN(s, this.modulus));
	    
	    this.generator = new QRElementN(this, s);
	  }

	@Override
	public QRElement createRandomElement() {
		QRElement qrElement = new QRElementN(this, CryptoUtilsFacade.computeQRNElement(this.modulus).getValue());

		return qrElement;
	}
	

	/**
	 * Creates an element without guarantee of uniform distribution
	 * 
	 * @return
	 */
	  public QRElementN createElement() {
// TODO Possible create a second version of this function using the generator to create new random elements.
	    BigInteger s;
	    BigInteger s_prime;

	    do {

	      s_prime = CryptoUtilsFacade.createElementOfZNS(this.getModulus());
	      s = s_prime.modPow(NumberConstants.TWO.getValue(), this.getModulus());

	    } while (!this.isElement(s));
	    return new QRElementN(this, s);
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
