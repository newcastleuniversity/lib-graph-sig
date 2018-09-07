package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import java.math.BigInteger;

/** Quadratic Residue Group where we don't know the modulus factorization in \(Z^*_p \) */
public final class QRGroupN extends QRGroup {

	public QRGroupN(final BigInteger modulus) {
		super(modulus);
	}

	@Override
	public BigInteger getOrder() {
		throw new UnsupportedOperationException("Order not known.");
	}
	

	/**
	 * Creates an element without guarantee of uniform distribution
	 * 
	 * @return QRElementN without knowing the modulus factorization
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
	public boolean isElement(final BigInteger value) {
		throw new UnsupportedOperationException("Checking the group membership is intractable.");
	}

	@Override
	public boolean isKnownOrder() {
		return false;
	}
}
