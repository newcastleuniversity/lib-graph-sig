package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import java.math.BigInteger;
import java.util.ArrayList;

/** Quadratic Residues Group when the modulus factorization is known */
public final class QRGroupPQ extends Group {

  private final BigInteger modulus;
  private final BigInteger pPrime;
  private final BigInteger qPrime;
  private final BigInteger order;
  private final BigInteger oneP;
  private final BigInteger oneQ;
  private GroupElement generator;
  private ArrayList<GroupElement> groupElements = new ArrayList<>();

  /**
   * Instantiates a new QR group where we know the modulus factorization.
   *
   * @param pPrime the p prime
   * @param qPrime the q prime
   */
  public QRGroupPQ(final BigInteger pPrime, final BigInteger qPrime) {

    this.modulus = pPrime.multiply(qPrime);
    this.pPrime = pPrime;
    this.qPrime = qPrime;
    this.order = getOrder();
    computeEEA(pPrime, qPrime);
    this.oneP = CRT.compute1p(EEAlgorithm.getT(), pPrime, qPrime);
    this.oneQ = CRT.compute1q(EEAlgorithm.getS(), pPrime, qPrime);
  }

  private static void computeEEA(BigInteger p, BigInteger q) {
    EEAlgorithm.computeEEAlgorithm(p, q);
  }

  @Override
  public BigInteger getOrder() {
    // (p-1)(q-1)/4 = pPrime * qPrime
    return this.pPrime.multiply(this.qPrime);
  }

  @Override
  public BigInteger getModulus() {
    return this.modulus;
  }

  @Override
  public GroupElement getGenerator() {
    return this.generator;
  }

  /**
   * Create generator group element for QRN. when the modulus factorization is known.
   *
   * @return the group element
   */
  public GroupElement createGenerator() {
    return this.generator =
        new QRElementPQ(this, CryptoUtilsFacade.computeQRNGenerator(this.modulus), pPrime, qPrime);
  }

  @Override
  public GroupElement createElement() {

    return new QRElementPQ(this, CryptoUtilsFacade.computeQRNElement(this.modulus), pPrime, qPrime);
  }

  @Override
  public GroupElement createElement(GroupElement s) {
    QRElementPQ qrElementPQ;
    BigInteger upperBound = this.pPrime.multiply(this.qPrime).subtract(BigInteger.ONE);

    do {
      BigInteger exponent =
          CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);
      qrElementPQ = new QRElementPQ(this, s.modPow(exponent, this.modulus));

    } while (!isElement(qrElementPQ.getValue()));

    this.groupElements.add(qrElementPQ);

    return qrElementPQ;
  }

  /**
   * Algorithm <tt>alg:element_of_QR_N</tt> - topocert-doc Determines if an integer alpha is an
   * element of QRN If the factorization of a Special RSA modulus is known \(N = pq\) then \((a | p)
   * = 1 \land (a | q) = 1\)
   *
   * @param alpha candidate integer alpha,
   * @return true if alpha in QRN, false if alpha not in QRN Dependencies: jacobiSymbol()
   */
  @Override
  public boolean isElement(BigInteger alpha) {
    // TODO check if computations are correct
    return CryptoUtilsFacade.isElementOfQR(alpha, pPrime)
        && CryptoUtilsFacade.isElementOfQR(alpha, qPrime);
  }

  /**
   * Algorithm <tt>alg:verifySGeneratorOfQRN</tt> - topocert-doc Verify s generator boolean.
   *
   * @param S the generator S
   * @param pPrime the p prime
   * @param qPrime the q prime
   * @return true if S is a generator of QRN or false if it is not
   */
  public boolean verifySGenerator(BigInteger S, BigInteger pPrime, BigInteger qPrime) {
    if (!S.equals(BigInteger.ONE.mod(modulus))) {
      if (!S.modPow(pPrime, modulus).equals(BigInteger.ONE.mod(modulus)))
        return !S.modPow(qPrime, modulus).equals(BigInteger.ONE.mod(modulus));
    } else return false;

    return false;
  }

  /**
   * Algorithm <tt>alg:verifySGeneratorOfQRN_alt</tt> - topocert-doc Verify S generator (alternative
   * implementation).
   *
   * @param S the generator
   * @param N the modulus
   * @return true if S is a generator of QRN or false if it is not
   */
  public boolean verifySGenerator(BigInteger S, BigInteger N) {
    return S.subtract(BigInteger.ONE).gcd(N).equals(BigInteger.ONE);
  }

  public BigInteger getOneP() {
    return oneP;
  }

  public BigInteger getOneQ() {
    return oneQ;
  }
}
