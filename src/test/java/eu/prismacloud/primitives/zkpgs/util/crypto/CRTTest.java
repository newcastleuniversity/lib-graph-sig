package eu.prismacloud.primitives.zkpgs.util.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Test CRT computations */
class CRTTest {

	private static final Logger log = Logger.getLogger(CRTTest.class.getName());

	private CRT classUnderTest;

	private BigInteger a;
	private BigInteger p;
	private BigInteger b;
	private BigInteger q;
	private BigInteger x;
	private KeyGenParameters keyGenParameters;

	@BeforeEach
	void setUp() {

		JSONParameters parameters = new JSONParameters();
		keyGenParameters = parameters.getKeyGenParameters();

		/** \( x_p \equiv 1 \bmod 5 \) \( x_q \equiv 2 \bmod 3 \) */
		a = BigInteger.valueOf(1);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(2);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(8);
	}

	@Test
	@DisplayName("Test Chinese Remainder Theorem")
	void computeCRTPC() {
		log.info("@Test: computeCRT");

		EEAlgorithm.computeEEAlgorithm(p, q);
		log.info("crt s: " + EEAlgorithm.getS());
		log.info("crt t: " + EEAlgorithm.getT());
		log.info("crt modInverse: " + p.modInverse(q));

		BigInteger res =
				CRT.computeCRT(a, BigInteger.valueOf(6), b, BigInteger.valueOf(10), p.multiply(q));
		log.info("result: " + res);

		assertEquals(BigInteger.valueOf(11), res);
	}

	@Test
	@DisplayName("Test Chinese Remainder Theorem")
	void computeCRT() {
		log.info("@Test: computeCRT");

		EEAlgorithm.computeEEAlgorithm(p, q);
		log.info("crt s: " + EEAlgorithm.getS());
		log.info("crt t: " + EEAlgorithm.getT());
		log.info("crt modInverse: " + p.modInverse(q));

		BigInteger res = CRT.computeCRT(a, p, b, q);
		log.info("result: " + res);

		assertEquals(BigInteger.valueOf(11), res);
	}

	@Test
	@DisplayName("Test multiplication")
	void computeCRTmult() {
		log.info("@Test: computeCRTmult");

		BigInteger xp1, xq1, xp2, xq2, res;

		a = BigInteger.valueOf(14);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(13);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(2);

		// compute 14 * 13 modulo 15 = 2 <-> (2,2)

		res = BigInteger.valueOf(14).multiply(BigInteger.valueOf(13)).mod(BigInteger.valueOf(15));
		log.info("result multiplication: " + res);
		assertEquals(x, res);

		xp1 = a.mod(p);
		log.info("xp1: " + xp1);
		xq1 = a.mod(q);
		log.info("xq1: " + xq1);

		xp2 = b.mod(p);
		log.info("xp2: " + xp2);
		xq2 = b.mod(q);
		log.info("xq2: " + xq2);

		res = CRT.computeCRT(xp1.multiply(xp2), p, xq1.multiply(xq2), q);
		log.info("result: " + res);

		assertEquals(x, res);
	}

	@Test
	@DisplayName("Test exponentiation")
	void computeCRTexp() {
		log.info("@Test: computeCRTexp");
		BigInteger base, res, exp, n;

		a = BigInteger.valueOf(14);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(13);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(2);
		base = BigInteger.valueOf(11);
		exp = BigInteger.valueOf(53);
		n = BigInteger.valueOf(15);

		// compute 11^53 mod 15
		res = base.modPow(exp, n);
		log.info("result exponentiation: " + res);
		assertEquals(BigInteger.valueOf(11), res);

		BigInteger xp = base.modPow(exp.mod(p.subtract(BigInteger.ONE)), p);
		BigInteger xq = base.modPow(exp.mod(q.subtract(BigInteger.ONE)), q);
		res = CRT.computeCRT(xp, p, xq, q);
		log.info("result pq: " + res);
		assertEquals(BigInteger.valueOf(11), res);
	}

	@Test
	@DisplayName("Test Chinese Remainder Theorem in Z star 15")
	void testCRTZStar15() {
		log.info("@Test: testCRTZStar15");
		BigInteger result;
		// test CRT in \( Z^*_15 = { 1, 2, 4, 7, 8, 11, 13, 14} \)

		// test 1 <-> (1,1)
		a = BigInteger.valueOf(1);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(1);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(1);

		result = CRT.computeCRT(a, p, b, q);

		log.info("result 1 <-> (1,1) " + result);
		assertEquals(x, result);

		// test 2 <-> (2,2)
		a = BigInteger.valueOf(2);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(2);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(2);

		result = CRT.computeCRT(a, p, b, q);

		log.info("result 2 <-> (2,2) " + result);
		assertEquals(x, result);

		// test 4 <-> (4,1)
		a = BigInteger.valueOf(4);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(1);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(4);

		result = CRT.computeCRT(a, p, b, q);

		log.info("result 4 <-> (4,1) " + result);
		assertEquals(x, result);

		// test 7 <-> (2,1)
		a = BigInteger.valueOf(2);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(1);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(7);

		result = CRT.computeCRT(a, p, b, q);

		log.info("result 7 <-> (2,1) " + result);
		assertEquals(x, result);

		// test 8 <-> (3,2)
		a = BigInteger.valueOf(3);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(2);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(8);

		result = CRT.computeCRT(a, p, b, q);

		log.info("result 8 <-> (3,2) " + result);
		assertEquals(x, result);

		// test 11 <-> (1,2)
		a = BigInteger.valueOf(1);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(2);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(11);

		result = CRT.computeCRT(a, p, b, q);

		log.info("result 11 <-> (1,2) " + result);
		assertEquals(x, result);

		// test 13 <-> (3,1)
		a = BigInteger.valueOf(3);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(1);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(13);

		result = CRT.computeCRT(a, p, b, q);

		log.info("result 13 <-> (3,1) " + result);
		assertEquals(x, result);

		// test 14 <-> (4,2)
		a = BigInteger.valueOf(4);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(2);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(14);

		result = CRT.computeCRT(a, p, b, q);

		log.info("result 14 <-> (4,2) " + result);
		assertEquals(x, result);
	}

	@Test
	@DisplayName("Test random modulo exponentiations using CRT")
	void computeCRTRandomExp() {
		log.info("@Test: computeCRTRandom");
		SpecialRSAMod specialRSAMod = CryptoUtilsFacade.computeSpecialRSAModulus(keyGenParameters);

		QRGroupPQ qrGroupPQ = new QRGroupPQ(specialRSAMod.getpPrime(), specialRSAMod.getqPrime());

		Group qrGroupN = new QRGroupN(specialRSAMod.getN());

		BigInteger upperBound =
				(specialRSAMod.getpPrime().multiply(specialRSAMod.getqPrime())).subtract(BigInteger.ONE);

		QRElementPQ S = qrGroupPQ.createGenerator();
		GroupElement S_n = new QRElementN(qrGroupN, S.getValue());

		BigInteger Z,  Z_pq, Z_n;

		for (int i = 0; i < 100; i++) {
			BigInteger x_Z =
					CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);

			// compute using BigIntegers modPow
			Z = S.getValue().modPow(x_Z, specialRSAMod.getN());

			// compute using QRElementN modPow
			Z_n = S_n.modPow(x_Z).getValue();

			// compute using QRElementPQ modPow
			Z_pq = S.modPow(x_Z).getValue();

			assertEquals(Z, Z_n, "The exponentiation over QRGroupN did not yield the same result as the BigInteger computation.");
			assertEquals(Z, Z_pq, "The CRT exponentiation over QRGroupPQ did not yield the same result as the BigInteger computation.");
		}

		for (int j = 0; j < 100; j++) {

			BigInteger x_Z = CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);

			// compute using BigIntegers
			BigInteger Ri = S.getValue().modPow(x_Z, specialRSAMod.getN());

			// compute using QRElementN modPow
			BigInteger Ri_n = (S_n.modPow(x_Z)).getValue();

			// compute using QRElementPQ modPow
			BigInteger Ri_pq = (S.modPow(x_Z)).getValue();

			assertEquals(Ri, Ri_pq, "The exponentiation over QRGroupN did not yield the same result as the BigInteger computation.");
			assertEquals(Ri, Ri_n, "The CRT exponentiation over QRGroupPQ did not yield the same result as the BigInteger computation.");
		}
	}

	@Test
	@DisplayName("Test random multiplications using CRT")
	void computeCRTRandomMult() {
		/*
		 *  TODO Please do not just copy and paste test cases. 
		 *  This test case seems to be copied from the exponentiation test case.
		 *  It uses the wrong setup for testing a multiplication, that is, 
		 *  was multiplying group elements with exponents.
		 */

		log.info("@Test: computeCRTRandom");
		SpecialRSAMod specialRSAMod = CryptoUtilsFacade.computeSpecialRSAModulus(keyGenParameters);
		/* TODO Recreating special RSA mods in multiple test cases won't work. 
		 *  It takes too much time.
		 *  Need to create large keys once and reuse them.
		 */

		QRGroupPQ qrGroupPQ = new QRGroupPQ(specialRSAMod.getpPrime(), specialRSAMod.getqPrime());
		Group qrGroupN = new QRGroupN(specialRSAMod.getN());

		BigInteger upperBound =
				specialRSAMod.getpPrime().multiply(specialRSAMod.getqPrime()).subtract(BigInteger.ONE);

		// Creating a generator can be expensive to intractable. Do not put that into a loop.
		QRElementPQ S = (QRElementPQ) qrGroupPQ.createGenerator();
		GroupElement S_n = new QRElementN(qrGroupN, S.getValue());

		for (int i = 0; i < 100; i++) {


			// Create a fresh likely-quadratic residue.
			BigInteger preMultiplier = CryptoUtilsFacade.createElementOfZNS(specialRSAMod.getN());
			BigInteger multiplier = preMultiplier.modPow(NumberConstants.TWO.getValue(), specialRSAMod.getN());
			QRElementPQ multiplier_pq = new QRElementPQ((QRGroupPQ) qrGroupPQ, multiplier);
			QRElementN multiplier_n = new QRElementN((QRGroupN) qrGroupN, multiplier);
			
//			BigInteger expValueP = S.getValue().mod(specialRSAMod.getP());
//			BigInteger expValueQ = S.getValue().mod(specialRSAMod.getQ());
//			log.info("Expected value of S in  ZPS = " + expValueP);
//			log.info("Expected value of S in ZQS = " + expValueQ);
//			
//			BigInteger expMultiplierP = multiplier.mod(specialRSAMod.getP());
//			BigInteger expMultiplierQ = multiplier.mod(specialRSAMod.getQ());
//			log.info("Expected multiplier P = " + expMultiplierP);
//			log.info("Expected multiplier Q = " + expMultiplierQ);

			// compute using BigIntegers
			BigInteger Z, Z_n, Z_pq;
			Z = (S.getValue().multiply(multiplier)).mod(specialRSAMod.getN());

			// compute using QRElementN multiply
			Z_n = (S_n.multiply(multiplier_n)).getValue(); 

			// compute using QRElementPQ multiply
			Z_pq = (S.multiply(multiplier_pq)).getValue();

			assertEquals(Z, Z_n, "The computation in QRGroupN did not yield the same result as the BigInteger computation.");
			assertEquals(Z, Z_pq, "The CRT Computation in QRGroupPQ did not yield the same result as the BigInteger computation.");
		}
		for (int j = 0; j < 100; j++) {

			//                log.info("j: " + j);
			// Create a fresh likely-quadratic residue.
			BigInteger preMultiplier = CryptoUtilsFacade.createElementOfZNS(specialRSAMod.getN());
			BigInteger multiplier = preMultiplier.modPow(NumberConstants.TWO.getValue(), specialRSAMod.getN());
			QRElementPQ multiplier_pq = new QRElementPQ((QRGroupPQ) qrGroupPQ, multiplier);
			QRElementN multiplier_n = new QRElementN((QRGroupN) qrGroupN, multiplier);

			// compute using BigIntegers multiply
			BigInteger Ri = (S.getValue().multiply(multiplier)).mod(specialRSAMod.getN());

			// compute using QRElementN multiply
			BigInteger Ri_n = (S_n.multiply(multiplier_n)).getValue();

			// compute using QRElementPQ multiply
			BigInteger Ri_pq = (S.multiply(multiplier_pq)).getValue();


			assertEquals(Ri, Ri_n, "The computation in QRGroupN did not yield the same result as the BigInteger computation.");
			assertEquals(Ri, Ri_pq, "The CRT Computation in QRGroupPQ did not yield the same result as the BigInteger computation.");
		}
	}

	//  @Test
	//  @DisplayName("Test convert to pq representation ")
	//  void convertToPQ() {
	//    a = BigInteger.valueOf(1);
	//    p = BigInteger.valueOf(5);
	//    b = BigInteger.valueOf(2);
	//    q = BigInteger.valueOf(3);
	//    x = BigInteger.valueOf(11);
	//    EEAlgorithm.computeEEAlgorithm(p, q);
	//    log.info("crt s: " + EEAlgorithm.getS());
	//    log.info("crt t: " + EEAlgorithm.getT());
	//    log.info("crt modInverse: " + p.modInverse(q));
	//    QRElementPQ qr = new QRElementPQ(NumberConstants.TWO.getValue()); // TODO Needs access to QRGroup.
	//    CRT.convertToPQ(qr, x, p, q);
	//    log.info("representation 0: " + qr.getXp());
	//    log.info("representation 1: " + qr.getXq());
	//
	//    assertEquals(a, qr.getXp());
	//    assertEquals(b, qr.getXq());
	//  }

	@Test
	void compute1p() {
		a = BigInteger.valueOf(1);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(2);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(8);

		EEAlgorithm.computeEEAlgorithm(p, q);
		log.info("crt s: " + EEAlgorithm.getS());
		log.info("crt t: " + EEAlgorithm.getT());
		log.info("crt modInverse: " + p.modInverse(q));
		BigInteger Y = EEAlgorithm.getT();
		BigInteger one_p = CRT.compute1p(Y, p, q);
		log.info("one_p: " + one_p);
		assertEquals(BigInteger.valueOf(6), one_p);
	}

	@Test
	void compute1q() {
		a = BigInteger.valueOf(1);
		p = BigInteger.valueOf(5);
		b = BigInteger.valueOf(2);
		q = BigInteger.valueOf(3);
		x = BigInteger.valueOf(8);

		EEAlgorithm.computeEEAlgorithm(p, q);
		log.info("crt s: " + EEAlgorithm.getS());
		log.info("crt t: " + EEAlgorithm.getT());
		log.info("crt modInverse: " + p.modInverse(q));
		BigInteger X = EEAlgorithm.getS();
		BigInteger one_q = CRT.compute1q(X, p, q);
		log.info("one_q: " + one_q);
		assertEquals(BigInteger.valueOf(10), one_q);
	}
}
