package uk.ac.ncl.cascade.hashToPrime;

import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroupElement;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Creates a Naor-Rheingold pseudorandom generator operating in a PrimeOrder group.
 *
 * Naor, M. and Rheingold, O. (1997). Number-theoretic con-
 * structions of efficient pseudo-random functions.
 */
public class NaorRheingoldPRG {
	private final BigInteger p;
	private final BigInteger q;
	private static Logger log = GSLoggerConfiguration.getGSlog();
	private final PrimeOrderGroupElement g;

	public NaorRheingoldPRG(PrimeOrderGroup gr) {
		this.p = gr.getModulus();
		this.q = gr.getOrder();
		this.g = (PrimeOrderGroupElement) gr.getGenerator();
	}

	public BigInteger compute(BigInteger x) {
		String bis;
		BigInteger prod;
		BigInteger ai;

		BigInteger a0 = CryptoUtilsFacade.computeRandomNumber(this.q.bitLength());

		bis = convertToBitString(x);
		prod = a0;
		for (int i = 0; i < bis.length(); i++) {
			char ch = bis.charAt(i);
			ai = CryptoUtilsFacade.computeRandomNumber(this.q.bitLength());
//			System.out.print(ch);
			if (ch == '1') {
				prod = ai.pow(1);
			} else if (ch == '0') {
				prod = ai.pow(0);
			}
		}

		prod = prod.multiply(a0);

		return this.g.modPow(prod).getValue();
	}

	public List<BigInteger> computeVectorA(int length) {
		List<BigInteger> vector = new ArrayList<BigInteger>();
		for (int i = 0; i < length; i++) {
			vector.add(i, CryptoUtilsFacade.computeRandomNumber(q.bitLength()));
		}
		return vector;
	}

	public String convertToBitString(BigInteger value) {
		return value.toString(2);
	}

}
