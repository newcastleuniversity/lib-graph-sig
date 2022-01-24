package uk.ac.ncl.cascade.hashToPrime;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroupElement;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Creates a Naor-Reingold pseudorandom generator operating in a PrimeOrder group.
 * <p>
 * Naor, M. and Reingold, O. (1997). Number-theoretic constructions
 * of efficient pseudo-random functions.
 */
public class NaorReingoldPRG {
	private final BigInteger p;
	private final BigInteger q;
	private static final Logger log = GSLoggerConfiguration.getGSlog();
	private final PrimeOrderGroupElement g;
	private List<BigInteger> a_i;

	/**
	 * Instantiates a new Naor-Rheingold pseudorandom generator.
	 *
	 * @param gr             the prime order group which is the subgroup of                       \( Z^{*}_{p} \) where p is prime.
	 */
	public NaorReingoldPRG(final PrimeOrderGroup gr) {
		this.p = gr.getModulus();
		this.q = gr.getOrder();
		this.g = (PrimeOrderGroupElement) gr.getGenerator();
		this.a_i = new ArrayList<BigInteger>();
	}

	/**
	 * Computes the output of the pseudorandom generator.
	 * The input x is converted to a bitstring.
	 * The product is computed by multiplying only the corresponding
	 * big integer values in the list where the character at index i is set to 1 in the bitstring.
	 * The output of the method is computed using the group generator
	 * with a modular exponentiation mod p.
	 *
	 * @param x the input value for the pseudorandom generator
	 * @param sequence list of random number for the pseudorandom generator
	 * @return the big integer output for the pseudorandom generator
	 */
	public BigInteger compute(BigInteger x, List<BigInteger> sequence) {
		Assert.notNull(x, "the input to NaorRheingold PRG must not be null");
		Assert.notNull(x, "the list of random numbers for the NaorRheingold PRG must not be null");

		String bis;
		BigInteger prod;
		BigInteger ai;
		bis = convertToBitString(x);
//		log.info("x bitlength: "+ x.bitLength());
//		log.info("bitstring length: " + bis.length());
		this.a_i = sequence;
//		log.info("ai size: " + this.a_i.size());
				
		if (this.a_i.size() != bis.length() + 1)
			throw new IllegalArgumentException("length of the random elements is not the same as the length of input bitstring");

		prod = this.a_i.get(0);
		int j = 0;
		for (int i = 0; i < bis.length(); i++) {
			j = i + 1;
			char ch = bis.charAt(i);
			ai = this.a_i.get(j);
			if (ch == '1') prod = prod.multiply(ai.pow(1));
		}

		return this.g.modPow(prod).getValue();
	}

	/**
	 * Creates a list of random numbers with the same bitlength as q.
	 * The input size of the list has been incremented by 1 such that |x| + 1
	 * to cater for the first element a_0 in the list.
	 *
	 * @param size the size of the generated list, which is input as |x| + 1
	 * @return the list of random numbers with bitlength = |q|
	 */
	public List<BigInteger> computeVectorA(int size) {
		List<BigInteger> vector = new ArrayList<BigInteger>();
		for (int i = 0; i < size; i++) {
			vector.add(i, CryptoUtilsFacade.computeRandomNumber(this.q.bitLength()));
		}
		return vector;
	}

	/**
	 * Returns the random sequence list that was generated.
	 *
	 * @return the list
	 */
	public List<BigInteger> getRandomSequence(){
		return this.a_i;
	}

	/**
	 * Converts an input big integer value to a bitstring representation.
	 *
	 * @param value the big integer value to convert to a bitstring
	 * @return the bit string representation of the big integer
	 */
	public String convertToBitString(BigInteger value) {
		return value.toString(2);
	}

}
