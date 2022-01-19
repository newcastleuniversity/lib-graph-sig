package uk.ac.ncl.cascade.hashToPrime;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroup;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Ioannis Sfyrakis on 19/01/2022
 */
public class HashToPrimeElimination {

	private final Group gr;
	private final BigInteger modulus;
	private final KeyGenParameters keyGenParameters;
	private SquareHashing sqHash;
	private List<BigInteger> candidates;

	public HashToPrimeElimination(final Group gr, final KeyGenParameters keyGenParameters) {
		this.gr = gr;
		this.modulus = this.gr.getModulus();
		this.keyGenParameters = keyGenParameters;
	}

	public BigInteger computeSquareHash(final BigInteger x) {
		Assert.notNull(x, "input to square hash must not be empty");

		BigInteger b = CryptoUtilsFacade.computeRandomNumber(this.modulus.bitLength());
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(this.modulus.bitLength());
		sqHash = new SquareHashing(this.gr.getModulus(), z, b);
		return sqHash.hash(x);
	}


	public BigInteger computePrime(final BigInteger input) {
		Assert.notNull(input, "input to Naor-Rheingold pseudorandom generator must not be empty");
		BigInteger number;
		this.candidates = new ArrayList<BigInteger>();
		NaorRheingoldPRG nr = new NaorRheingoldPRG((PrimeOrderGroup) this.gr);

		do {
			number = nr.compute(input);
			this.candidates.add(number);
		} while (!number.isProbablePrime(keyGenParameters.getL_pt()));

		return number;
	}

	public List<BigInteger> getCandidates() {
		return candidates;
	}

	public void primalityZKProof(BigInteger prime){
		// TODO implement zk proof of primality for input number
	}
}
