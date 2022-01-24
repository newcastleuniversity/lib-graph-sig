package uk.ac.ncl.cascade.hashToPrime;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Ioannis Sfyrakis on 19/01/2022
 */
public class HashToPrimeElimination {

	private Group gr;
	private BigInteger modulus;
	private final KeyGenParameters keyGenParameters;
	private final SquareHashing squareHash;
	private final NaorReingoldPRG nrPRG;
	private SquareHashing sqHash;
	private List<BigInteger> candidates;
	private List<BigInteger> primeSequence;

	/**
	 * Instantiates a new Hash to prime elimination.
	 *
	 * @param squareHash       the square hash
	 * @param nrPRG            the nr prg
	 * @param keyGenParameters the key gen parameters
	 */
	public HashToPrimeElimination(final SquareHashing squareHash, final NaorReingoldPRG nrPRG, final KeyGenParameters keyGenParameters) {
		Assert.notNull(squareHash, "Square hash is required for the hashToPrime predicate");
		Assert.notNull(nrPRG, "Naor-Reingold PRG is required for the hashToPrime predicate");
		Assert.notNull(keyGenParameters, "Keygen parameters are required for the hashToPrime predicate");

		this.squareHash = squareHash;
		this.nrPRG = nrPRG;
		this.keyGenParameters = keyGenParameters;
	}

	/**
	 * Compute square hash big integer.
	 *
	 * @param x the x
	 * @return the big integer
	 */
	public BigInteger computeSquareHash(final BigInteger x) {
		Assert.notNull(x, "input to square hash must not be empty");
		return this.squareHash.hash(x);
	}


	/**
	 * Compute prime big integer.
	 *
	 * @param input the input
	 * @return the big integer
	 */
	public BigInteger computePrime(final BigInteger input) {
		Assert.notNull(input, "input to Naor-Reingold pseudorandom generator must not be empty");
		BigInteger number;
		this.candidates = new ArrayList<BigInteger>();
		List<BigInteger> sequence;
		do {
			sequence = this.nrPRG.computeVectorA(input.bitLength()+1);
			number = computePRG(input, sequence);
			this.candidates.add(number);
		} while (!number.isProbablePrime(this.keyGenParameters.getL_pt()));
		this.primeSequence= sequence;
		return number;
	}

	/**
	 * Gets prime sequence.
	 *
	 * @return the prime sequence
	 */
	public List<BigInteger> getPrimeSequence() {
		return this.primeSequence;
	}

	/**
	 * Compute prg big integer.
	 *
	 * @param message  the message
	 * @param sequence the sequence
	 * @return the big integer
	 */
	public BigInteger computePRG(final BigInteger message, List<BigInteger> sequence) {
		return this.nrPRG.compute(message, sequence);
	}

	/**
	 * Gets candidates.
	 *
	 * @return the candidates
	 */
	public List<BigInteger> getCandidates() {
		return this.candidates;
	}

}
