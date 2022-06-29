package uk.ac.ncl.cascade.hashToPrime;

import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.PrimeOrderGroup;
import uk.ac.ncl.cascade.zkpgs.util.crypto.SafePrime;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class HashToPrimeEliminationTest {
	private static final int MODULUS_LENGTH = 256;
	private static final String GROUP_FILENAME = "prime_order_group.ser";
	private static final String NG_FILENAME = "pseudonyms-50.txt";
	private static final String PRIMES_FILENAME = "primes-50.txt";
	private static final Logger log = GSLoggerConfiguration.getGSlog();
	private static KeyGenParameters keyGenParameters;
	private static PrimeOrderGroup group;
	private static final String N_G = "515BA4DAD48EB099CE74F90997FB9B9EF257697A038E4EE65978069A65060C50235D244F523F53417BDE0F0AD5C1CE1EDFB9701BDCA6B5301B82737285D4884583FF0EB33714FB6EA3E87589D631D7430C00BE8C546101D61CE0C9D8CD356F0530367819073E5D444DA2B8773D740099C16A8A34333BCC71FB2A25D093DB23B21B9389650691EFC236E0B3C444836971DABBD253A30B4AC18D5B340348241B34526172C8D41738B5C55B5EFBD9A63C0BC885479399F92F57EDC14ADE9E4887E9C42DB358C7E4D4EDB29A5238";
	private BigInteger message;

	@BeforeAll
	static void setUp() throws IOException, ClassNotFoundException {
		keyGenParameters = KeyGenParameters.createKeyGenParameters(MODULUS_LENGTH, 1632, 80, 256, 1, 597, 120, 2724, 80, 256, 80, 80);

		FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();

		File f = new File(GROUP_FILENAME);
		boolean isFile = f.exists();

		if (isFile) {
			group = (PrimeOrderGroup) persistenceUtil.read(GROUP_FILENAME);
		} else {

			SafePrime safePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
			group = new PrimeOrderGroup(safePrime.getSafePrime(), safePrime.getSophieGermain());
			GroupElement generator = group.createGenerator();
			persistenceUtil.write(group, GROUP_FILENAME);
		}
	}

	@Test
	@DisplayName("test computing square hash with a fixed NG input")
	void computeSquareHashWithNG() {
		log.info("setup square hashing");
		SafePrime sqSafePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
		BigInteger sqPrime = sqSafePrime.getSafePrime();
		message = new BigInteger(N_G, 16);
		log.info("message: " + message);
		log.info("message length: " + message.bitLength());
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());

		BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		SquareHashing squareHash = new SquareHashing(sqPrime, z, b);
		log.info("setup NRPRG");
		NaorReingoldPRG nr = new NaorReingoldPRG(group);

		HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, keyGenParameters);

		BigInteger message = new BigInteger(N_G, 16);

		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);

		log.info("result: " + res);
		log.info("result bitlength: " + res.bitLength());

		SquareHashing sq = new SquareHashing(sqPrime, z, b);
		BigInteger hs = sq.hash(message);
		assertEquals(hs, res);

		BigInteger localres = message.add(z).pow(2).add(b).mod(sqPrime);
		assertEquals(localres, res);

	}

	@Test
	@DisplayName("test computing square hash with a random message")
	void computeSquareHash() {
		SafePrime sqSafePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
		BigInteger sqPrime = sqSafePrime.getSafePrime();
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());

		BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		SquareHashing squareHash = new SquareHashing(sqPrime, z, b);
		log.info("setup NRPRG");
		NaorReingoldPRG nr = new NaorReingoldPRG(group);

		HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, keyGenParameters);

		BigInteger message = CryptoUtilsFacade.computeRandomNumber(1632);
		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);
		log.info("result: " + res);
		log.info("result bitlength: " + res.bitLength());
		SquareHashing sq = new SquareHashing(sqPrime, z, b);
		BigInteger hs = sq.hash(message);
		assertEquals(hs, res);

		BigInteger localres = message.add(z).pow(2).add(b).mod(sqPrime);
		assertEquals(localres, res);
	}

	@Test
	@DisplayName("test computing a prime with a fixed input message")
	void computePrimeNG() {
		SafePrime sqSafePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
		BigInteger sqPrime = sqSafePrime.getSafePrime();
		message = new BigInteger(N_G, 16);
		log.info("message: " + message);
		log.info("message length: " + message.bitLength());
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());

		BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		SquareHashing squareHash = new SquareHashing(sqPrime, z, b);
		log.info("setup NRPRG");
		NaorReingoldPRG nr = new NaorReingoldPRG(group);

		HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, keyGenParameters);

		BigInteger message = new BigInteger(N_G, 16);

		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);

		BigInteger prime = htp.computePrime(res);
		assertNotNull(prime);
		assertTrue(prime.isProbablePrime(keyGenParameters.getL_pt()));
		log.info("prime: " + prime);
		log.info("prime bitlength: " + prime.bitLength());
		NaorReingoldPRG nrprg = new NaorReingoldPRG(group);
		BigInteger htPrime;
		List<BigInteger> primeSequence;

		primeSequence = htp.getPrimeSequence();
		htPrime = nrprg.compute(res, primeSequence);

		assertTrue(htPrime.isProbablePrime(keyGenParameters.getL_pt()));
		assertEquals(htPrime, prime);
	}

	@Test
	@DisplayName("test returning candidates after finding a prime number")
	void getCandidates() {
		log.info("setup square hashing");
		SafePrime sqSafePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
		BigInteger sqPrime = sqSafePrime.getSafePrime();
		message = new BigInteger(N_G, 16);
		log.info("message: " + message);
		log.info("message length: " + message.bitLength());
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());

		BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		SquareHashing squareHash = new SquareHashing(sqPrime, z, b);
		log.info("setup NRPRG");
		NaorReingoldPRG nr = new NaorReingoldPRG(group);

		HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, keyGenParameters);

		BigInteger message = new BigInteger(N_G, 16);

		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);

		BigInteger prime = htp.computePrime(res);
		assertNotNull(prime);
		assertTrue(prime.isProbablePrime(keyGenParameters.getL_pt()));

		List<BigInteger> cand = htp.getCandidates();
		assertNotNull(cand);
		assertTrue(cand.size() > 0);
		log.info("size of candidates: " + cand.size());
	}

	@Test
	@DisplayName("test computing primes with multiple input N_{G} pseudonyms")
	void computePrimesWithNGs() throws IOException {
		// read file with pseudonym
		FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
		List<String> values = persistenceUtil.readFileLines(NG_FILENAME);
		List<String> primes = new ArrayList<String>();
		for (String value : values) {
//			System.out.println("pseudonym: " + value);
			SafePrime sqSafePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
			BigInteger sqPrime = sqSafePrime.getSafePrime();
			message = new BigInteger(value, 16);
//			log.info("message: " + message);
//			log.info("message length: " + message.bitLength());
			BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
//			log.info("z: " + z);
//			log.info("z length: " + z.bitLength());

			BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
//			log.info("b: " + b);
//			log.info("b length: " + b.bitLength());
			SquareHashing squareHash = new SquareHashing(sqPrime, z, b);
//			log.info("setup NRPRG");
			NaorReingoldPRG nr = new NaorReingoldPRG(group);

			HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, keyGenParameters);

			BigInteger message = new BigInteger(value, 16);

			BigInteger res = htp.computeSquareHash(message);
			assertNotNull(res);

			BigInteger prime = htp.computePrime(res);
			assertNotNull(prime);
			assertTrue(prime.isProbablePrime(keyGenParameters.getL_pt()));
			log.info("prime: " + prime);
			log.info("prime bitlength: " + prime.bitLength());
			NaorReingoldPRG nrprg = new NaorReingoldPRG(group);
			BigInteger htPrime;
			List<BigInteger> primeSequence;

			primeSequence = htp.getPrimeSequence();
			htPrime = nrprg.compute(res, primeSequence);

			assertTrue(htPrime.isProbablePrime(keyGenParameters.getL_pt()));
			assertEquals(htPrime, prime);
			primes.add(htPrime.toString());
		}

		File f = new File(PRIMES_FILENAME);
		boolean isFile = f.exists();
		if (!isFile){
			 f.createNewFile();
		}

		persistenceUtil.writeFileLines(PRIMES_FILENAME, primes);

	}
}