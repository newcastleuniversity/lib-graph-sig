package uk.ac.ncl.cascade.encoding;

import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.encoding.PseudonymPrimeEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.JSONParameters;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

//@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
class PseudonymPrimeEncodingTest {

	private GraphEncodingParameters graphEncodingParameters;
	private FilePersistenceUtil persistenceUtil;
	private PseudonymPrimeEncoding pe;
	private Logger gslog = GSLoggerConfiguration.getGSlog();


	@BeforeEach
	void setUp() throws FileNotFoundException {
		JSONParameters parameters = new JSONParameters();
		graphEncodingParameters = parameters.getGraphEncodingParameters();
		persistenceUtil = new FilePersistenceUtil();
		List<String> values = persistenceUtil.readFileLines("ps-primes-5.txt");

		List<BigInteger> primes = new ArrayList<BigInteger>();

		for (String line : values) {
			primes.add(new BigInteger(line));
		}

		pe = new PseudonymPrimeEncoding(graphEncodingParameters, primes);
	}

	@Test
	void setupEncoding() throws EncodingException {
		pe.setupEncoding();
	}

	@Test
	void testPseudonymPrimesMap() throws IOException {
		persistenceUtil = new FilePersistenceUtil();
		Map<String, BigInteger> values = persistenceUtil.readFileLinesMap("pseudonyms-primes-50.txt");
		assertEquals(50, values.size());
		List<BigInteger> primes = new ArrayList<BigInteger>();
		Collection<BigInteger> vl = values.values();
		for (int i = 0; i < vl.size(); i++) {
			primes.add((BigInteger) vl.toArray()[i]);
		}

		assertEquals(50, primes.size());
//		for (String line : values.entrySet().) {
//			primes.add(new BigInteger(line));
//		}

		pe = new PseudonymPrimeEncoding(graphEncodingParameters, primes);

	}

	@Test
	void getGraphEncodingParameters() throws EncodingException {

		pe.setupEncoding();
		GraphEncodingParameters gr = pe.getGraphEncodingParameters();
		assertNotNull(gr);

	}

	@Test
	void getVertexRepresentatives() throws EncodingException {
		pe.setupEncoding();
		Map<URN, BigInteger> vr = pe.getVertexRepresentatives();
		assertEquals(5, vr.size());
		BigInteger vertexRep;
		for (int i = 0; i < vr.size(); i++) {
			vertexRep = vr.get(URN.createZkpgsURN("vertex.representative.e_i_" + i));
			assertTrue(vertexRep.isProbablePrime(80));
			gslog.info("e_i: " + vertexRep);
			gslog.info("bitlength: " + vertexRep.bitLength());
			assertTrue(vertexRep.bitLength() < graphEncodingParameters.getlPrime_V());

		}
	}

	@Test
	void getLabelRepresentatives() {
	}

	@Test
	void getVertexRepresentative() {
	}

	@Test
	void getVertexLabelRepresentative() {
	}

	@Test
	void getEdgeLabelRepresentative() {
	}
}