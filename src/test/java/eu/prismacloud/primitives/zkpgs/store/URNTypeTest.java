package eu.prismacloud.primitives.zkpgs.store;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import eu.prismacloud.primitives.zkpgs.prover.PossessionProver;
import eu.prismacloud.primitives.zkpgs.verifier.PossessionVerifier;

@TestInstance(Lifecycle.PER_CLASS)
class URNTypeTest {
	private PossessionProver prover;
	private PossessionVerifier verifier;

	@BeforeAll
	void setUp() {
		prover = new PossessionProver();
		verifier = new PossessionVerifier();
	}
	
	@Test
	void testBuildURNComponentWoIndex() {
		String urnStrFromClass =  URNType.buildURNComponent(URNType.HATE, PossessionProver.class);
		assertEquals(PossessionProver.URNID + "." + URNType.getClass(URNType.HATE) + "." + URNType.getSuffix(URNType.HATE), urnStrFromClass);
		
		String urnStrFromClassV =  URNType.buildURNComponent(URNType.HATE, PossessionVerifier.class);
		assertEquals(PossessionVerifier.URNID + "." + URNType.getClass(URNType.HATE) + "." + URNType.getSuffix(URNType.HATE), urnStrFromClassV);
		
		try {
			URNType.buildURNComponent(URNType.HATMI, PossessionProver.class);
		} catch (RuntimeException e) {
			// Expected exception.
			return;
		}
		fail("URNType did not throw a RuntimeException on attempting to use enumerable type w/o index.");
	}

	@Test
	void testBuildURNComponentWIndex() {
		int testIndex = 0;
		String urnStrFromClass =  URNType.buildURNComponent(URNType.HATMI, PossessionProver.class, testIndex);
		assertEquals(PossessionProver.URNID + "." + URNType.getClass(URNType.HATMI) + "." + URNType.getSuffix(URNType.HATMI) + testIndex, urnStrFromClass);
		
		String urnStrFromClassV =  URNType.buildURNComponent(URNType.HATMI, PossessionVerifier.class, testIndex);
		assertEquals(PossessionVerifier.URNID + "." + URNType.getClass(URNType.HATMI) + "." + URNType.getSuffix(URNType.HATMI) + testIndex, urnStrFromClassV);
		
		try {
			URNType.buildURNComponent(URNType.HATE, PossessionProver.class, testIndex);
		} catch (RuntimeException e) {
			// Expected exception.
			return;
		}
		fail("URNType did not throw a RuntimeException on attempting to use non-enumerable type w/ index.");
	}
	
	@Test
	void testIsProverVerifier() {
		assertTrue(URNType.isProverVerifier(prover.getClass()));
		assertFalse(URNType.isProverVerifier(URNType.class));
	}
}
