package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/** */
public class PossessionVerifier implements IVerifier {
	public static final String URNID = "possessionverifier";

	private final ExtendedPublicKey extendedPublicKey;
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;
	private final GroupElement baseZ;
	private final GroupElement baseS;
	private final BaseCollection baseCollection;
	private final GroupElement baseR0;
	private GroupElement APrime;
	private BigInteger hatvPrime;
	private BigInteger hate;
	private GroupElement hatZ;
	private BigInteger hatm_0;
	// private Logger gslog = GSLoggerConfiguration.getGSlog();

	public PossessionVerifier(BaseCollection basesInSignature, ExtendedPublicKey epk, ProofStore<Object> ps) {
		Assert.notNull(epk, "The extended public key must not be null.");
		Assert.notNull(ps, "The ProofStore must not be null.");

		this.extendedPublicKey = epk;
		this.keyGenParameters = epk.getKeyGenParameters();
		this.proofStore = ps;

		this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();
		this.baseS = extendedPublicKey.getPublicKey().getBaseS();

		this.baseCollection = basesInSignature;
		this.baseR0 = extendedPublicKey.getPublicKey().getBaseR_0();
	}

	@Override
	public boolean checkLengths() {
		int l_hate = keyGenParameters.getL_prime_e() + keyGenParameters.getProofOffset();
		int l_hatvPrime = keyGenParameters.getL_v() + keyGenParameters.getProofOffset();
		int l_m = keyGenParameters.getL_m() + keyGenParameters.getProofOffset() + 1;

		hate = (BigInteger) proofStore.retrieve("verifier.hate");
		hatvPrime = (BigInteger) proofStore.retrieve("verifier.hatvPrime");
		hatm_0 = (BigInteger) proofStore.retrieve("verifier.hatm_0");

		boolean vertexLengthsCorrect = true;
		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation baseRepresentation : vertexIterator) {
			BigInteger hatm = (BigInteger) proofStore.retrieve(
					URNType.buildURNComponent(URNType.HATMI, this.getClass(), baseRepresentation.getBaseIndex()));
			if (!CryptoUtilsFacade.isInPMRange(hatm, l_m)) {
				vertexLengthsCorrect = false;
			}
		}

		boolean edgeLengthsCorrect = true;
		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			BigInteger hatm = (BigInteger) proofStore.retrieve(
					URNType.buildURNComponent(URNType.HATMIJ, this.getClass(), baseRepresentation.getBaseIndex()));
			if (!CryptoUtilsFacade.isInPMRange(hatm, l_m)) {
				edgeLengthsCorrect = false;
			} 
		}

		return CryptoUtilsFacade.isInPMRange(hate, l_hate)
				&& CryptoUtilsFacade.isInPMRange(hatvPrime, l_hatvPrime)
				&& CryptoUtilsFacade.isInPMRange(hatm_0, l_m)
				&& vertexLengthsCorrect && edgeLengthsCorrect;
	}

	@Override
	public GroupElement executeVerification(BigInteger cChallenge) throws ProofStoreException {
		APrime = (GroupElement) proofStore.retrieve("verifier.APrime");
		hate = (BigInteger) proofStore.retrieve("verifier.hate");
		hatvPrime = (BigInteger) proofStore.retrieve("verifier.hatvPrime");
		hatm_0 = (BigInteger) proofStore.retrieve("verifier.hatm_0");

		// Aborting verification with output null, if lengths check rejects hat-values.
		if (!checkLengths()) return null;

		QRElement basesProduct = (QRElement) extendedPublicKey.getPublicKey().getQRGroup().getOne();

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation baseRepresentation : vertexIterator) {
			BigInteger hatm = (BigInteger) proofStore.retrieve(
					URNType.buildURNComponent(URNType.HATMI, this.getClass(), baseRepresentation.getBaseIndex()));
			Assert.notNull(hatm, "Hat value could not be retrieved.");

			basesProduct =
					basesProduct.multiply(
							baseRepresentation.getBase().modPow(hatm));
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation baseRepresentation : edgeIterator) {
			BigInteger hatm = (BigInteger) proofStore.retrieve(
					URNType.buildURNComponent(URNType.HATMIJ, this.getClass(), baseRepresentation.getBaseIndex()));
			Assert.notNull(hatm, "Hat value could not be retrieved.");

			basesProduct =
					basesProduct.multiply(
							baseRepresentation.getBase().modPow(hatm));
		}

		BigInteger offsetExp = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1);

		GroupElement aPrimeMulti = APrime.modPow(offsetExp);

		GroupElement baseZdividedAPrime = baseZ.multiply(aPrimeMulti.modInverse());
		GroupElement adjustedZ = baseZdividedAPrime.modPow(cChallenge.negate());

		GroupElement baseR0hatm_0 = baseR0.modPow(hatm_0);
		GroupElement aPrimeHate = APrime.modPow(hate);
		GroupElement baseShatvPrime = baseS.modPow(hatvPrime);

		hatZ = adjustedZ.multiply(aPrimeHate).multiply(baseShatvPrime).multiply(baseR0hatm_0).multiply(basesProduct);

		return hatZ;
	}

	@Override
	public Map<URN, GroupElement> executeCompoundVerification(BigInteger cChallenge) throws ProofStoreException {
		GroupElement hatValue = executeVerification(cChallenge);
		if (hatValue == null) return null; // Abort returning null.

		Map<URN, GroupElement> responses = new HashMap<URN, GroupElement>();
		String hatZURN = URNType.buildURNComponent(URNType.HATZ, PossessionVerifier.class);
		responses.put(URN.createZkpgsURN(hatZURN), hatValue);
		return responses;
	}

	@Override
	public List<URN> getGovernedURNs() {
		throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
	}
}
