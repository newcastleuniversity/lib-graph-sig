package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import java.math.BigInteger;
import java.util.List;
import java.util.logging.Logger;

/** */
public class PossessionVerifier implements IVerifier {
	public static final String URNID = "possessionverifier";

	private ExtendedPublicKey extendedPublicKey;
	private ProofStore<Object> proofStore;
	private KeyGenParameters keyGenParameters;
	private GroupElement baseZ;
	private GroupElement baseS;
	private BaseCollection baseCollection;
	private GroupElement baseR0;
	private GroupElement APrime;
	private BigInteger cChallenge;
	private BigInteger hatvPrime;
	private BigInteger hate;
	private GroupElement hatZ;
	private BigInteger hatm_0;
	private Logger gslog = GSLoggerConfiguration.getGSlog();

	public PossessionVerifier(ExtendedPublicKey epk, ProofStore<Object> ps) {
		Assert.notNull(epk, "The extended public key must not be null.");
		Assert.notNull(ps, "The ProofStore must not be null.");

		this.extendedPublicKey = epk;
		this.keyGenParameters = epk.getKeyGenParameters();
		this.proofStore = ps;

		this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();
		this.baseS = extendedPublicKey.getPublicKey().getBaseS();

		this.baseCollection = epk.getBaseCollection();
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

		/** TODO check lengths for hatm_i vertices and hatm_i_j edges */
		return CryptoUtilsFacade.isInPMRange(hate, l_hate)
				&& CryptoUtilsFacade.isInPMRange(hatvPrime, l_hatvPrime)
				&& CryptoUtilsFacade.isInPMRange(hatm_0, l_m);
	}

	@Override
	public GroupElement executeVerification(BigInteger cChallenge) throws ProofStoreException {
		APrime = (GroupElement) proofStore.retrieve("verifier.APrime");
		hate = (BigInteger) proofStore.retrieve("verifier.hate");
		hatvPrime = (BigInteger) proofStore.retrieve("verifier.hatvPrime");
		hatm_0 = (BigInteger) proofStore.retrieve("verifier.hatm_0");
		
		this.cChallenge = cChallenge;

		// Aborting verification with output null, if lengths check rejects hat-values.
		if (!checkLengths()) return null;

		QRElement basesProduct = (QRElement) extendedPublicKey.getPublicKey().getQRGroup().getOne();

		//    BaseIterator baseIterator = baseCollection.createIterator(BASE.ALL);
		//    for (BaseRepresentation baseRepresentation : baseIterator) {
		//      basesProduct =
		//          basesProduct.multiply(
		//              baseRepresentation.getBase().modPow(baseRepresentation.getExponent()));
		//    }
		GroupElement baseR0hatm_0 = baseR0.modPow(hatm_0);
		// gslog.info("Aprime: " + APrime);
		GroupElement aPrimeMulti = APrime.modPow(keyGenParameters.getLowerBoundE());

		GroupElement divide = baseZ.multiply(aPrimeMulti.modInverse());
		GroupElement result = divide.modPow(cChallenge.negate());
		GroupElement aPrimeHate = APrime.modPow(hate);
		GroupElement baseShatvPrime = baseS.modPow(hatvPrime);

		hatZ = result.multiply(aPrimeHate).multiply(baseShatvPrime).multiply(baseR0hatm_0);

		//	    gslog.info("hatZ: " + hatZ);
		//	    gslog.info("hatZ bitlength: " + hatZ.bitLength());

		return hatZ;
	}

	@Override
	public boolean isSetupComplete() {
		// Only instantiable with complete setup
		return true;
	}

	@Override
	public List<URN> getGovernedURNs() {
		throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
	}
}
