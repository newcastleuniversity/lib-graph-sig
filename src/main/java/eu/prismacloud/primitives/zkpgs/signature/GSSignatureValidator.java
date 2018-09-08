package eu.prismacloud.primitives.zkpgs.signature;

import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;

public class GSSignatureValidator {

	private Logger gslog = GSLoggerConfiguration.getGSlog();

	private final SignerPublicKey signerPublicKey;
	private final ProofStore<Object> proofStore;
	private final GSSignature sigma;
	private final KeyGenParameters keyGenParameters;
	private final BaseCollection encodedBasesCollection;

	private final GroupElement baseS;

	private final GroupElement baseZ;

	private GroupElement Q;

	public GSSignatureValidator(GSSignature sigma, SignerPublicKey pk, ProofStore<Object> ps) {
		this.signerPublicKey = pk;
		this.keyGenParameters = pk.getKeyGenParameters();
		this.baseS = pk.getBaseS();
		this.baseZ = pk.getBaseZ();
		this.proofStore = ps;
		this.sigma = sigma;
		this.encodedBasesCollection = sigma.getEncodedBases();
	}



	private void checkE(BigInteger e) {
		if (!e.isProbablePrime(keyGenParameters.getL_pt())) {
			throw new IllegalArgumentException("e is not prime");
		}

		if ((e.compareTo(keyGenParameters.getLowerBoundE()) < 0)
				|| (e.compareTo(keyGenParameters.getUpperBoundE()) > 0)) {
			throw new IllegalArgumentException("e is not within range");
		}
	}

	public GroupElement computeQ() {
		GroupElement basesProduct = (QRElement) signerPublicKey.getQRGroup().getOne();

		BaseIterator baseIterator = encodedBasesCollection.createIterator(BASE.ALL);
		for (BaseRepresentation base : baseIterator) {
			if (base.getBaseType().equals(BASE.BASES)) continue; // Dealing with randomness separately.
			basesProduct =
					basesProduct.multiply(
							base.getBase().modPow(base.getExponent()));
		}
	

		BigInteger v = sigma.getV();
		GroupElement Sv = baseS.modPow(v);
		GroupElement result = Sv.multiply(basesProduct);
		Q = baseZ.multiply(result.modInverse());
		
		return Q;
	}

	private void verifyAgainstHatQ() throws VerificationException {
		GroupElement hatQ = sigma.getA().modPow(sigma.getE());

		if (hatQ.compareTo(Q) != 0) {
			throw new VerificationException("Q cannot be verified");
		}
	}

	public boolean verify() {
		try {
			checkE(sigma.getE());
		} catch (Exception e) {
			return false;
		}
		
		return verifySignature();
	}

	private boolean verifySignature() {
		computeQ();
		try {
			verifyAgainstHatQ();
		} catch (VerificationException ve) {
			gslog.log(Level.SEVERE, ve.getMessage());
			return false;
		}
		return true;
	}

}
