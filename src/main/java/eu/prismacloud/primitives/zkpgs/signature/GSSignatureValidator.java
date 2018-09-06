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

	// TODO Source of encoded base collection?
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

	private GroupElement computeQ() throws ProofStoreException {
		GroupElement basesProduct = (QRElement) signerPublicKey.getQRGroup().getOne();

		BaseIterator vertexIterator = encodedBasesCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertexBase : vertexIterator) {
			basesProduct =
					basesProduct.multiply(
							vertexBase.getBase().modPow(vertexBase.getExponent()));
		}
		
		BaseIterator edgeIterator = encodedBasesCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation edgeBase : edgeIterator) {
			basesProduct =
					basesProduct.multiply(
							edgeBase.getBase().modPow(edgeBase.getExponent()));
		}

		GroupElement R_0 = signerPublicKey.getBaseR_0();

		BigInteger vPrime = (BigInteger) proofStore.retrieve("issuing.recipient.vPrime");
		BigInteger vPrimePrime = (BigInteger) proofStore.retrieve("recipient.vPrimePrime");
		BigInteger m_0 = (BigInteger) proofStore.retrieve("bases.exponent.m_0");

		BigInteger v = vPrimePrime.add(vPrime);

		GroupElement R_0multi = R_0.modPow(m_0);
		basesProduct = basesProduct.multiply(R_0multi);

		GroupElement Sv = baseS.modPow(v);
		GroupElement result = Sv.multiply(basesProduct);
		Q = baseZ.multiply(result.modInverse());
		
		proofStore.store("issuing.recipient.Q", Q);
		
		return Q;
	}

	private void verifyAgainstHatQ() throws VerificationException {
		GroupElement hatQ = sigma.getA().modPow(sigma.getE());

		if (hatQ.compareTo(Q) != 0) {
			throw new VerificationException("Q cannot be verified");
		}
	}

	public boolean verify() throws ProofStoreException {
		try {
			checkE(sigma.getE());
		} catch (Exception e) {
			return false;
		}
		
		return verifySignature();
	}

	private boolean verifySignature() throws ProofStoreException {
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
