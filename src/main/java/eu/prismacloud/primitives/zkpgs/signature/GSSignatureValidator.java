package eu.prismacloud.primitives.zkpgs.signature;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
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

	private GroupElement Q;

	public GSSignatureValidator(GSSignature sigma, SignerPublicKey pk, ProofStore<Object> ps) {
		this.signerPublicKey = pk;
		this.keyGenParameters = pk.getKeyGenParameters();
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

	/*
	 * TODO
	 * The Q used here (Q of this class) is different from the 
	 * Q computed by the Signer side!
	 * But with inclusion of R_0, msk and vPrime the views should be identical!
	 * TODO
	 */
	public GroupElement computeQ() {
		GroupElement basesProduct = (GroupElement) signerPublicKey.getQRGroup().getOne();

		boolean completedBase0 = false;
		BaseIterator baseIterator = encodedBasesCollection.createIterator(BASE.ALL);
		for (BaseRepresentation base : baseIterator) {
			if (base.getBaseType().equals(BASE.BASES)) continue; // Dealing with randomness separately.
			if (base.getBaseType().equals(BASE.BASE0)) {
				if (completedBase0) {
					throw new IllegalStateException("Base R_0 encoding the master secret key msk cannot be included multiple times.");
				} else {
					completedBase0 = true;
				}
			}

				basesProduct =
						basesProduct.multiply(
								base.getBase().modPow(base.getExponent()));
			}


			BigInteger v = sigma.getV();
			Assert.notNull(v, "The element v of the signature was null.");

			GroupElement Sv = signerPublicKey.getBaseS().modPow(v);
			GroupElement result = Sv.multiply(basesProduct);
			Q = signerPublicKey.getBaseZ().multiply(result.modInverse());

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

		/** 
		 * Checks whether a signature indeed contains all the bases required.
		 * 
		 * @param sigma Signature to analyze.
		 * @param expectedBases Basecollection of bases expected to be present.
		 * 
		 * @return Bases that are missing.
		 */
		public BaseCollection validateEncodedBases(GSSignature sigma, BaseCollection expectedBases) {
			BaseCollection missingBases = expectedBases.clone();
			BaseCollection actualBases = sigma.getEncodedBases();
			if (actualBases == null) return missingBases;

			BaseIterator actualBaseIter = actualBases.createIterator(BASE.ALL);
			for (BaseRepresentation base : actualBaseIter) {
				if (expectedBases.contains(base) && base.getExponent() != null) {
					missingBases.remove(base);
				}
			}
			return missingBases;
		}

		/** 
		 * Checks whether a signature contains unexpected bases.
		 * 
		 * @param sigma Signature to analyze.
		 * @param expectedBases Basecollection of bases expected to be present.
		 * 
		 * @return Bases that are unexpectedly present.
		 */
		public BaseCollection findUnexpectedBases(GSSignature sigma, BaseCollection expectedBases) {
			BaseCollection actualBases = sigma.getEncodedBases();

			BaseIterator expectedBaseIter = expectedBases.createIterator(BASE.ALL);
			for (BaseRepresentation base : expectedBaseIter) {
				if (actualBases.contains(base)) actualBases.remove(base);
			}
			return actualBases;
		}
	}
