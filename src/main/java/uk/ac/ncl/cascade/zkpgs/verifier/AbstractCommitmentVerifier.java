package uk.ac.ncl.cascade.zkpgs.verifier;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNClass;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.BaseIterator;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;

public abstract class AbstractCommitmentVerifier implements IVerifier {

	private final ExtendedPublicKey epk;
	private final ProofStore<Object> proofStore;
	private final BaseCollection baseCollection;
	private final GroupElement commitmentValue;
	private final int commitmentIndex;

	protected AbstractCommitmentVerifier(final GroupElement commitmentValue, 
			final BaseCollection basesInCommitment, final int index, final ExtendedPublicKey epk, final ProofStore<Object> ps) {
		
		Assert.notNull(basesInCommitment, "The commitment bases to be verified must not be null.");
		Assert.notNull(epk, "The extended public key must not be null.");
		Assert.notNull(ps, "The ProofStore must not be null.");

		this.proofStore = ps;
		this.epk = epk;
		this.baseCollection = basesInCommitment;
		this.commitmentValue = commitmentValue;
		this.commitmentIndex = index;
	}

	/**
	 * Executes a compound version of the commitment verification.
	 * 
	 * @param cChallenge a BigInteger challenge.
	 * 
	 * @return a Map of URN and GroupElement witness.
	 * @throws VerificationException if checking lengths or checking legal bases fails
	 */
	@Override
	public Map<URN, GroupElement> executeCompoundVerification(BigInteger cChallenge) throws ProofStoreException, VerificationException {
		Map<URN, GroupElement> verifierWitnessMap = new HashMap<URN, GroupElement>(1);
		GroupElement witness = executeVerification(cChallenge);

		verifierWitnessMap.put(getHatWitnessURN(), witness);

		return verifierWitnessMap;
	}

	@Override
	public GroupElement executeVerification(BigInteger cChallenge) throws ProofStoreException, VerificationException {
		Assert.notNull(cChallenge, "The challenge must not be null.");
		if (!checkLengths()) {
			throw new VerificationException("The proof did not verify. The length check on the responses failed.");
		}

		if (!checkBasesLegal()) {
			throw new VerificationException("The proof did not verify. The Prover used bases not certified in the Signer's extended public key.");
		}

		return computeVerifierWitness(cChallenge);
	}

	private GroupElement computeVerifierWitness(BigInteger cChallenge) {
		Assert.notNull(cChallenge, "The challenge cannot be null.");
		// Combine the commitment public value with the negated challenge.
		GroupElement hatWitness = commitmentValue.modPow(cChallenge.negate());

		// Including the randomness response.
		BigInteger hatRandomness = (BigInteger) proofStore.get(getHatRandomnessURN());
		Assert.notNull(hatRandomness, "The response for the commitment randomness, Commitment " + getCommitmentIndex() + " was found null.");
		hatWitness = hatWitness.multiply(epk.getPublicKey().getBaseS().modPow(hatRandomness));

		// Iterating over all committed bases to include their hat-values
		BaseIterator baseIterator = baseCollection.createIterator(BASE.ALL);
		for (BaseRepresentation base : baseIterator) {
			if (base.getBaseType().equals(BASE.BASES)) continue; // Treating randomness base separately

			BigInteger hatm = (BigInteger) proofStore.get(getURNbyBaseType(base, URNClass.HAT));
			Assert.notNull(hatm, "The message response for base " + base.getBaseIndex() + "was found null.");
			hatWitness = hatWitness.multiply(base.getBase().modPow(hatm));
		}

		return hatWitness;
	}

	@Override
	public boolean checkLengths() {
		// Evaluating the length of the commitment randomness response.
		BigInteger hatRandomness = (BigInteger) proofStore.get(getHatRandomnessURN());

		// Evaluating the lengths of the message responses.
		// We are addressing VERTEX, EDGE and MSK in turn.
		boolean messageLengthCheck = true;
		if (!isVerifyingEquality()) {
			BaseIterator baseIterator = baseCollection.createIterator(BASE.ALL);
			for (BaseRepresentation base : baseIterator) {
				if (base.getBaseType().equals(BASE.BASES)) continue; // Treating randomness base separately

				BigInteger hatm = (BigInteger) proofStore.get(getURNbyBaseType(base, URNClass.HAT));
				if (!CryptoUtilsFacade.isInPMRange(hatm, getHatMessageBitlength())) messageLengthCheck = false;
			}
		}
		return CryptoUtilsFacade.isInPMRange(hatRandomness, getHatRandomnessBitlength())
				&& messageLengthCheck;
	}

	/**
	 * Validates whether all bases in the base collection offered to this verifier
	 * are valid with respect to the given extended public key.
	 * 
	 * @return <tt>true</tt> if and only if all bases included are valid.
	 */
	public boolean checkBasesLegal() {
		BaseIterator baseIterator = baseCollection.createIterator(BASE.ALL);
		while (baseIterator.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) baseIterator.next();
			if (!epk.isValidBase(base)) return false;
		}
		return true;
	}

	/**
	 * Return the keygen params of the public key.
	 * 
	 * @return keygen params.
	 */
	protected KeyGenParameters getKeyGenParams() {
		return epk.getKeyGenParameters();
	}

	/**
	 * Returns the index of this commitment, -1 if the commitment is not enumeratable.
	 * 
	 * @return non-negative index if enumerable, -1 if not enumerable.
	 */
	protected int getCommitmentIndex() {
		return this.commitmentIndex;
	}

	protected URN getURNbyBaseType(BaseRepresentation base, URNClass urnClass) {
		return URNType.buildURNbyBaseType(base, urnClass, this.getClass());
	}


	protected abstract URN getHatWitnessURN();

	protected abstract int getHatRandomnessBitlength();

	protected int getHatMessageBitlength() {
		return getKeyGenParams().getL_m() + getKeyGenParams().getL_statzk()
				+ getKeyGenParams().getL_H() + 1;
	};

	protected abstract URN getHatRandomnessURN();
	protected abstract URN getHatVertexURN(int baseIndex);
	protected abstract URN getHatEdgeURN(int baseIndex);
	protected abstract URN getHatM0URN();
	protected abstract URN getHatMURN();

	/**
	 * States whether this commitment prover is proving equality of its secret
	 * exponents to messages that have established in other component provers.
	 * 
	 * <p>As a consequence the prover will not create witness randomness
	 * itself but use the witness randomness already given.
	 *  
	 * @return <tt>true</tt> if the prover relies on witness randomness for messages
	 * created by other provers.
	 */
	protected abstract boolean isVerifyingEquality();

	/**
	 * States whether this commitment prover is restricted to encoding a 
	 * single message on a single base R.
	 *  
	 * @return <tt>true</tt> if the prover uses only a single base R.
	 */
	protected abstract boolean isRestrictedToSingleton();
}
