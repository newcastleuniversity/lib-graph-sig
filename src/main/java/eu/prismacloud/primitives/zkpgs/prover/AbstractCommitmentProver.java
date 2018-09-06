package eu.prismacloud.primitives.zkpgs.prover;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.CommitmentProver.STAGE;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

public abstract class AbstractCommitmentProver implements IProver {

	private final SignerPublicKey signerPublicKey;
	private final int commitmentIndex;
	private final ProofStore<Object> proofStore;
	private final GSCommitment com;
	protected final BaseCollection baseCollection;
	private transient BigInteger cChallenge;
	private transient GroupElement witness;

	/**
	 * Establishes a CommitmentProver.
	 *
	 * @param com commitment to be proven.
	 * @param index of the commitment to be proven.
	 * @param spk Signer Public Key to be used.
	 * @param ps  ProofStore to be used.
	 */
	AbstractCommitmentProver(final GSCommitment com, final int index, final SignerPublicKey spk, final ProofStore<Object> ps) {
		Assert.notNull(com, "Commitment must not be null.");
		Assert.notNull(index, "Index must not be null.");
		Assert.notNull(ps, "The ProofStore must not be null.");
		Assert.notNull(spk, "Signer public key must not be null.");

		this.signerPublicKey = spk;
		this.commitmentIndex = index;
		this.proofStore = ps;
		this.com = com;
		this.baseCollection = com.getBaseCollection();
	}

	@Override
	public void executePrecomputation() throws ProofStoreException {
		// NO PRE-COMPUTATION IS NEEDED: NO-OP.
	}

	@Override
	public GroupElement executePreChallengePhase() throws ProofStoreException {
		establishWitnessRandomness();

		this.witness = computeWitness();
		return witness;
	}

	/**
	 * Executes the pre-challenge phase with a compound interface, returning a Map.
	 * The method computes the witness randomness for the secret messages and then a
	 * single tilde-value to represent the commitment value in the proof.
	 * 
	 * @return singleton Map of resulting GroupElement tilde-value. 
	 */
	@Override
	public Map<URN, GroupElement> executeCompoundPreChallengePhase() throws ProofStoreException {
		Map<URN, GroupElement> witnessMap = new HashMap<URN, GroupElement>(1);
		GroupElement witness = executePreChallengePhase();

		witnessMap.put(getWitnessURN(), witness);

		return witnessMap;
	}

	/**
	 * Computes the witness randomness named appropriate for the subclass
	 * and stores the witness randomness in the ProofStore.
	 * 
	 * @throws ProofStoreException if the witness randomness could not be written
	 * to the ProofStore.
	 */
	private void establishWitnessRandomness() throws ProofStoreException {
		// Establishing the witness randomness for the commitment randomness.
		BigInteger tildeRandomness = CryptoUtilsFacade.computeRandomNumberMinusPlus(getTildeRandomnessBitlength());
		proofStore.save(getTildeRandomnessURN(), tildeRandomness);

		// Establishing the witness randomness for all message exponents.
		// We are addressing VERTEX, EDGE and MSK in turn.
		if (!isProvingEquality()) {
			BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
			for (BaseRepresentation base : vertexIterator) {
				BigInteger tilde_m_i = CryptoUtilsFacade.computeRandomNumberMinusPlus(getTildeMessageBitLength());
				proofStore.save(getTildeVertexURN(base.getBaseIndex()), tilde_m_i);
			}

			BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
			for (BaseRepresentation base : edgeIterator) {
				BigInteger tilde_m_i_j = CryptoUtilsFacade.computeRandomNumberMinusPlus(getTildeMessageBitLength());
				proofStore.save(getTildeEdgeURN(base.getBaseIndex()), tilde_m_i_j);
			}

			BaseIterator baseR0Iterator = baseCollection.createIterator(BASE.BASE0);
			for (@SuppressWarnings("unused") BaseRepresentation base : baseR0Iterator) {
				BigInteger tilde_m_0 = CryptoUtilsFacade.computeRandomNumberMinusPlus(getTildeMessageBitLength());
				proofStore.save(getTildeM0URN(), tilde_m_0);
			}
		}
	}

	/** 
	 * Computes the witness from the established witness randomness.
	 * The method assumes that the witness randomness has been stored in the 
	 * ProofStore.
	 * 
	 * @return the GroupElement witness corresponding to the witness randomness
	 * and the public values (bases), e.g., tildeU or tildeC_i.
	 * 
	 * @throws ProofStoreException
	 */
	private GroupElement computeWitness() throws ProofStoreException {
		// Establishing the blinding randomness witness
		BigInteger tildeRandomness = (BigInteger) proofStore.get(getTildeRandomnessURN());
		GroupElement witness = signerPublicKey.getBaseS().modPow(tildeRandomness);

		// Computations for all bases and corresponding witness randomness.
		// We are addressing VERTEX, EDGE and MSK in turn.
		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation base : vertexIterator) {
			BigInteger tilde_m_i = (BigInteger) proofStore.get(getTildeVertexURN(base.getBaseIndex()));
			witness = witness.multiply(base.getBase().modPow(tilde_m_i));
		}

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation base : edgeIterator) {
			BigInteger tilde_m_i_j = (BigInteger) proofStore.get(getTildeEdgeURN(base.getBaseIndex()));
			witness = witness.multiply(base.getBase().modPow(tilde_m_i_j));
		}

		BaseIterator baseR0Iterator = baseCollection.createIterator(BASE.BASE0);
		for (BaseRepresentation base : baseR0Iterator) {
			BigInteger tilde_m_0 = (BigInteger) proofStore.get(getTildeM0URN());
			witness = witness.multiply(base.getBase().modPow(tilde_m_0));
		}

		return witness;
	}

	@Override
	public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge) throws ProofStoreException {
		this.cChallenge = cChallenge;

		Map<URN, BigInteger> responses = new HashMap<URN, BigInteger>();

		// Response for randomness		
		{
			BigInteger tildeRandomness = (BigInteger) proofStore.get(getTildeRandomnessURN());
			BigInteger hatRandomness = tildeRandomness.add(cChallenge.multiply(com.getRandomness()));
			proofStore.save(getHatRandomnessURN(), hatRandomness);
			responses.put(getHatRandomnessURN(), hatRandomness);
		}

		// Establishing the witness randomness for all message exponents.
		// We are addressing VERTEX, EDGE and MSK in turn.
		if (!isProvingEquality()) {
			BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
			for (BaseRepresentation base : vertexIterator) {
				BigInteger tilde_m_i = (BigInteger) proofStore.get(getTildeVertexURN(base.getBaseIndex()));
				BigInteger m_i = (BigInteger) base.getExponent();
				BigInteger hat_m_i = tilde_m_i.add(cChallenge.multiply(m_i));
				proofStore.save(getHatVertexURN(base.getBaseIndex()), hat_m_i);
				responses.put(getHatVertexURN(base.getBaseIndex()), hat_m_i);
			}

			BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
			for (BaseRepresentation base : edgeIterator) {
				BigInteger tilde_m_i_j = (BigInteger) proofStore.get(getTildeEdgeURN(base.getBaseIndex()));
				BigInteger m_i_j = (BigInteger) base.getExponent();
				BigInteger hat_m_i_j = tilde_m_i_j.add(cChallenge.multiply(m_i_j));
				proofStore.save(getHatEdgeURN(base.getBaseIndex()), hat_m_i_j);
				responses.put(getHatEdgeURN(base.getBaseIndex()), hat_m_i_j);
			}

			BaseIterator baseR0Iterator = baseCollection.createIterator(BASE.BASE0);
			for (BaseRepresentation base : baseR0Iterator) {
				BigInteger tilde_m_0 = (BigInteger) proofStore.get(getTildeM0URN());
				BigInteger m_0 = (BigInteger) base.getExponent();
				BigInteger hat_m_0 = tilde_m_0.add(cChallenge.multiply(m_0));
				proofStore.save(getHatM0URN(), hat_m_0);
				responses.put(getHatM0URN(), hat_m_0);
			}
		}

		return responses;
	}

	/**
	 * Self-verifies the proof responses of the CommitmentProver.
	 *
	 * <p>It is required that the bases raised to the responses 
	 * multiplied by the public value of the commitment to the negated
	 * challenge yields the witness.
	 *
	 * @return <tt>true</tt> if the response values are computed correctly. If verify() is called
	 *     before the challenge is submitted, the method always returns <tt>false</tt>.
	 */
	@Override
	public boolean verify() {
		if (this.cChallenge == null || this.witness == null) return false;

		// Establish the public commitment value to the negated challenge.
		GroupElement hatWitness = com.getCommitmentValue().modPow(cChallenge.negate());

		try {		
			// Include the commitment randomness
			BigInteger hatRandomness = (BigInteger) proofStore.get(getHatRandomnessURN());
			hatWitness.multiply(signerPublicKey.getBaseS().modPow(hatRandomness));

			// Iterate over the message hat values, considering VERTEX, EDGE and m_0 in turn
			BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
			for (BaseRepresentation base : vertexIterator) {
				BigInteger hat_m_i = (BigInteger) proofStore.get(getHatVertexURN(base.getBaseIndex()));
				hatWitness.multiply(base.getBase().modPow(hat_m_i));
			}

			BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
			for (BaseRepresentation base : edgeIterator) {
				BigInteger hat_m_i_j = (BigInteger) proofStore.get(getHatEdgeURN(base.getBaseIndex()));
				hatWitness.multiply(base.getBase().modPow(hat_m_i_j));
			}

			BaseIterator baseR0Iterator = baseCollection.createIterator(BASE.BASE0);
			for (BaseRepresentation base : baseR0Iterator) {
				BigInteger hat_m_0 = (BigInteger) proofStore.get(getHatM0URN());
				hatWitness.multiply(base.getBase().modPow(hat_m_0));
			}
		} catch (NullPointerException e) {
			// Intentionally not throwing an exception. Verify() should be safe to call.
			return false;
		}

		return (this.witness.equals(hatWitness));
	}

	/**
	 * Return the keygen params of the public key.
	 * 
	 * @return keygen params.
	 */
	protected KeyGenParameters getKeyGenParams() {
		return signerPublicKey.getKeyGenParameters();
	}

	/**
	 * Returns the index of this commitment, -1 if the commitment is not enumeratable.
	 * 
	 * @return non-negative index if enumerable, -1 if not enumerable.
	 */
	protected int getCommitmentIndex() {
		return this.commitmentIndex;
	}


	protected abstract URN getWitnessURN();

	protected abstract URN getTildeRandomnessURN();
	protected abstract URN getTildeRandomnessURN(int index);
	protected abstract int getTildeRandomnessBitlength();

	protected int getTildeMessageBitLength() {
		return getKeyGenParams().getL_m() + getKeyGenParams().getL_statzk()
				+ getKeyGenParams().getL_H() + 1;
	};

	protected abstract URN getTildeVertexURN(int baseIndex);
	protected abstract URN getTildeEdgeURN(int baseIndex);
	protected abstract URN getTildeM0URN();

	protected abstract URN getHatRandomnessURN();
	protected abstract URN getHatRandomnessURN(int index);
	protected abstract URN getHatVertexURN(int baseIndex);
	protected abstract URN getHatEdgeURN(int baseIndex);
	protected abstract URN getHatM0URN();

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
	protected abstract boolean isProvingEquality();
}
