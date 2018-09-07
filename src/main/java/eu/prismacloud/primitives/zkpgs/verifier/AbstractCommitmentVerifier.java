package eu.prismacloud.primitives.zkpgs.verifier;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.IURNGoverner;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNClass;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier.STAGE;

public abstract class AbstractCommitmentVerifier implements IVerifier {

	private final SignerPublicKey signerPublicKey;
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;
	private final int commitmentIndex;

	protected AbstractCommitmentVerifier(final int index, final SignerPublicKey pk, final ProofStore<Object> ps) {
		
		this.proofStore = ps;
		this.signerPublicKey = pk;
		this.keyGenParameters = this.signerPublicKey.getKeyGenParameters();
		this.commitmentIndex = index;
	}
	
	@Override
	public Map<URN, GroupElement> executeCompoundVerification(BigInteger cChallenge) throws ProofStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public GroupElement executeVerification(BigInteger cChallenge) throws ProofStoreException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean checkLengths() {
		// TODO Auto-generated method stub
		return false;
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
	
	protected URN getURNbyBaseType(BaseRepresentation base, URNClass urnClass) {
			return URNType.buildURNbyBaseType(base, urnClass, this.getClass());
	}


	protected abstract URN getWitnessURN();

	protected abstract URN getTildeRandomnessURN();
	protected abstract int getTildeRandomnessBitlength();

	protected int getTildeMessageBitLength() {
		return getKeyGenParams().getL_m() + getKeyGenParams().getL_statzk()
				+ getKeyGenParams().getL_H() + 1;
	};

	protected abstract URN getTildeVertexURN(int baseIndex);
	protected abstract URN getTildeEdgeURN(int baseIndex);
	protected abstract URN getTildeM0URN();
	protected abstract URN getTildeMURN();

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
	protected abstract boolean isProvingEquality();

	/**
	 * States whether this commitment prover is restricted to encoding a 
	 * single message on a single base R.
	 *  
	 * @return <tt>true</tt> if the prover uses only a single base R.
	 */
	protected abstract boolean isRestrictedToSingleton();
}
