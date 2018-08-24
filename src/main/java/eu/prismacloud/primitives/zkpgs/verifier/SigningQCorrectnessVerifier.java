package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.math.BigInteger;
import java.util.List;
import java.util.logging.Logger;

/** */
public class SigningQCorrectnessVerifier implements IVerifier {

	private Logger gslog = GSLoggerConfiguration.getGSlog();

	private final KeyGenParameters keyGenParameters;

	private final SignerPublicKey signerPublicKey;
	private final ProofStore<Object> proofStore;

	private BigInteger e;
	private BigInteger hatd;
	private GroupElement A;
	private ProofSignature P_2;

	public SigningQCorrectnessVerifier(SignerPublicKey pk, ProofStore<Object> ps) {

		this.signerPublicKey = pk;
		this.proofStore = ps;
		this.keyGenParameters = pk.getKeyGenParameters();
	}


	@Override
	public GroupElement executeVerification(BigInteger cChallenge) throws ProofStoreException {
		Assert.notNull(A, "Pre-signature value A has not been retrieved from the ProofStore");
		
		BigInteger cPrime = (BigInteger) P_2.get("P_2.cPrime");
		BigInteger hatd = (BigInteger) P_2.get("P_2.hatd");
		
		Assert.notNull(cPrime, "Challenge cPrime was null.");
		Assert.notNull(hatd, "Response hatd was null.");
		
		checkLengths();

		// A is an external input. Check that it is setup for the PK group.
		if (!A.getGroup().getModulus().equals(signerPublicKey.getModN())) {
			throw new IllegalArgumentException("The pre-signature value A is not associated "
					+ "with the modulus of the signer's public key.");
		}
		GroupElement hatA = A.modPow(cPrime.add(hatd.multiply(e)));
		return hatA;
	}
	
	@Override
	public boolean checkLengths() {
		int l_hatd = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

		hatd = (BigInteger) proofStore.get(URN.createZkpgsURN("P_2.hatd"));
		
		return CryptoUtilsFacade.isInPMRange(hatd, l_hatd);
	}

	@Override
	public boolean isSetupComplete() {
		// Always initialized by constructor.
		return true;
	}

	@Override
	public List<URN> getGovernedURNs() {
		throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
	}
}
