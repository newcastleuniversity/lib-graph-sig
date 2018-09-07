package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.prover.SigningQCorrectnessProver;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/** */
public class SigningQCorrectnessVerifier implements IVerifier {

	//private Logger gslog = GSLoggerConfiguration.getGSlog();

	private final KeyGenParameters keyGenParameters;

	private final SignerPublicKey signerPublicKey;
	private final ProofStore<Object> proofStore;

	private final BigInteger e;
	private BigInteger hatd;
	private final GroupElement A;
	private final ProofSignature P_2;
	private final GSSignature sigma;

	public SigningQCorrectnessVerifier(
			final ProofSignature P_2,
			final GSSignature sigma,
			final SignerPublicKey pk,
			final ProofStore<Object> ps) {

		Assert.notNull(P_2, "Pre-signature ProofSignature P_2 has been found to be null.");
		Assert.notNull(sigma, "Pre-signature sigma has been found to be null.");
		Assert.notNull(pk, "The signer public key has been found to be null.");
		Assert.notNull(ps, "The ProofStore has been found to be null.");

		this.signerPublicKey = pk;
		this.proofStore = ps;
		this.keyGenParameters = pk.getKeyGenParameters();
		this.P_2 = P_2;
		this.sigma = sigma;
		this.A = this.sigma.getA();
		this.e = this.sigma.getE();
		Assert.notNull(this.A, "Pre-signature value A has been found to be null.");
		Assert.notNull(this.e, "Pre-signature value e has been found to be null.");
	}

	@Override
	public GroupElement executeVerification(BigInteger cPrime) throws ProofStoreException {
		Assert.notNull(A, "Pre-signature value A has been found to be null.");

		Assert.notNull(cPrime, "Challenge cPrime was null.");

		// BigInteger cPrime = (BigInteger) P_2.get("P_2.cPrime");
		BigInteger hatd = (BigInteger) P_2.get("P_2.hatd");
		Assert.notNull(hatd, "Response hatd was null.");

		checkLengths();

		// A is an external input. Check that it is setup for the PK group.
		if (!A.getGroup().getModulus().equals(signerPublicKey.getModN())) {
			throw new IllegalArgumentException(
					"The pre-signature value A is not associated "
							+ "with the modulus of the signer's public key.");
		}
		GroupElement hatA = A.modPow(cPrime.add(hatd.multiply(e)));

		String hatAURN = URNType.buildURNComponent(URNType.HATA, SigningQCorrectnessProver.class);
		proofStore.store(hatAURN, hatA);
		
		return hatA;
	}

	@Override
	public Map<URN, GroupElement> executeCompoundVerification(BigInteger cPrime) throws ProofStoreException {
		Map<URN, GroupElement> responses = new HashMap<URN, GroupElement>();
		String hatAURN = URNType.buildURNComponent(URNType.HATA, SigningQCorrectnessProver.class);
		responses.put(URN.createZkpgsURN(hatAURN), executeVerification(cPrime));

		return responses;
	}

	@Override
	public boolean checkLengths() {
		int l_hatd = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

		hatd = (BigInteger) P_2.get("P_2.hatd");

		return CryptoUtilsFacade.isInPMRange(hatd, l_hatd);
	}

	@Override
	public List<URN> getGovernedURNs() {
		throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
	}
}
