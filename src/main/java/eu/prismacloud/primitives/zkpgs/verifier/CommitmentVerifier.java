package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementN;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * The type Commitment verifier.
 */
public class CommitmentVerifier implements IVerifier {

	private Logger gslog = GSLoggerConfiguration.getGSlog();

	private BigInteger hatvPrime;
	private BigInteger hatm_0;
	private GSCommitment U;
	private final GroupElement baseS;
	private final GroupElement baseR_0;
	private final STAGE proofStage;
	private Map<URN, BaseRepresentation> baseRepresentationMap;
	private final KeyGenParameters keyGenParameters;
	private GroupElement hatU;
	private BigInteger hatc;
	private BigInteger cChallenge;
	private Map<URN, BigInteger> responses;
	private final ProofStore<Object> proofStore;
	private final ExtendedPublicKey extendedPublicKey;
//	private GSCommitment gscommitment;
	private GroupElement witness;
	private BigInteger hatr_i;
	private BigInteger hatm_i;
	private final GroupElement baseR;

	public enum STAGE {
		ISSUING,
		VERIFYING
	};
	
	public CommitmentVerifier(final STAGE proofStage, ExtendedPublicKey epk, ProofStore<Object> ps) {
		this.proofStore = ps;
		this.extendedPublicKey = epk;
		this.baseS = this.extendedPublicKey.getPublicKey().getBaseS();
		this.baseR_0 = this.extendedPublicKey.getPublicKey().getBaseR_0();
		this.baseR = this.extendedPublicKey.getPublicKey().getBaseR();
		this.keyGenParameters = this.extendedPublicKey.getKeyGenParameters();
		this.proofStage = proofStage;
	}

	public GroupElement computeWitness(
			final BigInteger cChallenge,
			final Map<URN, BigInteger> responses) {

		this.cChallenge = cChallenge;
		this.responses = responses;


		if (STAGE.ISSUING == proofStage) {

			checkLengthsIssuing(responses, keyGenParameters);

			witness = computehatUIssuing();

		} else if (STAGE.VERIFYING == proofStage) {

			witness = computeHatCVerifying(null); //TODO this implementation is faulty. Should iterate over hat values.
		}

		return witness;
	}

	public GroupElement computeWitness(
			final BigInteger cChallenge,
			final BaseRepresentation vertex) throws VerificationException {


		if (!checkLengthsVerifying(vertex)) {
			throw new VerificationException("Lengths could not be verified.");
		}

		witness = computeHatCVerifying(vertex);
		return witness;
	}

	private GroupElement computeHatCVerifying(BaseRepresentation vertex) {
		String commitmentURN = "prover.commitments.C_" + vertex.getBaseIndex();
		GroupElement baseRHatm_i = baseR.modPow(hatm_i);
		GroupElement baseSHatr_i = baseS.modPow(hatr_i);

		GSCommitment commitment = (GSCommitment) proofStore.retrieve(commitmentURN);
		GroupElement hatC_i =
				commitment
				.getCommitmentValue()
				.modPow(cChallenge.negate())
				.multiply(baseRHatm_i)
				.multiply(baseSHatr_i);
		return hatC_i;
	}

	public boolean checkLengthsVerifying(BaseRepresentation vertex) {

		int l_hatr =
				keyGenParameters.getL_n() + keyGenParameters.getProofOffset();
		int l_hatm =
				keyGenParameters.getL_m() + keyGenParameters.getProofOffset() + 1;


		hatr_i = (BigInteger) proofStore.retrieve("commitmentprover.responses.vertex.hatr_i_" + vertex.getBaseIndex());

		hatm_i = (BigInteger) proofStore.retrieve("possessionprover.responses.vertex.hatm_i_" + vertex.getBaseIndex());

		gslog.info("hatr in range: " + CryptoUtilsFacade.isInPMRange(hatr_i, l_hatr));
		gslog.info("hatm in range: " + CryptoUtilsFacade.isInPMRange(hatm_i, l_hatm));

		return CryptoUtilsFacade.isInPMRange(hatr_i, l_hatr) && CryptoUtilsFacade.isInPMRange(hatm_i, l_hatm);

	}

	private void checkLengthsIssuing(
			Map<URN, BigInteger> responses, KeyGenParameters keyGenParameters) {
		int hatvPrimeLength =
				keyGenParameters.getL_n()
				+ (2 * keyGenParameters.getL_statzk())
				+ keyGenParameters.getL_H()
				+ 1;

		int messageLength =
				keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 2;

		hatvPrime = (BigInteger) proofStore.retrieve("proofsignature.P_1.hatvPrime");
		hatm_0 = (BigInteger) proofStore.retrieve("proofsignature.P_1.hatm_0");

		Assert.checkBitLength(hatm_0, messageLength - 1, "length of hatm_0 is not correct ");
		Assert.checkBitLength(hatvPrime, hatvPrimeLength - 1, "length of hatvPrime is not correct ");

		for (BigInteger response : responses.values()) {
			if (!(response == hatvPrime)) {
				Assert.checkBitLength(response, messageLength - 1, " response length is not correct");
			}
		}
	}

	/**
	 * Computehat U.
	 * @return the group element
	 */
	public GroupElement computehatUIssuing() {

		Map<URN, BigInteger> exponentsMap = new HashMap<>();
		Map<URN, GroupElement> baseMap = new HashMap<>();

		//    BigInteger R_0hatm_0 = baseR_0.modPow(hatm_0).getValue();
		baseMap.put(URN.createZkpgsURN("commitment.baseR_0"), baseR_0);
		exponentsMap.put(URN.createZkpgsURN("commitment.hatm_0"), hatm_0);

		String uCommitmentURN = "recipient.U";
		U = (GSCommitment) proofStore.retrieve(uCommitmentURN);
		gslog.info("commitment U:  " + U.getCommitmentValue());
		cChallenge = (BigInteger) proofStore.retrieve("proofsignature.P_1.c");
		gslog.info("c challenge: " + cChallenge);
		//    populateExponents(exponentsMap);

		//    populateBases(baseMap);

		GroupElement valueU = U.getCommitmentValue();

		gslog.info("valueU: " + valueU);
		baseMap.put(URN.createZkpgsURN("commitment.S"), baseS);
		exponentsMap.put(URN.createZkpgsURN("commitments.hatvPrime"), hatvPrime);
		baseMap.put(URN.createZkpgsURN("recipient.U"), U.getCommitmentValue());
		exponentsMap.put(URN.createZkpgsURN("recipient.c"), cChallenge);

		//    QRElement qr1 = new QRElementN(baseS.getGroup(), BigInteger.ONE);
		//    GroupElement multiBaseResult = qr1.multiBaseExpMap(baseMap, exponentsMap);
		GroupElement negU = valueU.modPow(cChallenge.negate());

		hatU = negU.multiply(baseS.modPow(hatvPrime)).multiply(baseR_0.modPow(hatm_0));
		// qr1.multiBaseExpMap(baseMap, exponentsMap); //
		// valueU.modPow(cChallenge.negate()).multiply(multiBaseResult);
		gslog.info("hatU: " + hatU);
		return hatU;
	}


        @Override
        public GroupElement executeVerification (BigInteger cChallenge) throws ProofStoreException {
                throw new ProofStoreException("");
        }

        @Override
        public Map<URN, GroupElement> executeCompoundVerification (BigInteger cChallenge) throws ProofStoreException {
            throw new ProofStoreException("");
        }

        @Override
        public List<URN> getGovernedURNs () {
            throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
        }

        @Override
        public boolean checkLengths () {
            // TODO Auto-generated method stub
            return false;
        }
    }
