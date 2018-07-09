package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/** The type Commitment verifier. */
public class CommitmentVerifier implements IVerifier {

  private BigInteger hatvPrime;
  private BigInteger hatm_0;
  private GSCommitment U;
  private BigInteger c;
  private GroupElement baseS;
  private GroupElement baseZ;
  private GroupElement baseR_0;
  private GroupElement S;
  private GroupElement Z;
  private GroupElement R_0;
  private BigInteger n_1;
  private BigInteger modN;
  private STAGE proofStage;
  private Map<URN, BaseRepresentation> baseRepresentationMap;
  private KeyGenParameters keyGenParameters;
  private GroupElement hatU;
  private List<BigInteger> challengeList;
  private BigInteger hatc;
  private BigInteger cChallenge;
  private Map<URN, BigInteger> responses;
  private ProofStore<Object> proofStore;
  private GSCommitment gscommitment;
  private GroupElement witness;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  public enum STAGE {
    ISSUING,
    VERIFYING
  };

  public GroupElement computeWitness(
      final BigInteger cChallenge,
      final Map<URN, BigInteger> responses,
      final ProofStore<Object> proofStore,
      final ExtendedPublicKey extendedPublicKey,
      final KeyGenParameters keyGenParameters,
      final STAGE proofStage) {

    /** TODO finish implementation for computeWitness in commmitment verifier */
    this.cChallenge = cChallenge;
    this.responses = responses;
    this.proofStore = proofStore;
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseRepresentationMap = extendedPublicKey.getBases();
    this.keyGenParameters = keyGenParameters;
    this.proofStage = proofStage;

    if (STAGE.ISSUING == proofStage) {

      checkLengthsIssuing(responses, keyGenParameters);

      witness = computehatUIssuing();

    } else if (STAGE.VERIFYING == proofStage) {
      /** TODO finish implementation for verifying stage */
    }

    return witness;
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

    gslog.info("hatm_0 bitlength: " + hatm_0.bitLength());
    gslog.info("messageLength: " + messageLength);
    Assert.checkBitLength(hatm_0, messageLength - 1, "length of hatm_0 is not correct ");
    Assert.checkBitLength(hatvPrime, hatvPrimeLength - 1, "length of hatvPrime is not correct ");

    for (BigInteger response : responses.values()) {
      if (!(response == hatvPrime)) {
        Assert.checkBitLength(response, messageLength - 1, " response length is not correct");
      }
    }
  }

  private void checkLengthsVerifying() {
    /** TODO finish implementation for checkLengths when in verifying stage */
  }

  /** Computehat U. */
  public GroupElement computehatUIssuing() {

    Map<URN, BigInteger> exponentsU = new HashMap<>();
    Map<URN, GroupElement> basesU = new HashMap<>();

    String uCommitmentURN = "recipient.U";
    U = (GSCommitment) proofStore.retrieve(uCommitmentURN);
    cChallenge = (BigInteger) proofStore.retrieve("proofsignature.P_1.c");

    populateExponents(exponentsU);

    populateBases(basesU);

    GroupElement valueU = U.getCommitmentValue();

    gslog.info("valueU: " + valueU);

    hatU =
        valueU
            .modPow(cChallenge.negate())
            .multiply(new QRElement(baseS.getGroup(), CryptoUtilsFacade.computeMultiBaseExMap(basesU, exponentsU, modN)));
    return hatU;
  }

  private void populateBases(Map<URN, GroupElement> basesMap) {
    basesMap.put(URN.createZkpgsURN("baseRepresentationMap.S"), baseS);
    //    basesMap.put(URN.createZkpgsURN("baseRepresentationMap.R_0"),R_0);

    for (Map.Entry<URN, BaseRepresentation> baseRepresentation : baseRepresentationMap.entrySet()) {
      basesMap.put(baseRepresentation.getKey(), baseRepresentation.getValue().getBase());
    }
  }

  private void populateExponents(Map<URN, BigInteger> exponentsMap) {
    exponentsMap.put(URN.createZkpgsURN("exponents.hatvPrime"), hatvPrime);
    //    exponentsMap.put(URN.createZkpgsURN("exponents.hatm_0"), hatm_0);

    for (Map.Entry<URN, BaseRepresentation> baseRepresentation : baseRepresentationMap.entrySet()) {
      exponentsMap.put(baseRepresentation.getKey(), baseRepresentation.getValue().getExponent());
    }
  }
}
