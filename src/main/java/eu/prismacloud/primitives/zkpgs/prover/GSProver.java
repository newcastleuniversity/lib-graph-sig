package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GSProver { // implements IProver {

  private final BigInteger modN;
  private final BigInteger baseS;
  private BigInteger n_3;
  private final ProofStore<Object> proofStore;
  private final KeyGenParameters keyGenParameters;
  private BigInteger r;
  private Map<URN, GSCommitment> commitmentMap;
  private GSSignature blindedSignature;
  private BigInteger r_i;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private IMessageGateway messageGateway;

  public GSProver(
      final BigInteger modN,
      final GroupElement baseS,
      final BigInteger n_3,
      final ProofStore<Object> proofStore,
      final KeyGenParameters keyGenParameters) {

    this.modN = modN;
    this.baseS = baseS.getValue();
    this.n_3 = n_3;
    this.proofStore = proofStore;
    this.keyGenParameters = keyGenParameters;
  }

  public GSProver(
      final BigInteger modN,
      final GroupElement baseS,
      final ProofStore<Object> proofStore,
      final KeyGenParameters keyGenParameters) {

    this.modN = modN;
    this.baseS = baseS.getValue();
    this.proofStore = proofStore;
    this.keyGenParameters = keyGenParameters;
  }

  public Map<URN, GSCommitment> getCommitmentMap() {
    return this.commitmentMap;
  }

  public void computeCommitments(Map<URN, BaseRepresentation> vertexRepresentations)
      throws Exception {
    GSCommitment commitment;
    BigInteger R_i;
    BigInteger m_i;
    BigInteger C_i;

    this.commitmentMap = new HashMap<>();

    int i = 0;
    for (BaseRepresentation vertexRepresentation : vertexRepresentations.values()) {
      R_i = vertexRepresentation.getBase().getValue();
      /** TODO check lenght of randomness r */
      r_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());
      m_i = vertexRepresentation.getExponent();
      C_i = R_i.modPow(m_i, modN).multiply(baseS.modPow(r, modN));
      commitment = new GSCommitment(R_i, m_i, r_i, baseS, modN);
      String commitmentURN = "prover.commitments.C_" + i;
      commitmentMap.put(
          URN.createURN(URN.getZkpgsNameSpaceIdentifier(), commitmentURN), commitment);
      proofStore.store(commitmentURN, commitment);

      i++;
    }

    String commmitmentMapURN = "prover.commitments.C_i";
    proofStore.store(commmitmentMapURN, commitmentMap);
  }

  public void computeBlindedSignature(GSSignature gsSignature) {
    blindedSignature =
        gsSignature.blind(gsSignature.getA(), gsSignature.getE(), gsSignature.getV());
    storeBlindedGS();
  }

  private void storeBlindedGS() {
    String APrimeURN = "prover.blindedgs.APrime";
    String ePrimeURN = "prover.blindedgs.ePrime";
    String vPrimeURN = "prover.blindedgs.vPrime";

    try {
      proofStore.store(APrimeURN, blindedSignature.getA());
      proofStore.store(ePrimeURN, blindedSignature.getE());
      proofStore.store(vPrimeURN, blindedSignature.getV());
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  public void sendMessage(GSMessage signerMessageToRecipient, Object target) {
    messageGateway.sendMessage(signerMessageToRecipient, target);
  }
}
