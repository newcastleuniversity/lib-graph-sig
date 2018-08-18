package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.Base;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GSProver {
	public static final String URNID = "prover";
	
  private GroupElement baseR;
  private BigInteger modN;
  private GroupElement baseS;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger n_3;
  private ProofStore<Object> proofStore;
  private final KeyGenParameters keyGenParameters;
  private Map<URN, GSCommitment> commitmentMap;
  private GSSignature blindedSignature;
  private BigInteger r_i;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private MessageGatewayProxy messageGateway;
  private static final String SERVER = "server";

  public GSProver(
      final ExtendedPublicKey extendedPublicKey, final KeyGenParameters keyGenParameters) {
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.baseR = extendedPublicKey.getPublicKey().getBaseR();
    this.proofStore = new ProofStore<Object>();
    this.messageGateway = new MessageGatewayProxy(SERVER);
  }

  public Map<URN, GSCommitment> getCommitmentMap() {
    return this.commitmentMap;
  }

  public void computeCommitments(BaseIterator vertexRepresentations)
      throws Exception {
    GSCommitment commitment;
    GroupElement R_i;
    BigInteger m_i;
    GroupElement C_i;

    this.commitmentMap = new HashMap<URN, GSCommitment>();

    int i = 0;
    for (BaseRepresentation vertexRepresentation : vertexRepresentations) {
      R_i = vertexRepresentation.getBase();
      /** TODO check lenght of randomness r */
      r_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());
      m_i = vertexRepresentation.getExponent();
      C_i = baseR.modPow(m_i).multiply(baseS.modPow(r_i));
      commitment = new GSCommitment(R_i, m_i, r_i, baseS, modN);
      commitment.setCommitmentValue(C_i);
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
    blindedSignature = gsSignature.blind();
    storeBlindedGS();
  }

  private void storeBlindedGS() {
    String APrimeURN = "prover.blindedgs.APrime";
    String ePrimeURN = "prover.blindedgs.ePrime";
    String vPrimeURN = "prover.blindedgs.vPrime";

    try {
      proofStore.store(APrimeURN, blindedSignature.getA());
      proofStore.store(ePrimeURN, blindedSignature.getEPrime());
      proofStore.store(vPrimeURN, blindedSignature.getV());
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  public void sendMessage(GSMessage messageToVerifier) {
    messageGateway.send(messageToVerifier);
  }

  public GSMessage receiveMessage() {
    return messageGateway.receive();
  }

  public void close() {
    messageGateway.close();
  }
}
