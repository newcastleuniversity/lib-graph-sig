package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessagePartner;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GSProver implements IMessagePartner {
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
      final ExtendedPublicKey extendedPublicKey,
      final ProofStore<Object> proofStore) {
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.baseR = extendedPublicKey.getPublicKey().getBaseR();
    this.proofStore = proofStore;
    this.messageGateway = new MessageGatewayProxy(SERVER);
  }
  
  public void init() throws IOException {
	  this.messageGateway.init();
  }

  public Map<URN, GSCommitment> getCommitmentMap() {
    return this.commitmentMap;
  }

  public void computeCommitments(BaseIterator vertexRepresentations) throws ProofStoreException  {
    GSCommitment commitment;
    
    this.commitmentMap = new HashMap<URN, GSCommitment>();

    for (BaseRepresentation vertexRepresentation : vertexRepresentations) {
      GroupElement R_i = vertexRepresentation.getBase();
      /** TODO check length of randomness r */
      r_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());
      BigInteger m_i = vertexRepresentation.getExponent();
      GroupElement C_i = baseR.modPow(m_i).multiply(baseS.modPow(r_i));
      commitment = GSCommitment.createCommitment(m_i, R_i,  extendedPublicKey);
//      commitment.setCommitmentValue(C_i);
      String commitmentURN = "prover.commitments.C_" + vertexRepresentation.getBaseIndex();
      commitmentMap.put(
          URN.createURN(URN.getZkpgsNameSpaceIdentifier(), commitmentURN), commitment);
      proofStore.store(commitmentURN, commitment);
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

  public void sendMessage(GSMessage messageToVerifier) throws IOException {
    messageGateway.send(messageToVerifier);
  }

  public GSMessage receiveMessage() throws IOException {
    return messageGateway.receive();
  }

  public void close() throws IOException {
    messageGateway.close();
  }
}
