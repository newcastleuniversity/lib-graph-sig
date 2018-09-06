package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Establishes the correctness of the Signer's Strong RSA signature, with Q as pre-signing value.
 */
public class SigningQCorrectnessProver implements IProver {

  public static final String URNID = "issuing.signer";

  private Logger gslog = GSLoggerConfiguration.getGSlog();

  private final ProofStore<Object> proofStore;
  private final SignerPublicKey signerPublicKey;
  private final SignerPrivateKey signerPrivateKey;
  private final KeyGenParameters keyGenParameters;
  private final GSSignature gsSignature;
  private final BigInteger n_2;
  private BigInteger tilded;
  private BigInteger hatd;
  private BigInteger d;
  private GroupElement Q;
  
  public SigningQCorrectnessProver(
      final GSSignature gsSignature,
      final BigInteger n_2,
      final SignerKeyPair skp,
      final ProofStore<Object> ps) {
    this.proofStore = ps;
    this.signerPublicKey = skp.getPublicKey();
    this.signerPrivateKey = skp.getPrivateKey();
    this.gsSignature = gsSignature;
    this.keyGenParameters = skp.getKeyGenParameters();
    this.n_2 = n_2;
  }

  @Override
  public void executePrecomputation() {
    // NO PRE-COMPUTATION IS NEEDED: NO-OP.
  }

  @Override
  public GroupElement executePreChallengePhase() throws ProofStoreException {

    this.Q = (QRElement) proofStore.retrieve("issuing.signer.Q");

    BigInteger order = signerPrivateKey.getPPrime().multiply(signerPrivateKey.getQPrime());

    this.tilded =
        CryptoUtilsFacade.computeRandomNumber(
            NumberConstants.TWO.getValue(), order.subtract(BigInteger.ONE));

    proofStore.store(URNType.buildURNComponent(URNType.TILDED, this.getClass()), tilded);
    GroupElement tildeA = Q.modPow(tilded);
    
    return tildeA;
  }
  
  @Override
  public Map<URN, GroupElement> executeCompoundPreChallengePhase() throws ProofStoreException {
	  GroupElement tildeA = executePreChallengePhase();
	  Map<URN, GroupElement> witnesses = new HashMap<URN, GroupElement>();
	    String tildeAURN = URNType.buildURNComponent(URNType.TILDEA, SigningQCorrectnessProver.class);
	    witnesses.put(URN.createZkpgsURN(tildeAURN), tildeA);
	    return witnesses;
	  }

  @Override
  public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge)
      throws ProofStoreException {
    this.d = (BigInteger) proofStore.retrieve("issuing.signer.d");

    BigInteger order = signerPrivateKey.getPPrime().multiply(signerPrivateKey.getQPrime());
    hatd = (tilded.subtract(cChallenge.multiply(d))).mod(order);
    Map<URN, BigInteger> responses = new HashMap<URN, BigInteger>(1);
    responses.put(
        URN.createZkpgsURN(URNType.buildURNComponent(URNType.HATD, this.getClass())), hatd);
    return responses;
  }

  @Override
  public boolean verify() {
    return false;
  }

  @Override
  public List<URN> getGovernedURNs() {
    throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
  }
}
