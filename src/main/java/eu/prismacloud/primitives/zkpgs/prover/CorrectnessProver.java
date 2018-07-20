package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/** */
public class CorrectnessProver implements IProver {

  private BigInteger n_2;
  private ProofStore<Object> proofStore;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger order;
  private KeyGenParameters keyGenParameters;
  private BigInteger tilded;
  private QRElement tildeA;
  private List<String> challengeList;
  private BigInteger cPrime;
  private BigInteger hatd;
  private GSSignature gsSignature;
  private BigInteger modN;
  private BigInteger d;
  private QRElement Q;
  private QRElement A;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private GraphEncodingParameters graphEncodingParameters;

  public QRElement preChallengePhase(
      final GSSignature gsSignature,
      final BigInteger order,
      final BigInteger n_2,
      final ProofStore<Object> proofStore,
      final ExtendedPublicKey extendedPublicKey,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters)
      throws Exception {

    this.gsSignature = gsSignature;
    this.n_2 = n_2;
    this.order = order;
    this.proofStore = proofStore;
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.tilded =
        CryptoUtilsFacade.computeRandomNumber(
            NumberConstants.TWO.getValue(), order.subtract(BigInteger.ONE));
    this.Q = (QRElement) proofStore.retrieve("issuing.signer.Q");
    this.A = (QRElement) proofStore.retrieve("issuing.signer.A");
    this.d = (BigInteger) proofStore.retrieve("issuing.signer.d");
    ;
    proofStore.store("correctnessprover.randomness.tilded", tilded);
    tildeA = Q.modPow(tilded);

    return tildeA;
  }

  @Override
  public void createWitnessRandomness() throws ProofStoreException {}

  @Override
  public void computeWitness() throws ProofStoreException {}

  public BigInteger computeChallenge() throws NoSuchAlgorithmException {
    challengeList = populateChallengeList();
    cPrime = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
    return cPrime;
  }

  @Override
  public void computeResponses() {}

  private List<String> populateChallengeList() {
    challengeList = new ArrayList<String>();
    GSContext gsContext =
                new GSContext(extendedPublicKey, keyGenParameters, graphEncodingParameters);
        List<String> contextList = gsContext.computeChallengeContext();
    gslog.info("contextlist length: " + contextList.size());
    // TODO add context list
    challengeList.addAll(contextList);
    challengeList.add(String.valueOf(Q));
    challengeList.add(String.valueOf(A));
    challengeList.add(String.valueOf(tildeA));
    challengeList.add(String.valueOf(n_2));
    return challengeList;
  }

  public BigInteger postChallengePhase() {
    hatd = tilded.subtract(cPrime.multiply(d).mod(order));
    return hatd;
  }
}
