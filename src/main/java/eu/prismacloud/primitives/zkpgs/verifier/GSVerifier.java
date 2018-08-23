package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class GSVerifier {
  private final Map<URN, BigInteger> barV = new HashMap<>();
  private ProofStore<Object> verifierStore;
  private final KeyGenParameters keyGenParameters;
  private static final String CLIENT = "client";
  private final MessageGatewayProxy messageGateway;
  private final ExtendedPublicKey extendedPublicKey;

  public GSVerifier(
      final ExtendedPublicKey extendedPublicKey, final KeyGenParameters keyGenParameters) {

    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.messageGateway = new MessageGatewayProxy(CLIENT);
  }

  public Map<URN, BigInteger> getBarV() {
    return barV;
  }

  public boolean checkLengths(ProofSignature p_3) {
    int hateLength =
        keyGenParameters.getL_prime_e()
            + keyGenParameters.getL_statzk()
            + keyGenParameters.getL_H()
            + 1;
    int hatvLength =
        keyGenParameters.getL_v() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;
    
    // TODO Implement length check
    
    return false;
  }

  public void sendMessage(GSMessage messageToProver) {
    messageGateway.send(messageToProver);
  }

  public GSMessage receiveMessage() {
    return messageGateway.receive();
  }

  public void close() {
    messageGateway.close();
  }

  public BigInteger computeNonce() {
    return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
  }
}
