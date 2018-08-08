package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class GSVerifier {
  private final Map<URN, BigInteger> barV = new HashMap<>();
  private final ProofStore<Object> verifierStore;
  private final KeyGenParameters keyGenParameters;
  private static final String CLIENT = "client";
  private final MessageGatewayProxy messageGateway;

  public GSVerifier(ProofStore<Object> verifierStore, KeyGenParameters keyGenParameters) {
    this.verifierStore = verifierStore;
    this.keyGenParameters = keyGenParameters;
    this.messageGateway = new MessageGatewayProxy(CLIENT);
  }

  public Map<URN, BigInteger> getBarV() {
    return barV;
  }

  public void checkLengths(ProofSignature p_3) {
    int hateLength =
        keyGenParameters.getL_prime_e()
            + keyGenParameters.getL_statzk()
            + keyGenParameters.getL_H()
            + 1;
    int hatvLength =
        keyGenParameters.getL_v() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;
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
}
