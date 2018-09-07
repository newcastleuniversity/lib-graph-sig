package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessagePartner;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class GSVerifier implements IMessagePartner {
  private final Map<URN, BigInteger> barV = new HashMap<>();
  private ProofStore<Object> verifierStore;
  private final KeyGenParameters keyGenParameters;
  private static final String CLIENT = "client";
  private final MessageGatewayProxy messageGateway;
  private final ExtendedPublicKey extendedPublicKey;

  public GSVerifier(
      final ExtendedPublicKey extendedPublicKey) {

    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
    this.messageGateway = new MessageGatewayProxy(CLIENT);
  }
  
  public void init() throws IOException {
	  this.messageGateway.init();
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

  public void sendMessage(GSMessage messageToProver) throws IOException {
    messageGateway.send(messageToProver);
  }

  public GSMessage receiveMessage() throws IOException {
    return messageGateway.receive();
  }

  public void close() throws IOException {
    messageGateway.close();
  }

  public BigInteger computeNonce() {
    return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
  }
}
