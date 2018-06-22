package eu.prismacloud.primitives.zkpgs.recipient;

import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.orchestrator.IssuingOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.IssuingCommitmentProver;
import eu.prismacloud.primitives.zkpgs.signer.GSSigner;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.verifier.CorrectnessVerifier;
import java.math.BigInteger;

public class GSRecipient { // implements IRecipient {

  private final IssuingOrchestrator issuingOrchestrator;
  private final KeyGenParameters keyGenParameters;
  private BigInteger n_1;
  private BigInteger vPrime;
  private BigInteger R_0;
  private BigInteger m_0;
  private GSGraph<GSVertex, GSEdge> recipientGraph; // = new GSGraph();
  private BigInteger n_2;

  public GSRecipient(
      final IssuingOrchestrator issuingOrchestrator, final KeyGenParameters keyGenParameters) {
    this.issuingOrchestrator = issuingOrchestrator;
    this.keyGenParameters = keyGenParameters;
  }

  public void setN_1(BigInteger n_1) {
    this.n_1 = n_1;
  }

  public void round0() {}

  public BigInteger generatevPrime() {
    vPrime =
        CryptoUtilsFacade.computeRandomNumber(
            keyGenParameters.getL_n() + keyGenParameters.getL_statzk());

    return vPrime;
  }

  public IssuingCommitmentProver createCommitmentProver(
      ICommitment U, ExtendedPublicKey extendedPublicKey) {

    IssuingCommitmentProver commitmentProver =
        new IssuingCommitmentProver(U, vPrime, R_0, m_0, n_1, keyGenParameters, extendedPublicKey);
    return commitmentProver;
  }

  public CorrectnessVerifier createCorrectnessVerifier() {
    return null;
  }

  public ICommitment commit(GSGraph<GSVertex, GSEdge> gsGraph, BigInteger rnd) {
    return null;
  }

  public GSGraph<GSVertex, GSEdge> getRecipientGraph() {
    return recipientGraph;
  }

  public void sendMessage(GSMessage recMessageToSigner, GSSigner signer) {
    signer.receiveMessage(recMessageToSigner);
  }

  //  @Override
  public void setGraph(GSGraph<GSVertex, GSEdge> recipientGraph) {
    this.recipientGraph = recipientGraph;
  }

  public BigInteger generateN_2() {
    n_2 = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());

    return n_2;
  }
}
