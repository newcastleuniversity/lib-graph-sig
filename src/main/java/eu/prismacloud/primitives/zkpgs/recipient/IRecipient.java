package eu.prismacloud.primitives.zkpgs.recipient;

import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signature.IGraphSignature;
import java.math.BigInteger;

public interface IRecipient {

  public IGraphSignature hiddenSign(
      ICommitment cmt,
      GSVertex signerConnectingVertex,
      GSVertex recipientConnectingVertex,
      ExtendedPublicKey extendedPublicKey,
      GSGraph<GSVertex, GSEdge> recipientGraph,
      BigInteger rndRecipient);

  public SignerKeyPair keyGen(KeyGenParameters gs_params);

  public ICommitment commit(GSGraph<GSVertex, GSEdge> gsGraph, BigInteger rnd);

  public void setGraph(GSGraph<GSVertex, GSEdge> recipientGraph);

  public Boolean verify(
      ExtendedPublicKey extendedPublicKey,
      ICommitment recipientCommitment,
      BigInteger rndRecipient,
      GSSignature graphSignature);
}
