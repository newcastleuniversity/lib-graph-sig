package uk.ac.ncl.cascade.zkpgs.recipient;

import uk.ac.ncl.cascade.zkpgs.commitment.ICommitment;
import uk.ac.ncl.cascade.zkpgs.graph.GSEdge;
import uk.ac.ncl.cascade.zkpgs.graph.GSGraph;
import uk.ac.ncl.cascade.zkpgs.graph.GSVertex;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.IURNGoverner;

import java.math.BigInteger;

public interface IRecipient extends IURNGoverner {

//  public IGraphSignature hiddenSign(
//      ICommitment cmt,
//      GSVertex signerConnectingVertex,
//      GSVertex recipientConnectingVertex,
//      ExtendedPublicKey extendedPublicKey,
//      GSGraph<GSVertex, GSEdge> recipientGraph,
//      BigInteger rndRecipient);

  public SignerKeyPair keyGen(KeyGenParameters gs_params);

  public ICommitment commit(GSGraph<GSVertex, GSEdge> gsGraph, BigInteger rnd);

  public void setGraph(GSGraph<GSVertex, GSEdge> recipientGraph);

  public Boolean verify(
      ExtendedPublicKey extendedPublicKey,
      ICommitment recipientCommitment,
      BigInteger rndRecipient,
      GSSignature graphSignature);
}
