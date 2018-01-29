package eu.prismacloud.primitives.grs.recipient;

import java.math.BigInteger;

import eu.prismacloud.primitives.grs.commitment.ICommitment;
import eu.prismacloud.primitives.grs.graph.GSGraph;
import eu.prismacloud.primitives.grs.graph.GSVertex;
import eu.prismacloud.primitives.grs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.grs.keys.IGSKeyPair;
import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.grs.signature.GSGraphSignature;
import eu.prismacloud.primitives.grs.signature.IGraphSignature;


public interface IRecipient {
    /*
     * The recipient initialized the HiddenSign protocol by creating a graph commitment and retaining randomness R,
     * possibly only containing his master secret key, but no sub-graph.
     * In this case it is assumed that the signer knows the graph to be signed.
     * Once the signer sends his partial signature, the recipient completes the signature with his randomness R. 
     *
     */
	
	
	 //public GSMessage sendMessage(GSMessage recMessageToSigner) ;

	
	 public IGraphSignature hiddenSign(ICommitment cmt, GSVertex signerConnectingVertex, GSVertex recipientConnectingVertex, ExtendedPublicKey extendedPublicKey, GSGraph recipientGraph, BigInteger rndRecipient);

	  
	    public IGSKeyPair keyGen(KeyGenParameters gs_params);

	    public ICommitment commit(GSGraph gsGraph, BigInteger rnd) ;

	   
	    public void setGraph(GSGraph recipientGraph); 

	    public Boolean verify(ExtendedPublicKey extendedPublicKey, ICommitment recipientCommitment, BigInteger rndRecipient, GSGraphSignature graphSignature);
}
