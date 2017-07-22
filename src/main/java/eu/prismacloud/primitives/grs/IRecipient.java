package eu.prismacloud.primitives.grs;

/**
 * Created by Ioannis Sfyrakis  on 05/07/2017.
 */
public interface IRecipient {
    /*
     * The recipient initialized the HiddenSign protocol by creating a graph commitment and retaining randomness R,
     * possibly only containing his master secret key, but no sub-graph.
     * In this case it is assumed that the signer knows the graph to be signed.
     * Once the signer sends his partial signature, the recipient completes the signature with his randomness R. 
     *
     */
}
