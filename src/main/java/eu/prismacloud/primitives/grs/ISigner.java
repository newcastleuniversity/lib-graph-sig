package eu.prismacloud.primitives.grs;

/**
 * Created by Ioannis Sfyrakis  on 05/07/2017.
 */
public interface ISigner {
    /*
     * responsible for generating an appropriate key setup, certify an encoding scheme, and to sign graphs
     * In the hiddenSign() protocol the signer accepts a graph commitment from the recipient, adds an issuer-known sub-graph and
     * and completes the signature with his secret key sk_signer.
     * The signer outputs a partial graph signature, subsequently completed by the recipient.
     */

}
