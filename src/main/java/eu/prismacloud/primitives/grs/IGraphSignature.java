package eu.prismacloud.primitives.grs;

import java.math.BigInteger;

/**
 * Created by Ioannis Sfyrakis  on 05/07/2017.
 */
public interface IGraphSignature {

    /**
     * Key gen key gen pair.
     *
     * @param securityParam the security param
     * @param params        the params
     * @return the key gen pair
     */
    public IKeyGenPair keyGen(int securityParam, IKeyGenParams params);

    /**
     * Commit commitment.
     *
     * @param graph the graph
     * @param rnd   the rnd
     * @return the commitment
     */
    public ICommitment commit(IGraphRepresentation graph, BigInteger rnd);

    /**
     * Hidden sign graph signature.
     *
     * @param cmt  the cmt
     * @param pk_s the pk s
     * @return the graph signature
     */
    public IGraphSignature hiddenSign(ICommitment cmt,/*add connection points */ ISignerPublicKey pk_s);

    /**
     * Verify boolean.
     *
     * @param pk_s   the pk s
     * @param cmt    the cmt
     * @param rTilde the r tilde
     * @param gsig   the gsig
     * @return the boolean
     */
    public Boolean verify(ISignerPublicKey pk_s, ICommitment cmt, BigInteger rTilde, IGraphSignature gsig);

}
