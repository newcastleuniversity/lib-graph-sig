package eu.prismacloud.primitives.grs;

import eu.prismacloud.primitives.grs.signature.IGraphSignature;

/**
 * Created by Ioannis Sfyrakis on 21/07/2017
 */
public class IGraphSignatureMockBuilder {
    private IGraphSignature mock;

//    public IGraphSignatureMockBuilder() {
//        mock = EasyMock.mock(IGraphSignature.class);
//    }
//
//    public IGraphSignatureMockBuilder keyGen(int securityParam, IKeyGenParams params, final IKeyGenPair expected) {
//        EasyMock.expect(mock.keyGen(securityParam, params)).andReturn(expected).once();
//        return this;
//    }
//
//    public IGraphSignatureMockBuilder commit(IGraphRepresentation graph, BigInteger rnd, final ICommitment expected) {
//        EasyMock.expect(mock.commit(graph, rnd)).andReturn(expected).once();
//        return this;
//    }
//
//    public IGraphSignatureMockBuilder hiddenSign(ICommitment cmt, ISignerPublicKey pk_s, final IGraphSignature expected) {
//        EasyMock.expect(mock.hiddenSign(cmt, pk_s)).andReturn(expected).once();
//        return this;
//    }
//
//    public IGraphSignatureMockBuilder verify(ISignerPublicKey pk_s, ICommitment cmt, BigInteger rTilde, IGraphSignature gsig, final Boolean expected) {
//        EasyMock.expect(mock.verify(pk_s, cmt, rTilde, gsig)).andReturn(expected).once();
//        return this;
//    }
//
//    public IGraphSignature buildAndReplay() {
//        EasyMock.replay(mock);
//        return mock;
//    }
}
