package eu.prismacloud.primitives.grs.recipient;

import eu.prismacloud.primitives.grs.GSMessage;
import eu.prismacloud.primitives.grs.commitment.GSCommitment;
import eu.prismacloud.primitives.grs.commitment.ICommitment;
import eu.prismacloud.primitives.grs.graph.GSGraph;
import eu.prismacloud.primitives.grs.graph.GSVertex;
import eu.prismacloud.primitives.grs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.grs.keys.IGSKeyPair;
import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.grs.signature.GSGraphSignature;
import eu.prismacloud.primitives.grs.signature.IGraphSignature;
import org.jgrapht.graph.DefaultEdge;

import java.math.BigInteger;

/**
 * Created by Ioannis Sfyrakis  on 05/07/2017.
 */
public class GSRecipient implements IRecipient {

    public IGraphSignature hiddenSign(ICommitment cmt, GSVertex gsGraph, GSVertex gsGraph1, ExtendedPublicKey extendedPublicKey, GSGraph gsGraph2, BigInteger rnd) {

        /* TODO compute graph signature */
        return null;
    }

    private GSGraph recipientGraph;// = new GSGraph();

    public IGSKeyPair keyGen(KeyGenParameters gs_params) {
        return null;
    }

    public ICommitment commit(GSGraph gsGraph, BigInteger rnd) {
        return null;
    }

    public void hiddenSign(GSCommitment cmt, GSVertex gsGraph, GSVertex graph, ExtendedPublicKey extendedPublicKey, GSGraph gsGraph1, BigInteger extendedPrivateKey) {

    }


    public GSGraph getRecipientGraph() {
        return recipientGraph;
    }

    public void createGraph() {

        GSVertex v1 = new GSVertex();
        v1.setLabel("vertex_1");
        GSVertex v2 = new GSVertex();
        v2.setLabel("vertex_2");

        recipientGraph.addVertex(v1);
        recipientGraph.addVertex(v2);

        DefaultEdge edge = recipientGraph.addEdge(v1, v2);

        GSVertex signerConnectingVertex = new GSVertex();
        signerConnectingVertex.setLabel("conn_vertex_3");

        recipientGraph.addVertex(signerConnectingVertex);


    }

    public GSGraph initGraph() {
        return new GSGraph();
    }

    public GSMessage sendMessage(GSMessage recMessageToSigner) {
        return null;
    }

    public void setGraph(GSGraph recipientGraph) {
        this.recipientGraph = recipientGraph;
    }

    public Boolean verify(ExtendedPublicKey extendedPublicKey, ICommitment recipientCommitment, BigInteger rndRecipient, GSGraphSignature graphSignature) {
        return true;
    }
}
