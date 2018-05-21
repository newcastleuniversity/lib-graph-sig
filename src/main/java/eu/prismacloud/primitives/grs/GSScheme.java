package eu.prismacloud.primitives.grs;

import com.ibm.zurich.idmx.utils.Utils;
import eu.prismacloud.primitives.grs.commitment.GSCommitment;
import eu.prismacloud.primitives.grs.commitment.ICommitment;
import eu.prismacloud.primitives.grs.encoding.GSGraphEncoding;
import eu.prismacloud.primitives.grs.graph.GSGraph;
import eu.prismacloud.primitives.grs.graph.GSVertex;
import eu.prismacloud.primitives.grs.keys.IGSKeyPair;
import eu.prismacloud.primitives.grs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.grs.recipient.GSRecipient;
import eu.prismacloud.primitives.grs.signature.IGraphSignature;
import eu.prismacloud.primitives.grs.signer.GSSigner;
import eu.prismacloud.primitives.grs.signer.ISigner;
import eu.prismacloud.primitives.grs.verifier.GSVerifier;
import eu.prismacloud.primitives.grs.verifier.IVerifier;
import java.math.BigInteger;
import org.jgrapht.graph.DefaultEdge;

public class GSScheme {
  public static void main() {

    // Signer part
    ISigner signer = new GSSigner();

    //        IParams gs_params = (IParams) new GSParamsImpl(2048);
    //        gs_params.setCommitmentGroup(1632);
    //        gs_params.setSubGroupLength(256);
    //        gs_params.setMaxMessageEncodingLength(256);
    //        gs_params.setReservedMessagesNumber(1);
    //        gs_params.setCertificateELength(597);
    //        gs_params.setIntervalLengthE(120);
    //        gs_params.setCertificateVLength(2724);
    //        gs_params.setStatisticalZKParam(80);
    //        gs_params.setHashLength(256);
    //        gs_params.setCLSecurityParam(80);
    //        gs_params.setPrimeProbability(80);
    KeyGenParameters gs_params = null;
    IGSKeyPair keyGenPair = signer.keyGen(gs_params);
    //
    GraphEncodingParameters gs_encoding_params = null;
    //        gs_encoding_params.setMaxVertexNo(1000);
    //        gs_encoding_params.setVertexEncodingLength(120);
    //        gs_encoding_params.setMaxEdgeNo(50000);
    //        gs_encoding_params.setMaxLabelNo(256);
    //        gs_encoding_params.setLabelEncodingLength(16);

    GSGraphEncoding graphEncoding = new GSGraphEncoding();

    GSGraphEncodingResult graphEncodingResult =
        graphEncoding.setup(
            keyGenPair.getPrivateKey(),
            keyGenPair.getPrivateKey(),
            keyGenPair,
            keyGenPair.getSignature());

    // EncodingSignature encodingSignature = graphEncoding.signEncoding();

    BigInteger rndSigner = Utils.computeRandomNumber(KeyGenParameters.l_0.getValue());

    // Create signer's graph
    GSGraph signerGraph = new GSGraph();
    GSVertex v1 = new GSVertex();
    v1.setLabel("vertex_s1");
    GSVertex v2 = new GSVertex();
    v2.setLabel("vertex_s2");
    signerGraph.addVertex(v1);
    signerGraph.addVertex(v2);

    DefaultEdge edge = signerGraph.addEdge(v1, v2);
    GSVertex signerConnectingVertex = new GSVertex();
    signerConnectingVertex.setLabel("conn_vertex_s3");
    signerGraph.addVertex(signerConnectingVertex);
    DefaultEdge edgeConn = signerGraph.addEdge(v2, signerConnectingVertex);

    signer.setGraph(signerGraph);

    //        // encode signer's graph
    //        IGraphRepresentation signerGraphRep = graphEncoding.encode(signerGraph);

    // Create recipient's graph
    GSRecipient recipient = new GSRecipient();
    GSGraph recipientGraph = new GSGraph();
    GSVertex rec_v1 = new GSVertex();
    v1.setLabel("vertex_1");
    GSVertex rec_v2 = new GSVertex();
    v2.setLabel("vertex_2");

    recipientGraph.addVertex(rec_v1);
    recipientGraph.addVertex(rec_v2);

    DefaultEdge rec_edge = recipientGraph.addEdge(rec_v1, rec_v2);
    GSVertex recipientConnectingVertex = new GSVertex();
    recipientConnectingVertex.setLabel("conn_vertex_4");

    recipientGraph.addVertex(recipientConnectingVertex);

    DefaultEdge edgeRecConn = recipientGraph.addEdge(v2, recipientConnectingVertex);

    // add graph to recipient
    recipient.setGraph(recipientGraph);

    //        // encode recipient's graph
    //        IGraphRepresentation recipientGraphRep = graphEncoding.encode(recipientGraph);

    BigInteger rndRecipient = Utils.computeRandomNumberSymmetric(KeyGenParameters.l_0.getValue());

    // recipient commitment
    ICommitment recipientCommitment = recipient.commit(recipientGraph, rndRecipient);

    //
    //        IMessage recMessageToSigner = new GSMessage();
    //        recMessageToSigner.addCommitment(recipientCommitment);
    //
    //        IMessage recMessage = recipient.sendMessage((GSMessage) recMessageToSigner);
    //        ICommitment recCommitment = recMessage.getCommitment();

    signer.hiddenSign(
        (GSCommitment) recipientCommitment,
        signerConnectingVertex,
        recipientConnectingVertex,
        graphEncoding.getExtendedPublicKey(),
        signerGraph,
        graphEncoding.getExtendedPrivateKey());
    //
    //        GSMessage signerMessageToRecipient = new GSMessage();
    //        signerMessageToRecipient.addSignature(preGSignature);
    //        GSMessage signerMessage = signer.sendMessage(signerMessageToRecipient);
    //
    //        GSGraphSignature signerPreGSignature = signerMessage.getSignature();

    IGraphSignature signResult =
        recipient.hiddenSign(
            recipientCommitment,
            signerConnectingVertex,
            recipientConnectingVertex,
            graphEncoding.getExtendedPublicKey(),
            recipientGraph,
            rndRecipient);

    // Verify
    IVerifier verifier = new GSVerifier();
    BigInteger rndVerifier = Utils.computeRandomNumberSymmetric(KeyGenParameters.l_0.getValue());
    Boolean result =
        recipient.verify(
            graphEncoding.getExtendedPublicKey(),
            recipientCommitment,
            rndRecipient,
            signResult.getGraphSignature());

    System.out.println("Verification Result: " + result);
  }
}
