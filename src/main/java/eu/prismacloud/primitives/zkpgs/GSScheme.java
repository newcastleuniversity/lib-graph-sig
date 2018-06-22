package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;

public class GSScheme {
  private static KeyGenParameters keyGenParameters;

  public static void main() {

    //    // Signer part
    //    ISigner signer = new GSSigner();
    //
    //    //        IParams gs_params = (IParams) new GSParamsImpl(2048);
    //    //        gs_params.setCommitmentGroup(1632);
    //    //        gs_params.setSubGroupLength(256);
    //    //        gs_params.setMaxMessageEncodingLength(256);
    //    //        gs_params.setReservedMessagesNumber(1);
    //    //        gs_params.setCertificateELength(597);
    //    //        gs_params.setIntervalLengthE(120);
    //    //        gs_params.setCertificateVLength(2724);
    //    //        gs_params.setStatisticalZKParam(80);
    //    //        gs_params.setHashLength(256);
    //    //        gs_params.setCLSecurityParam(80);
    //    //        gs_params.setPrimeProbability(80);
    //    KeyGenParameters gs_params = null;
    //    IGSKeyPair keyGenPair = signer.keyGen(gs_params);
    //    //
    //    GraphEncodingParameters gs_encoding_params = null;
    //    //        gs_encoding_params.setMaxVertexNo(1000);
    //    //        gs_encoding_params.setVertexEncodingLength(120);
    //    //        gs_encoding_params.setMaxEdgeNo(50000);
    //    //        gs_encoding_params.setMaxLabelNo(256);
    //    //        gs_encoding_params.setLabelEncodingLength(16);
    //
    //    GraphEncoding graphEncoding = new GraphEncoding();
    //
    //    // TODO fix graph enconding parameters for the graph encoding setup
    //    GSGraphEncodingResult graphEncodingResult =
    //        graphEncoding.graphEncodingSetup(
    //            keyGenPair,
    //            new GraphEncodingParameters(80, 80, 80, 80, 80));
    //
    //    // EncodingSignature encodingSignature = graphEncoding.signEncoding();
    //
    //    BigInteger rndSigner = Utils.computeRandomNumber(keyGenParameters.getL_statzk());
    //
    //    // Create signer's graph
    //    GSGraph signerGraph = GSGraph.createGraph();
    //    GSVertex v1 = new GSVertex("");
    //    v1.setLabel("vertex_s1");
    //    GSVertex v2 = new GSVertex("");
    //    v2.setLabel("vertex_s2");
    //    signerGraph.addVertex(v1);
    //    signerGraph.addVertex(v2);
    //
    //    DefaultEdge edge = signerGraph.addEdge(v1, v2);
    //    GSVertex signerConnectingVertex = new GSVertex("");
    //    signerConnectingVertex.setLabel("conn_vertex_s3");
    //    signerGraph.addVertex(signerConnectingVertex);
    //    DefaultEdge edgeConn = signerGraph.addEdge(v2, signerConnectingVertex);
    //
    //    signer.setGraph(signerGraph);
    //
    //    //        // encode signer's graph
    //    //        IGraphRepresentation signerGraphRep = graphEncoding.encode(signerGraph);
    //
    //    // Create recipient's graph
    //    GSRecipient recipient = new GSRecipient();
    //    GSGraph recipientGraph = GSGraph.createGraph();
    //    GSVertex rec_v1 = new GSVertex("");
    //    v1.setLabel("vertex_1");
    //    GSVertex rec_v2 = new GSVertex("");
    //    v2.setLabel("vertex_2");
    //
    //    recipientGraph.addVertex(rec_v1);
    //    recipientGraph.addVertex(rec_v2);
    //
    //    DefaultEdge rec_edge = recipientGraph.addEdge(rec_v1, rec_v2);
    //    GSVertex recipientConnectingVertex = new GSVertex("");
    //    recipientConnectingVertex.setLabel("conn_vertex_4");
    //
    //    recipientGraph.addVertex(recipientConnectingVertex);
    //
    //    DefaultEdge edgeRecConn = recipientGraph.addEdge(v2, recipientConnectingVertex);
    //
    //    // add graph to recipient
    //    recipient.setGraph(recipientGraph);
    //
    //    //        // encode recipient's graph
    //    //        IGraphRepresentation recipientGraphRep = graphEncoding.encode(recipientGraph);
    //
    //    BigInteger rndRecipient =
    // Utils.computeRandomNumberSymmetric(keyGenParameters.getL_statzk());
    //
    //    // recipient commitment
    //    ICommitment recipientCommitment = recipient.commit(recipientGraph, rndRecipient);
    //
    //    //
    //    //        IMessage recMessageToSigner = new GSMessage();
    //    //        recMessageToSigner.addCommitment(recipientCommitment);
    //    //
    //    //        IMessage recMessage = recipient.sendMessage((GSMessage) recMessageToSigner);
    //    //        ICommitment recCommitment = recMessage.getCommitment();
    //
    //    signer.hiddenSign(
    //        (GSCommitment) recipientCommitment,
    //        signerConnectingVertex,
    //        recipientConnectingVertex,
    //        graphEncoding.getExtendedKeyPair(),
    //        signerGraph,
    //        graphEncoding.getExtendedPrivateKey());
    //    //
    //    //        GSMessage signerMessageToRecipient = new GSMessage();
    //    //        signerMessageToRecipient.addSignature(preGSignature);
    //    //        GSMessage signerMessage = signer.sendMessage(signerMessageToRecipient);
    //    //
    //    //        GSGraphSignature signerPreGSignature = signerMessage.getSignature();
    //
    //    IGraphSignature signResult =
    //        recipient.hiddenSign(
    //            recipientCommitment,
    //            signerConnectingVertex,
    //            recipientConnectingVertex,
    //            graphEncoding.getExtendedKeyPair(),
    //            recipientGraph,
    //            rndRecipient);
    //
    //    // Verify
    //    IVerifier verifier = new GSVerifier();
    //    BigInteger rndVerifier =
    // Utils.computeRandomNumberSymmetric(keyGenParameters.getL_statzk());
    //    Boolean result =
    //        recipient.verify(
    //            graphEncoding.getExtendedKeyPair(),
    //            recipientCommitment,
    //            rndRecipient,
    //            signResult.getGraphSignature());
    //
    //    System.out.println("Verification Result: " + result);
  }
}
