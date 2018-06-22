package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.message.MesageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.IssuingCommitmentProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigner;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/** Signing orchestrator */
public class SignerOrchestrator {

  private final ExtendedKeyPair extendedKeyPair;
  private KeyGenParameters keyGenParameters;
  private GSSigner signer;
  private BigInteger n_1;
  private BigInteger n_2;
  private GSGraph<GSVertex, GSEdge> recipientGraph; // = new GSGraph();
  private ProofSignature P_1;
  private ICommitment U;
  IMessageGateway messageGateway;

  public SignerOrchestrator(ExtendedKeyPair extendedKeyPair, KeyGenParameters keyGenParameters) {
    this.extendedKeyPair = extendedKeyPair;
    this.keyGenParameters = keyGenParameters;
  }

  public ExtendedKeyPair getExtendedKeyPair() {
    return this.extendedKeyPair;
  }

  public void round0() {
   messageGateway  = new MesageGatewayProxy();

    n_1 = signer.computeNonce();
    signer.sendMessage(new GSMessage(n_1), null);

    /** TODO send message to recipient for the n_1 */
    /** TODO signer send n_1 to recipient */
    //recipient.setN_1(n_1);
  }


  public void round2() {
    Map<URN, Object> proofSignatureElements = P_1.getProofSignatureElements();
    BigInteger hatvPrime =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatvPrime"));
    CommitmentVerifier commitmentVerifier =
        signer.createCommitmentVerifier(
            P_1,
            U,
            n_1,
            extendedKeyPair.getPublicKey().getBaseS(),
            extendedKeyPair.getPublicKey().getBaseR_0(),
            extendedKeyPair.getPublicKey().getBaseZ(),
            extendedKeyPair.getPublicKey().getModN(),
            extendedKeyPair.getExtendedPublicKey().getBases());

    commitmentVerifier.computehatU();

    commitmentVerifier.computeChallenge();

    if (!commitmentVerifier.verifyChallenge()) {
      /** TODO add a more specific protocol exception */
      throw new IllegalArgumentException("challenge verification failed");
    }

    signer.computeRandomness();
    signer.computevPrimePrime();
    signer.createPartialSignature(extendedKeyPair);
    signer.store(); // TODO signer stores Q, vPrimePrime, context

    signer.createCorrectnessProver();
  }
}
