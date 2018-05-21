package eu.prismacloud.primitives.grs.verifier;

import eu.prismacloud.primitives.grs.commitment.ICommitment;
import eu.prismacloud.primitives.grs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.grs.signature.GSGraphSignature;
import java.math.BigInteger;

public interface IVerifier {
  Boolean verify(
      ExtendedPublicKey extendedPublicKey,
      ICommitment recCommitment,
      BigInteger rndVerifier,
      GSGraphSignature graphSignature);
  /*
   * The verifier role interacts with a prover to verify a policy predicate P.
   * The verifier initializes the interaction, sending the policy Predicate P as well as a nonce
   * that binds the session context.
   *
   */
}
