package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GroupSetupProverOrchestrator implements IProverOrchestrator {

  private final ExtendedKeyPair extendedKeyPair;
  private final ProofStore<Object> proofStore;
  private final KeyGenParameters keyGenParameters;
  private final GroupSetupProver gsProver;
  private final ExtendedPublicKey extendedPublicKey;
  private final BaseCollection baseCollection;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  public GroupSetupProverOrchestrator(
      final ExtendedKeyPair extendedKeyPair, final ProofStore<Object> proofStore) {
    Assert.notNull(extendedKeyPair, "Extended key pair must not be null");
    Assert.notNull(proofStore, "Proof store must not be null");

    this.extendedKeyPair = extendedKeyPair;
    this.extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
    this.proofStore = proofStore;
    this.keyGenParameters = extendedKeyPair.getExtendedPublicKey().getKeyGenParameters();
    this.gsProver = new GroupSetupProver(extendedKeyPair, proofStore);
    this.baseCollection = extendedKeyPair.getExtendedPublicKey().getBaseCollection();
  }

  public void init() {}

  public void executePreChallengePhase() {

    try {
      gsProver.executeCompoundPreChallengePhase();
    } catch (ProofStoreException e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  public BigInteger computeChallenge() {
    gslog.info("compute challenge ");
    BigInteger cChallenge = null;
    try {
      List<String> challengeList = populateChallengeList();
      cChallenge = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
    } catch (NoSuchAlgorithmException e) {
      gslog.log(Level.SEVERE, "Fiat-Shamir challenge could not be computed.", e);
    }
    return cChallenge;
  }

  public List<String> populateChallengeList() {
    GSContext gsContext = new GSContext(extendedPublicKey);
    List<String> ctxList = gsContext.computeChallengeContext();

    GroupElement tildeZ =
        (GroupElement) proofStore.retrieve(gsProver.getProverURN(URNType.TILDEBASEZ));
    GroupElement basetildeR =
        (GroupElement) proofStore.retrieve(gsProver.getProverURN(URNType.TILDEBASER));
    GroupElement basetildeR_0 =
        (GroupElement) proofStore.retrieve(gsProver.getProverURN(URNType.TILDEBASER0));

    ctxList.add(String.valueOf(tildeZ));
    ctxList.add(String.valueOf(basetildeR));
    ctxList.add(String.valueOf(basetildeR_0));

    BigInteger tilder_i;
    BigInteger tilder_j;
    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);

    for (BaseRepresentation baseRepresentation : vertexIterator) {
      tilder_i =
          (BigInteger)
              proofStore.retrieve(
                  gsProver.getProverURN(URNType.TILDEBASERI, baseRepresentation.getBaseIndex()));
      ctxList.add(String.valueOf(tilder_i));
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      tilder_j =
          (BigInteger)
              proofStore.retrieve(
                  gsProver.getProverURN(URNType.TILDEBASERIJ, baseRepresentation.getBaseIndex()));
      ctxList.add(String.valueOf(tilder_j));
    }

    return ctxList;
  }

  public void executePostChallengePhase(BigInteger cChallenge) {
    try {
      gsProver.executePostChallengePhase(cChallenge);
    } catch (ProofStoreException e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  @Override
  public ProofSignature createProofSignature() {
    return gsProver.outputProofSignature();
  }
}
