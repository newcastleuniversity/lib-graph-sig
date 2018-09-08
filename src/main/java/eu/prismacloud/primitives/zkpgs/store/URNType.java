package eu.prismacloud.primitives.zkpgs.store;

import java.util.ArrayList;
import java.util.List;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.keys.IKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.IPublicKey;
import eu.prismacloud.primitives.zkpgs.orchestrator.IProverOrchestrator;
import eu.prismacloud.primitives.zkpgs.orchestrator.IVerifierOrchestrator;
import eu.prismacloud.primitives.zkpgs.prover.IProver;
import eu.prismacloud.primitives.zkpgs.verifier.IVerifier;

public enum URNType {
	// Public Values
	RV,
	RE,
	MODN,
	BASES,
	BASEZ,
	BASER,
	BASER0,
	BASERI,
	BASERIJ,
	CCHALLENGE,
	EI,
	APRIME,
	CI,
	U,
	NONCEI,
	PI,
	
	// Secrets
	DLRV,
	DLRE,
	ABARIBARJ,
	BBARIBARJ,
	RBARIBARJ,
	M0,
	MI,
	MIJ,
	RI,
	SIGMA,
	EPRIME,
	VPRIME,
	A,
	E,
	V,
	
	// Witness Randomness and Witnesses (tilde-values)
	TILDEA,
	TILDED,
	TILDEE,
	TILDEV,
	TILDEVPRIME,
	TILDEM0,
	TILDEMI,
	TILDEMIJ,
	TILDERI,
	TILDERIJ,
	TILDER,
	TILDER0,
	TILDERZ,
	TILDEABARIBARJ,
	TILDEBBARIBARJ,
	TILDERBARIBARJ,
	TILDEBASEZ,
	TILDEBASER,
	TILDEBASER0,
	TILDEBASERI,
	TILDEBASERIJ,
	TILDECI,
	TILDEU,
	TILDEZ,
	TILDEBASERBARIBARJ,
	
	// Responses (hat-values)
	HATA,
	HATD,
	HATE,
	HATV,
	HATVPRIME,
	HATM0,
	HATMI,
	HATMIJ,
	HATRI,
	HATBASERI,
	HATRIJ,
	HATBASERIJ,
	HATRZ,
	HATR,
	HATBASER,
	HATR0,
	HATBASER0,
	HATZ,
	HATABARIBARJ,
	HATBBARIBARJ,
	HATRBARIBARJ,
	HATCI,
	HATU,
	HATMAP,
	
	// Undefined unsafe type.
	UNDEFINED;

	private URNType() {}

	public static String getSuffix(URNType t) {
		switch(t) {
		case RV: return "R_V_";
		case RE: return "R_E_";
		case MODN: return "modN";
		case BASES: return "baseS";
		case BASEZ: return "baseZ";
		case BASER: return "baseR";
		case BASER0: return "baseR_0";
		case BASERI: return "baseR_i_";
		case BASERIJ: return "baseR_i_j_";
		case CCHALLENGE: return "c";
		case EI: return "e_i_";
		case APRIME: return "APrime";
		case CI: return "C_i_";
		case U: return "U";
		case NONCEI: return "n_";
		case PI: return "P_";
		
		case ABARIBARJ: return "a_BariBarj_";
		case BBARIBARJ: return "b_BariBarj_";
		case RBARIBARJ: return "r_BariBarj_";
		case M0: return "m_0";
		case MI: return "m_i_";
		case MIJ: return "m_i_j_";
		case RI: return "r_i_";
		case DLRV: return "x_R_V_";
		case DLRE: return "x_R_E_";
		case SIGMA: return "sigma";
		case EPRIME: return "ePrime";
		case VPRIME: return "vPrime";
		case A: return "A";
		case E: return "e";
		case V: return "v";
		
		case TILDEA: return "tildeA";
		case TILDED: return "tilded";
		case TILDEE: return "tildee";
		case TILDEV: return "tildev";
		case TILDEVPRIME: return "tildevprime";
		case TILDEM0: return "tildem_0";
		case TILDEMI: return "tildem_i_";
		case TILDEMIJ: return "tildem_i_j_";
		case TILDERI: return "tilder_i_";
		case TILDERIJ: return "tilder_i_j_";
		case TILDER: return "tilder";
		case TILDER0: return "tilder_0";
		case TILDERZ: return "tilder_Z";
		case TILDEABARIBARJ: return "tildea_BariBarj_";
		case TILDEBBARIBARJ: return "tildeb_BariBarj_";
		case TILDERBARIBARJ: return "tilder_BariBarj_";
		case TILDEBASEZ: return "tildeZ";
		case TILDEBASER: return "tildeR";
		case TILDEBASER0: return "tildeR_0";
		case TILDEBASERI: return "tildeR_i";
		case TILDEBASERIJ: return "tildeR_i_j_";
		case TILDEU: return "tildeU";
		case TILDECI: return "tildeC_i_";
		case TILDEZ: return "tildeZ";
		case TILDEBASERBARIBARJ: return "tildeBaseR_BariBarj_";
		
		case HATA: return "hata";
		case HATD: return "hatd";
		case HATE: return "hate";
		case HATV: return "hatv";
		case HATVPRIME: return "hatvprime";
		case HATM0: return "hatm_0";
		case HATMI: return "hatm_i_";
		case HATMIJ: return "hatm_i_j_";
		case HATRI: return "hatr_i_";
		case HATBASERI: return "hatR_i_";
		case HATBASERIJ: return "hatR_i_j_";
		case HATRZ: return "hatr_Z";
		case HATR: return "hatr";
		case HATBASER: return "hatR";
		case HATR0: return "hatr_0";
		case HATBASER0: return "hatR_0";
		case HATZ: return "hatZ";
		case HATRIJ: return "hatr_i_j_";
		case HATABARIBARJ: return "hata_BariBarj_";
		case HATBBARIBARJ: return "hatb_BariBarj_";
		case HATRBARIBARJ: return "hatr_BariBarj_";
		case HATCI: return "hatC_i_";
		case HATU: return "hatU";
		case HATMAP: return "hatMap";
		
		
		case UNDEFINED: throw new IllegalArgumentException("URNType " + t + " does not define suffixes.");
		}
		throw new IllegalArgumentException("URNType " + t + " does not exist.");
	}

	public static String getNameSpaceComponentClass(URNType t) {
		switch(t) {
		case RV: return "baseRepresentationMap.vertex";
		case RE: return "baseRepresentationMap.edge.";
		case MODN: return "modulus";
		case BASES: return "bases";
		case BASEZ: return "bases";
		case BASER: return "bases";
		case BASER0: return "bases";
		case BASERI: return "bases";
		case BASERIJ: return "bases";
		case CCHALLENGE: return "challenge";
		case EI: return "vertex.representative";
		case APRIME: return "signature";
		case CI: return "commitment";
		case U: return "commitment";
		case NONCEI: return "nonce";
		case PI: return "proofsignature";
		
		case ABARIBARJ: return "secret";
		case BBARIBARJ: return "secret";
		case RBARIBARJ: return "secret";
		case M0: return "secret";
		case MI: return "secret"; // TODO Conventions used so far?
		case MIJ: return "secret";
		case RI: return "secret";
		case DLRV: return "discretelogs.vertex";
		case DLRE: return "discretelogs.edge";
		case SIGMA: return "signature";
		case EPRIME: return "signature";
		case VPRIME: return "signature";
		case A: return "signature";
		case E: return "signature";
		case V: return "signature";
		
		case TILDEA: return "witnesses";
		case TILDED: return "witnesses.randomness";
		case TILDEE: return "witnesses.randomness";
		case TILDEV: return "witnesses.randomness";
		case TILDEVPRIME: return "witnesses.randomness";
		case TILDEM0: return "witnesses.randomness";
		case TILDEMI: return "witnesses.randomness.vertex";
		case TILDEMIJ: return "witnesses.randomness.edge";
		case TILDERI: return "witnesses.randomness.vertex";
		case TILDER: return "witnesses.randomness";
		case TILDER0: return "witnesses.randomness";
		case TILDERZ: return "witnesses.randomness";
		case TILDEABARIBARJ: return "witnesses.randomness";
		case TILDEBBARIBARJ: return "witnesses.randomness";
		case TILDERBARIBARJ: return "witnesses.randomness";
		case TILDEBASEZ: return "witnesses";
		case TILDEBASER: return "witnesses";
		case TILDEBASER0: return "witnesses";
		case TILDEBASERI: return "witnesses";
		case TILDEBASERIJ: return "witnesses";
		case TILDEU: return "witnesses";
		case TILDECI: return "witnesses";
		case TILDEZ: return "witnesses";
		case TILDERIJ: return "witnesses";
		case TILDEBASERBARIBARJ: return "witnesses";
		
		case HATA: return "responses";
		case HATD: return "responses";
		case HATE: return "responses";
		case HATV: return "responses";
		case HATVPRIME: return "responses";
		case HATM0: return "responses";
		case HATMI: return "responses.vertex";
		case HATMIJ: return "responses.edge";
		case HATRI: return "responses.vertex";
		case HATBASERI: return "responses.vertex";
		case HATRIJ: return "responses.edge";
		case HATBASERIJ: return "responses.edge";
		case HATRZ: return "responses";
		case HATR: return "responses";
		case HATBASER: return "responses";
		case HATZ: return "responses";
		case HATR0: return "responses";
		case HATBASER0: return "responses";
		case HATABARIBARJ: return "responses";
		case HATBBARIBARJ: return "responses";
		case HATRBARIBARJ: return "responses";
		case HATCI: return "responses";
		case HATU: return "responses";
		case HATMAP: return "responses";
		
		case UNDEFINED: throw new IllegalArgumentException("URNType " + t
				+ " does not offer namespace components.");
		}
		throw new IllegalArgumentException("URNType " + t + " does not exist.");
	}

	/**
	 * Returns the class of an URNType, that is, whether  the URNType
	 * holds a secret, a witness or corresponding randomness (tilde-value), 
	 * a response (hat-value) or a public value (e.g., a commitment value or a base);
	 *
	 * @param t the type of the URN
	 * @return class of an URNType
	 */
	public static URNClass getClass(URNType t) {
		switch(t) {
		case RV: return URNClass.PUBLIC;
		case RE: return URNClass.PUBLIC; 
		case MODN: return URNClass.PUBLIC;
		case BASES: return URNClass.PUBLIC;
		case BASEZ: return URNClass.PUBLIC;
		case BASER: return URNClass.PUBLIC;
		case BASER0: return URNClass.PUBLIC;
		case BASERI: return URNClass.PUBLIC;
		case BASERIJ: return URNClass.PUBLIC;
		case CCHALLENGE: return URNClass.PUBLIC;
		case EI: return URNClass.PUBLIC;
		case APRIME: return URNClass.PUBLIC;
		case CI: return URNClass.PUBLIC;
		case U: return URNClass.PUBLIC;
		case NONCEI: return URNClass.PUBLIC;
		case PI: return URNClass.PUBLIC;
		
		case ABARIBARJ: return URNClass.SECRET;
		case BBARIBARJ: return URNClass.SECRET;
		case RBARIBARJ: return URNClass.SECRET;
		case M0: return URNClass.SECRET;
		case MI: return URNClass.SECRET;
		case MIJ: return URNClass.SECRET;
		case RI: return URNClass.SECRET;
		case DLRV: return URNClass.SECRET;
		case DLRE: return URNClass.SECRET;
		case SIGMA: return URNClass.SECRET;
		case EPRIME: return URNClass.SECRET;
		case VPRIME: return URNClass.SECRET;
		case A: return URNClass.SECRET;
		case E: return URNClass.SECRET;
		case V: return URNClass.SECRET;
		
		case TILDEA: return URNClass.TILDE;
		case TILDED: return URNClass.TILDE;
		case TILDEE: return URNClass.TILDE;
		case TILDEV: return URNClass.TILDE;
		case TILDEVPRIME: return URNClass.TILDE;
		case TILDEM0: return URNClass.TILDE;
		case TILDEMI: return URNClass.TILDE;
		case TILDEMIJ: return URNClass.TILDE;
		case TILDERI: return URNClass.TILDE;
		case TILDER: return URNClass.TILDE;
		case TILDER0: return URNClass.TILDE;
		case TILDERZ: return URNClass.TILDE;
		case TILDEABARIBARJ: return URNClass.TILDE;
		case TILDEBBARIBARJ: return URNClass.TILDE;
		case TILDERBARIBARJ: return URNClass.TILDE;
		case TILDEBASEZ: return URNClass.TILDE;
		case TILDEBASER: return URNClass.TILDE;
		case TILDEBASER0: return URNClass.TILDE;
		case TILDEBASERI: return URNClass.TILDE;
		case TILDEBASERIJ: return URNClass.TILDE;
		case TILDEU: return URNClass.TILDE;
		case TILDECI: return URNClass.TILDE;
		case TILDEZ: return URNClass.TILDE;
		case TILDERIJ: return URNClass.TILDE;
		case TILDEBASERBARIBARJ: return URNClass.TILDE;
		
		case HATA: return URNClass.HAT;
		case HATD: return URNClass.HAT;
		case HATE: return URNClass.HAT;
		case HATV: return URNClass.HAT;
		case HATVPRIME: return URNClass.HAT;
		case HATM0: return URNClass.HAT;
		case HATMI: return URNClass.HAT;
		case HATMIJ: return URNClass.HAT;
		case HATRI: return URNClass.HAT;
		case HATBASERI: return URNClass.HAT;
		case HATRIJ: return URNClass.HAT;
		case HATBASERIJ: return URNClass.HAT;
		case HATRZ: return URNClass.HAT;
		case HATR: return URNClass.HAT;
		case HATBASER: return URNClass.HAT;
		case HATZ: return URNClass.HAT;
		case HATR0: return URNClass.HAT;
		case HATBASER0: return URNClass.HAT;
		case HATABARIBARJ: return URNClass.HAT;
		case HATBBARIBARJ: return URNClass.HAT;
		case HATRBARIBARJ: return URNClass.HAT;
		case HATCI: return URNClass.HAT;
		case HATU: return URNClass.HAT;
		case HATMAP: return URNClass.HAT;
		
		case UNDEFINED: return URNClass.UNDEFINED;
		}
		throw new IllegalArgumentException("URNType " + t + " does not exist.");
	}

	public static boolean isEnumerable(URNType t) {
		switch(t) {
		case RV: return true;
		case RE: return true;
		case BASERI: return true;
		case BASERIJ: return true;
		case EI: return true;
		case CI: return true;
		case NONCEI: return true;
		case PI: return true;
		
		case ABARIBARJ: return true;
		case BBARIBARJ: return true;
		case RBARIBARJ: return true;
		case MI: return true;
		case MIJ: return true;
		case RI: return true;
		case DLRV: return true;
		case DLRE: return true;
		
		case TILDEMI: return true;
		case TILDEMIJ: return true;
		case TILDERI: return true;
		case TILDERIJ: return true;
		case TILDECI: return true;
		case TILDEABARIBARJ: return true;
		case TILDEBBARIBARJ: return true;
		case TILDERBARIBARJ: return true;
		case TILDEBASERI: return true;
		case TILDEBASERIJ: return true;
		case TILDEBASERBARIBARJ: return true;
		
		case HATMI: return true;
		case HATMIJ: return true;
		case HATRI: return true;
		case HATBASERI: return true;
		case HATBASERIJ: return true;
		case HATABARIBARJ: return true;
		case HATBBARIBARJ: return true;
		case HATRBARIBARJ: return true;
		case HATCI: return true;
		default: return false;
		}
	}

	/**
	 * Builds an URN Component for a prover class fulfilling the IProver interface
	 * or a verifier fulfilling the IVerifier interface.
	 *
	 * @param t URNType
	 * @param c Class governing the datum
	 * @return String URN component to identify a datum of that class in the ProofStore.
	 */
	@SuppressWarnings("rawtypes")
	public static String buildURNComponent(URNType t, Class c) {
		if (URNType.isEnumerable(t)) {
			throw new IllegalArgumentException("URNType " + t + " is enumerable and should be evaluated with an index.");
		}

		String proverID;
		try {
			proverID = (String) c.getDeclaredField("URNID").get(null);
		} catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
			throw new IllegalArgumentException("URNID of component " + c.getName() + " could not be accessed.", e);
		}


		return proverID + URN.DOT + URNType.getNameSpaceComponentClass(t) + URN.DOT + URNType.getSuffix(t);
	}

	/**
	 * Creates an URN for a baseType and URNClass, setting the index for enumberable URNs
	 * to the base index.
	 * 
	 * @param base BaseRepresentation to analyzed,
	 * @param urnClass URNClass intended.
	 * @param c Governing class.
	 * 
	 * @return URN representing that data.
	 */
	@SuppressWarnings("rawtypes")
	public static URN buildURNbyBaseType(BaseRepresentation base, URNClass urnClass, Class c) {
		URNType urnType = getURNTypebyBaseType(base, urnClass);
		if (URNType.isEnumerable(urnType)) {
			return buildURN(getURNTypebyBaseType(base, urnClass), c, base.getBaseIndex());
		} else {
			return buildURN(getURNTypebyBaseType(base, urnClass), c);
		}
	}
	
	/**
	 * Creates an URN for a baseType and URNClass, setting the index for the URN manually
	 * (thta is ignoring the base index).
	 * 
	 * @param base BaseRepresentation to analyzed,
	 * @param urnClass URNClass intended.
	 * @param index index of the URN.
	 * @param c Governing class.
	 * 
	 * @return URN representing that data.
	 */
	@SuppressWarnings("rawtypes")
	public static URN buildURNbyBaseType(BaseRepresentation base, URNClass urnClass, int index, Class c) {
		return buildURN(getURNTypebyBaseType(base, urnClass), c, index);
	}

    /**
     * Creates an URN for a prover/verifier class with the IProver/IVerifier interface.
     *
     * @param base     the base
     * @param urnClass the urn class
     * @return URN representing that data.
     */
    public static URNType getURNTypebyBaseType(BaseRepresentation base, URNClass urnClass) {
		BASE baseType = base.getBaseType();
		
		switch (urnClass) {
		case TILDE: 
				switch (baseType) {
					case VERTEX: return TILDEMI;
					case EDGE: return TILDEMIJ;
					case BASE0: return TILDEM0;
					default: throw new IllegalArgumentException("There was no canonical representation "
							+ "for base type " + baseType + " and URNClass " + urnClass);
				}
	
		case HAT: 
				switch (baseType) {
					case VERTEX: return HATMI;
					case EDGE: return HATMIJ;
					case BASE0: return HATM0;
					default: throw new IllegalArgumentException("There was no canonical representation "
							+ "for base type " + baseType + " and URNClass " + urnClass);
				}
		default: throw new IllegalArgumentException("There was no canonical representation "
				+ "for base type " + baseType + " and URNClass " + urnClass);
		}
	}
	
	/**
	 * Builds an URN Component for a prover class fulfilling the IProver interface
	 * or a verifier fulfilling the IVerifier interface.
	 *
	 * @param t URNType
	 * @param c Class governing the datum
	 * @return String URN component to identify a datum of that class in the ProofStore.
	 */
	@SuppressWarnings("rawtypes")
	public static String buildURNComponentByBaseType(URNType t, Class c) {
		if (URNType.isEnumerable(t)) {
			throw new IllegalArgumentException("URNType " + t + " is enumerable and should be evaluated with an index.");
		}

		String proverID;
		try {
			proverID = (String) c.getDeclaredField("URNID").get(null);
		} catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
			throw new IllegalArgumentException("URNID of component " + c.getName() + " could not be accessed.", e);
		}


		return proverID + URN.DOT + URNType.getNameSpaceComponentClass(t) + URN.DOT + URNType.getSuffix(t);
	}

	/**
	 * Creates an URN for a prover/verifier class with the IProver/IVerifier interface.
	 * 
	 * @param t URNType to use.
	 * @param c Governing class.
	 * 
	 * @return URN representing that data.
	 */
	@SuppressWarnings("rawtypes")
	public static URN buildURN(URNType t, Class c) {
		return URN.createZkpgsURN(buildURNComponent(t, c));
	}

	/**
	 * Creates an URN for a prover/verifier class with the IProver/IVerifier interface.
	 * 
	 * @param t URNType to use.
	 * @param c Governing class.
	 * @param index Index of the URN created.
	 * 
	 * @return URN representing that data.
	 */
	@SuppressWarnings("rawtypes")
	public static URN buildURN(URNType t, Class c, int index) {
		return URN.createZkpgsURN(buildURNComponent(t, c, index));
	}

	/**
	 * Builds an URN Component for a prover class fulfilling the IProver interface.
	 *
	 * @param t URNType
	 * @param c Class governing the datum
	 * @param index int index of the datum
	 * @return String URN component to identify a datum of that class in the ProofStore.
	 */
	@SuppressWarnings("rawtypes")
	public static String buildURNComponent(URNType t, Class c, int index) {
		if (!URNType.isEnumerable(t)) {
			throw new IllegalArgumentException("URNType " + t + " is not enumerable and should not be evaluated with an index.");
		}

		if (!isURNGoverner(c)) {
			throw new IllegalArgumentException("Class " + c.getName() + " does not implement an IURNGoverner interface.");
		}

		String proverID;
		try {
			proverID = (String) c.getDeclaredField("URNID").get(null);
		} catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
			throw new IllegalArgumentException("URNID of component " + c.getName() + " could not be accessed.", e);
		}

		return proverID + URN.DOT + URNType.getNameSpaceComponentClass(t) + URN.DOT + URNType.getSuffix(t) + index;
	}

	@SuppressWarnings("rawtypes")
	public static boolean isURNGoverner(Class c) {
		Class[] implementedInterfaces = c.getInterfaces();
		for (Class inter : implementedInterfaces) {
			if (inter.equals(IURNGoverner.class)
					|| inter.equals(IProver.class) || inter.equals(IVerifier.class)
					|| inter.equals(IProverOrchestrator.class) || inter.equals(IVerifierOrchestrator.class)
					|| inter.equals(IKeyPair.class) || inter.equals(IPublicKey.class)) 
				return true;
		}
		return false;
	}

	/**
	 * Generates a list of URNs for a given prover/verifier, based on a list of (non-enumerable) URNType instances.
	 *
	 * @param list List of URNType
	 * @param c prover or verifier class
	 *
	 * @return List of URN for the given prover/verifier
	 */
	@SuppressWarnings("rawtypes")
	public static List<URN> buildURNList(List<URNType> list, Class c) {
		List<URN> urnList = new ArrayList<URN>(list.size());
		for (URNType urnType : list) {
			URN.createZkpgsURN(buildURNComponent(urnType, c));
		}
		return urnList;
	}

	/**
	 * Generates a list of URNs for a given prover/verifier, based on a list of enumerable URNType instances.
	 *
	 * @param list List of URNType
	 * @param enumeratedList List of EnumeratedURNType
	 * @param c prover or verifier class
	 *
	 * @return List of URN for the given prover/verifier
	 */
	@SuppressWarnings("rawtypes")
	public static List<URN> buildURNList(List<URNType> list, List<EnumeratedURNType> enumeratedList, Class c) {
		List<URN> urnList = new ArrayList<URN>(list.size());
		for (URNType urnType : list) {
			URN.createZkpgsURN(buildURNComponent(urnType, c));
		}
		for (EnumeratedURNType urnType : enumeratedList) {
			URN.createZkpgsURN(buildURNComponent(urnType.type, c, urnType.index));
		}

		return urnList;
	}

	/**
	 * Parses an URN String and returns the URNType, based on its suffix.
	 * 
	 * @param urnString namespace-specific string of the URN
	 * 
	 * @return URNType as given by the suffix.
	 */
	protected static URNType parseURNType(String urnString) {
		return URNType.parseURNSuffix(URN.parseSuffix(urnString));

	}

	/**
	 * Returns the URNType based on an URNSuffix
	 * 
	 * @param urnSuffix suffix of an URN namespace-specific component
	 * 
	 * @return URNType as given by the suffix.
	 */
	protected static URNType parseURNSuffix(String urnSuffix) {
		URNType[] urnTypes = URNType.values();
		for (int i = 0; i < urnTypes.length; i++) {
			if (urnTypes[i].equals(URNType.UNDEFINED)) continue;
			if (urnSuffix.equals(URNType.getSuffix(urnTypes[i])) || urnSuffix.startsWith(URNType.getSuffix(urnTypes[i]))) {
				return urnTypes[i];
			}
		}

		throw new IllegalArgumentException("The URNType for suffix " + urnSuffix + " could not be determined.");
	}
	
	/**
	 * Checks for the internal consistency of the URNType system.
	 * Each defined URNType is required to offer an non-UNDEFINED URNClass, a suffix String
	 * and a namespace component class.
	 * 
	 * <p>Suffixes of tilde-values must start with "tilde"; 
	 * suffixes of hat-values must start with "hat". 
	 * 
	 * @return <tt>true</tt> if each URNType fulfills the provisions of being consistent.
	 */
	protected static boolean isConsistent() {
		URNType[] urnTypes = URNType.values();
		for (int i = 0; i < urnTypes.length; i++) {
			if (urnTypes[i].equals(URNType.UNDEFINED)) continue;
			try {
				String suffix = URNType.getSuffix(urnTypes[i]);
				if (suffix == null || suffix.equals("")) {
					return false;
				}
				
				URNClass urnClass = URNType.getClass(urnTypes[i]);
				if (urnClass == null || urnClass.equals(URNClass.UNDEFINED)) {
					return false;
				}
				
				if (urnClass.equals(URNClass.TILDE) && !suffix.startsWith("tilde")) {
					return false;
				}
				if (urnClass.equals(URNClass.HAT) && !suffix.startsWith("hat")) {
					return false;
				}
				
				String classString = getNameSpaceComponentClass(urnTypes[i]);
				if (classString == null || classString.equals("")) {
					return false;
				}
			} catch (RuntimeException e) {
				return false;
			}
		}
		return true;
	}
	
	/**
	 * Checks whether a urnType is valid for a given suffix.
	 * 
	 * @param urnType URNType to test.
	 * @param suffix designated suffix.
	 * 
	 * @return <tt>true</tt> if urnType is valid
	 */
	protected static boolean isTypeValid(URNType urnType, String suffix) {
		return suffix.equals(URNType.getSuffix(urnType)) ||
				suffix.startsWith(URNType.getSuffix(urnType));
	}
}
