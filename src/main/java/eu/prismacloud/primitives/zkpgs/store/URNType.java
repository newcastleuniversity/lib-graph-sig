package eu.prismacloud.primitives.zkpgs.store;

import java.util.ArrayList;
import java.util.List;

import eu.prismacloud.primitives.zkpgs.prover.IProver;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.verifier.IVerifier;

public enum URNType {
  ABARIBARJ,
  BBARIBARJ,
  RBARIBARJ,
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
	TILDEU,
	TILDEZ,
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
	HATR0,
	HATZ,
 HATABARIBARJ,
 HATBBARIBARJ,
 HATRBARIBARJ;

	private URNType() {}

	public static String getSuffix(URNType t) {
		switch(t) {
		case ABARIBARJ: return "a_BariBarj_";
		case BBARIBARJ: return "b_BariBarj_";
		case RBARIBARJ: return "r_BariBarj_";
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
		case TILDEZ: return "tildeZ";
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
		case HATR0: return "hatr_0";
		case HATZ: return "hatZ";
		case HATRIJ: return "hatr_i_j_";
		case HATABARIBARJ: return "hata_BariBarj_";
		case HATBBARIBARJ: return "hatb_BariBarj_";
		case HATRBARIBARJ: return "hatr_BariBarj_";
		}
		throw new RuntimeException("URNType " + t + " does not exist.");
	}

	public static String getClass(URNType t) {
		switch(t) {
		case ABARIBARJ: return "secret";
		case BBARIBARJ: return "secret";
		case RBARIBARJ: return "secret";
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
		case TILDEZ: return "witnesses";
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
		case HATZ: return "responses";
		case HATR0: return "responses";
		case HATABARIBARJ: return "responses";
		case HATBBARIBARJ: return "responses";
		case HATRBARIBARJ: return "responses";
		}
		throw new RuntimeException("URNType " + t + " does not exist.");
	}

	public static boolean isEnumerable(URNType t) {
		switch(t) {
		case ABARIBARJ: return true;
		case BBARIBARJ: return true;
		case RBARIBARJ: return true;
		case TILDEMI: return true;
		case TILDEMIJ: return true;
		case TILDERI: return true;
		case TILDERIJ: return true;
		case TILDEABARIBARJ: return true;
		case TILDEBBARIBARJ: return true;
		case TILDERBARIBARJ: return true;
		case TILDEBASERI: return true;
		case TILDEBASERIJ: return true;
		case HATMI: return true;
		case HATMIJ: return true;
		case HATRI: return true;
		case HATBASERI: return true;
		case HATBASERIJ: return true;
		case HATABARIBARJ: return true;
		case HATBBARIBARJ: return true;
		case HATRBARIBARJ: return true;
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
			  throw new RuntimeException("URNType " + t + " is enumerable and should be evaluated with an index.");
		  }

		String proverID;
		  try {
			proverID = (String) c.getDeclaredField("URNID").get(null);
		} catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
			throw new RuntimeException("URNID of component " + c.getName() + " could not be accessed.", e);
		}


		return proverID + URN.DOT + URNType.getClass(t) + URN.DOT + URNType.getSuffix(t);
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
			  throw new RuntimeException("URNType " + t + " is not enumerable and should not be evaluated with an index.");
		}

		if (!isProverVerifier(c)) {
			throw new RuntimeException("Class " + c.getName() + " does neither implement the IProver nor the IVerifier interface.");
		}

		String proverID;
		try {
			proverID = (String) c.getDeclaredField("URNID").get(null);
		} catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
			throw new RuntimeException("URNID of component " + c.getName() + " could not be accessed.", e);
		}


		return proverID + URN.DOT + URNType.getClass(t) + URN.DOT + URNType.getSuffix(t) + index;
	}

	@SuppressWarnings("rawtypes")
	public static boolean isProverVerifier(Class c) {
		Class[] implementedInterfaces = c.getInterfaces();
		for (Class inter : implementedInterfaces) {
			if (inter.equals(IProver.class) || inter.equals(IVerifier.class)) return true;
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
}
