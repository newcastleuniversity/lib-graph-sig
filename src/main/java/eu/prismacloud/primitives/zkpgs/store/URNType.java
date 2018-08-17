package eu.prismacloud.primitives.zkpgs.store;


public enum URNType {
  ABARIBARJ,
  BBARIBARJ,
  RBARIBARJ,
  TILDEE,
  TILDEV,
  TILDEVPRIME,
  TILDEM0,
  TILDEMI,
  TILDEMIJ,
  TILDEABARIBARJ,
  TILDEBBARIBARJ,
  TILDERBARIBARJ,
  HATE,
  HATV,
  HATVPRIME,
  HATM0,
  HATMI,
  HATMIJ,
 HATABARIBARJ,
 HATBBARIBARJ,
 HATRBARIBARJ;

	
	public static String getSuffix(URNType t) {
		switch(t) {
		case ABARIBARJ: return "a_BariBarj_";
		case BBARIBARJ: return "r_BariBarj_";
		case RBARIBARJ: return "r_BariBarj_";
		case TILDEE: return "tildee";
		case TILDEV: return "tildev";
		case TILDEVPRIME: return "tildevprime";
		case TILDEM0: return "tildem_0";
		case TILDEMI: return "tildem_i_";
		case TILDEMIJ: return "tildem_i_j_";
		case TILDEABARIBARJ: return "tildea_BariBarj_";
		case TILDEBBARIBARJ: return "tildeb_BariBarj_";
		case TILDERBARIBARJ: return "tilder_BariBarj_";
		case HATE: return "hate";
		case HATV: return "hatv";
		case HATVPRIME: return "hatvprime";
		case HATM0: return "hatm_0";
		case HATMI: return "hatm_i_";
		case HATMIJ: return "hatm_i_j_";
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
		case TILDEE: return "witnesses.randomness";
		case TILDEV: return "witnesses.randomness";
		case TILDEVPRIME: return "witnesses.randomness";
		case TILDEM0: return "witnesses.randomness";
		case TILDEMI: return "witnesses.randomness.vertex";
		case TILDEMIJ: return "witnesses.randomness.edge";
		case TILDEABARIBARJ: return "witnesses.randomness";
		case TILDEBBARIBARJ: return "witnesses.randomness";
		case TILDERBARIBARJ: return "witnesses.randomness";
		case HATE: return "responses";
		case HATV: return "responses";
		case HATVPRIME: return "responses";
		case HATM0: return "responses";
		case HATMI: return "responses.vertex";
		case HATMIJ: return "responses.edge";
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
		case TILDEABARIBARJ: return true;
		case TILDEBBARIBARJ: return true;
		case TILDERBARIBARJ: return true;
		case HATMI: return true;
		case HATMIJ: return true;
		case HATABARIBARJ: return true;
		case HATBBARIBARJ: return true;
		case HATRBARIBARJ: return true;
		default: return false;
		}
	}
}
