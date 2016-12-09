import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class PrivateKeyRing {

	/*
	 * KeyRing = mazzo di chiavi, strumento per memorizzare (e quindi
	 * conservare) chiavi, dev'essere simile al KeyStore di Java. Il KeyRing
	 * dev'essere disponibile in 2 versioni: pubblica e privata. Partendo dal
	 * presupposto che ciascun gruppo abbia: una coppia di chiavi
	 * (pubblica/privata) per cifrare, una coppia di chiavi (pubblica/privata)
	 * per firmare, una chiave AES a 128 bit e una chiave DESede a 168 bit, nel
	 * KeyRing privato devono essere conservate le coppie di chiavi
	 * (pubblica/privata) per cifrare e firmare e quelle segrete del gruppo
	 * (credo intenda quelle AES a 128 e DESede a 168 bit). Nel KeyRing
	 * pubblico, invece, devono essere memorizzate le chiavi (pubbliche) per
	 * cifrare e firmare degli altri gruppi del corso. Ma come funziona uno
	 * schema di cifratura a chiave pubblica (e.g. RSA)? Facciamo un esempio.
	 * Supponiamo che Angelo voglia comunicare con Christian e Marcello; ciascun
	 * utente ha una coppia di chiavi (pubblica/privata, il KeyPair in sostanza)
	 * generate opportunamente. Ciascun utente, inoltre, avrà nel proprio mazzo
	 * di chiavi anche tutte le chiavi "pubbliche" degli altri. Se Angelo vuole
	 * comunicare con Christian cosa succede? Angelo cifra
	 * "con la chiave pubblica di Christian" il messaggio; quando il messaggio
	 * arriva a Christian, quest'ultimo può decifrarlo con la
	 * "propria chiave privata"; viceversa, quando Christian vuole comuninicare
	 * con Angelo, cifra il messaggio con la k_pub di Angelo, e Angelo decifrerà
	 * il messaggio con la propria chiave privata. In sostanza, le chiavi
	 * pubbliche di tutti, sono conosciute da tutti, e le si utilizzano per
	 * cifrare; le chiavi private, invece, sono conosciute solo dai legittimi
	 * possessori e vengono utilizzate in fase di decifratura.
	 */

	private static PrivateKeyRing instance = null;
	private static final String groupName = "I2X3";

	private PrivateKeyRing() {
		KeyPair keyPairRSA, keyPairDSA;
		try {
			KeyPairGenerator keyPairGenRSA = KeyPairGenerator.getInstance("RSA");
			keyPairGenRSA.initialize(1024);
			keyPairRSA = keyPairGenRSA.genKeyPair();

			KeyPairGenerator keyPairGenDSA = KeyPairGenerator.getInstance("DSA");
			keyPairGenDSA.initialize(1024);
			keyPairDSA = keyPairGenDSA.genKeyPair();

			// EPK = public encryption key
			new Record(groupName + "_EPK", keyPairRSA.getPublic().getEncoded());
			// ESK = private decryption key
			new Record(groupName + "_ESK", keyPairRSA.getPrivate().getEncoded());
			// SPK = public verification key
			new Record(groupName + "_SPK", keyPairDSA.getPublic().getEncoded());
			// SSK = private signing key
			new Record(groupName + "_SSK", keyPairDSA.getPrivate().getEncoded());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	public static PrivateKeyRing getInstance() {
		if (instance == null)
			instance = new PrivateKeyRing();
		return instance;
	}

	/* Nested class */
	public static final class Record {

		private String alias;
		private byte[] encodedKey;

		public Record(String alias, byte[] encodedKey) {
			this.alias = alias;
			this.encodedKey = encodedKey;
		}

		public String getAlias() {
			return alias;
		}

		public byte[] getEncodedKey() {
			return encodedKey;
		}

	}

}
