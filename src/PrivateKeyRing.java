import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

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
	private List<Record> keyRing;

	private PrivateKeyRing() throws InvalidKeySpecException, NoSuchAlgorithmException {
		keyRing = new ArrayList<>();

		KeyPair keyPairRSA, keyPairDSA;
		KeyPairGenerator keyPairGenRSA = KeyPairGenerator.getInstance("RSA");
		keyPairGenRSA.initialize(1024);
		keyPairRSA = keyPairGenRSA.genKeyPair();

		KeyPairGenerator keyPairGenDSA = KeyPairGenerator.getInstance("DSA");
		keyPairGenDSA.initialize(1024);
		keyPairDSA = keyPairGenDSA.genKeyPair();

		// EPK = public encryption key
		keyRing.add(new Record(groupName + "_EPK", keyPairRSA.getPublic().getEncoded(), "EPK"));
		// ESK = private decryption key
		keyRing.add(new Record(groupName + "_ESK", keyPairRSA.getPrivate().getEncoded(), "ESK"));
		// SPK = public verification key
		keyRing.add(new Record(groupName + "_SPK", keyPairDSA.getPublic().getEncoded(), "SPK"));
		// SSK = private signing key
		keyRing.add(new Record(groupName + "_SSK", keyPairDSA.getPrivate().getEncoded(), "SSK"));
	}

	public static PrivateKeyRing getInstance() throws InvalidKeySpecException, NoSuchAlgorithmException {
		if (instance == null)
			instance = new PrivateKeyRing();
		return instance;
	}

	public Key getKey(String alias) throws Exception {
		byte[] encodedKey = null;
		String keyType = null;
		for (Record r : keyRing) {
			if (r.getAlias().equals(alias)) {
				encodedKey = r.getEncodedKey();
				keyType = r.getKeyType();
			}
		}

		if (encodedKey == null)
			throw new Exception("Key not found!");

		Key key = null;
		if (keyType.equals("EPK") || keyType.equals("ESK")) {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			if (keyType.equals("EPK"))
				key = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			else
				key = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
		}
		if (keyType.equals("SPK") || keyType.equals("SSK")) {
			KeyFactory keyFactory = KeyFactory.getInstance("DSA");
			if (keyType.equals("SPK"))
				key = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			else
				key = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
		}

		if (key == null)
			throw new Exception("Invalid key type!");

		return key;
	}

	/* Nested class */
	public static final class Record {

		private String alias;
		private byte[] encodedKey; // chiave trasparente
		private String keyType;

		public Record(String alias, byte[] encodedKey, String keyType) {
			this.alias = alias;
			this.encodedKey = encodedKey;
			this.keyType = keyType;
		}

		public String getAlias() {
			return alias;
		}

		public byte[] getEncodedKey() {
			return encodedKey;
		}

		public String getKeyType() {
			return keyType;
		}

	}

}
