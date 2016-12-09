import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

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
	private List<Record> keyRing;

	private PrivateKeyRing() throws InvalidKeySpecException, NoSuchAlgorithmException {
		keyRing = new ArrayList<>();
	}

	public static PrivateKeyRing getInstance() throws InvalidKeySpecException, NoSuchAlgorithmException {
		if (instance == null)
			instance = new PrivateKeyRing();
		return instance;
	}

	// La key restituita è una chiave opaca
	public Key getKey(String alias) throws Exception {
		Record record = findRecord(alias);
		if (record == null)
			throw new Exception("Key not found!");

		byte[] encodedKey = record.getEncodedKey();
		String keyType = record.getKeyType();
		String keyAlgorithm = keyType.split("/")[0];
		String keyFormat = keyType.split("/")[1];

		Key key = null;
		if (keyAlgorithm.equals("RSA") || keyAlgorithm.equals("DSA")) {
			KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);

			if (keyFormat.equals("X.509"))
				key = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			else if (keyFormat.equals("PKCS#8"))
				key = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
		} else {
			// Genero la chiave opaca a partire dall'array di byte
			// (SecretKeySpec implementa sia KeySpec che SecretKey). Opero in
			// questo modo perché in Java manca il SecretKeyFactory per AES (è
			// un bug conosciuto, sono supportati solo DES e DESede).
			// http://bugs.java.com/view_bug.do?bug_id=7022467
			key = new SecretKeySpec(encodedKey, keyAlgorithm);
		}

		if (key == null)
			throw new Exception("Invalid key type!");

		return key;
	}

	// La key presa in ingresso è una chiave opaca
	public void setKey(String alias, Key key, String keyType) {
		Record record = findRecord(alias);
		if (record != null)
			keyRing.remove(record);

		keyRing.add(new Record(alias, key.getEncoded(), keyType));
	}

	// Funzioncina di comodo da documentare
	private Record findRecord(String alias) {
		Record record = null;
		for (Record r : keyRing)
			if (r.getAlias().equals(alias))
				record = r;
		return record;
	}

	// Classe innestata da documentare
	public static final class Record {

		private String alias;
		private byte[] encodedKey;
		private String keyType; // "Algorithm/Format" (e.g. RSA/X.509)

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
