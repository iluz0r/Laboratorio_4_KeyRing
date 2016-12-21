import java.io.Serializable;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.spec.SecretKeySpec;

public abstract class KeyRing {

	protected ArrayList<Record> keyRing;

	public KeyRing() {
		keyRing = new ArrayList<>();
	}

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
		} else
			key = new SecretKeySpec(encodedKey, keyAlgorithm);

		if (key == null)
			throw new Exception("Invalid key type!");

		return key;
	}

	public void setKey(String alias, Key key, String keyType) {
		Record record = findRecord(alias);
		
		// Sovrascrivo il record già esistente
		if (record != null)
			keyRing.remove(record);

		keyRing.add(new Record(alias, key.getEncoded(), keyType));
	}

	private Record findRecord(String alias) {
		Record record = null;
		for (Record r : keyRing)
			if (r.getAlias().equals(alias))
				record = r;
		return record;
	}

	// Classe innestata statica
	public static class Record implements Serializable {

		private static final long serialVersionUID = 1L;

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
