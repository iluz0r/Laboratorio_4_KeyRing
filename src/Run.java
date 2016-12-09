import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Run {

	private static final String groupName = "I2X3";

	public static void main(String[] args) throws Exception {
		PrivateKeyRing skr = PrivateKeyRing.getInstance();

		// Genero la coppia di chiavi RSA per cifrare/decifrare
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024);
		KeyPair RSAKeyPair = keyPairGen.genKeyPair();

		// Genero la coppia di chiavi DSA per firmare/verificare
		keyPairGen = KeyPairGenerator.getInstance("DSA");
		keyPairGen.initialize(1024);
		KeyPair DSAKeyPair = keyPairGen.genKeyPair();

		// Inserisco le coppie di chiavi generate (RSA e DSA) nel mazzo di chiavi privato
		// EPK = public encryption key
		skr.setKey(groupName + "_EPK", RSAKeyPair.getPublic(), "EPK");
		// ESK = private decryption key
		skr.setKey(groupName + "_ESK", RSAKeyPair.getPrivate(), "ESK");
		// SPK = public verification key
		skr.setKey(groupName + "_SPK", DSAKeyPair.getPublic(), "SPK");
		// SSK = private signing key
		skr.setKey(groupName + "_SSK", DSAKeyPair.getPrivate(), "SSK");

		// Genero una chiave AES a 128 bit
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey AESKey = keyGen.generateKey();

		// Genero una chiave DESede a 168 bit
		keyGen = KeyGenerator.getInstance("DESede");
		keyGen.init(168);
		SecretKey DESedeKey = keyGen.generateKey();

		// Inserisco le chiavi AES e DESede nel mazzo di chiavi privato
		skr.setKey(groupName + "_AES", AESKey, "EPK");
		skr.setKey(groupName + "_DESede", DESedeKey, "ESK");

		System.out.println(skr.getKey(groupName + "_SPK"));
	}

}
