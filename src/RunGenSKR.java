import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class RunGenSKR {

	private final static String groupName = "Foo";

	public static void main(String[] args) {
		// Ottengo l'istanza del PrivateKeyRing
		PrivateKeyRing skr = PrivateKeyRing.getInstance();

		// Genero la coppia di chiavi RSA per cifrare/decifrare
		KeyPair RSAKeyPair = null;
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
			keyPairGen.initialize(1024);
			RSAKeyPair = keyPairGen.genKeyPair();
		} catch (NoSuchAlgorithmException e2) {
			e2.printStackTrace();
		}

		// Genero la coppia di chiavi DSA per firmare/verificare
		KeyPair DSAKeyPair = null;
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
			keyPairGen.initialize(1024);
			DSAKeyPair = keyPairGen.genKeyPair();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}

		// Inserisco le coppie di chiavi generate (RSA e DSA) nel mazzo di
		// chiavi privato
		Key key = RSAKeyPair.getPublic();
		skr.setKey(groupName + "_EPK", key); 

		key = RSAKeyPair.getPrivate();
		skr.setKey(groupName + "_ESK", key);

		key = DSAKeyPair.getPublic();
		skr.setKey(groupName + "_SPK", key);

		key = DSAKeyPair.getPrivate();
		skr.setKey(groupName + "_SSK", key);

		// Genero una chiave AES a 128 bit
		SecretKey AESKey = null;
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			AESKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		// Genero una chiave DESede a 168 bit
		SecretKey DESedeKey = null;
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
			keyGen.init(168);
			DESedeKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		// Inserisco le chiavi AES e DESede nel mazzo di chiavi privato
		skr.setKey(groupName + "_AES", AESKey);
		skr.setKey(groupName + "_DESede", DESedeKey);

		// Salvo sul disco il KeyRing privato
		try {
			skr.store(new FileOutputStream(new File("privateKeyRing.enc")), "paperino".toCharArray());
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
