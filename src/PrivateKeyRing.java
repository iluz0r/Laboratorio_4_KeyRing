import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PrivateKeyRing extends KeyRing {

	private static PrivateKeyRing instance = null;

	private PrivateKeyRing() {
		super();
	}

	public static PrivateKeyRing getInstance() {
		if (instance == null)
			instance = new PrivateKeyRing();
		return instance;
	}

	public void load(InputStream is, char[] password)
			throws GeneralSecurityException, IOException, ClassNotFoundException {
		// Recupero salt e IV
		byte[] salt = new byte[8];
		is.read(salt);
		byte[] IV = new byte[16];
		is.read(IV);

		// Calcolo la SecretKey da password e salt
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec keySpec = new PBEKeySpec(password, salt, 65536, 128);
		SecretKey tmp = factory.generateSecret(keySpec);
		SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");

		// Ottengo una istanza del cifrario e lo inizializzo
		Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));

		// Leggo il KeyRing cifrato dal disco
		CipherInputStream cis = new CipherInputStream(is, cipher);
		ObjectInputStream ois = new ObjectInputStream(cis);
		SealedObject sealedObject = (SealedObject) ois.readObject();
		keyRing = (ArrayList<Record>) sealedObject.getObject(cipher);

		ois.close();
	}

	public void store(OutputStream os, char[] password) throws GeneralSecurityException, IOException {
		// Genero la SecretKey a partire dalla password e dal salt
		SecureRandom random = new SecureRandom();
		byte salt[] = new byte[8];
		random.nextBytes(salt);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec keySpec = new PBEKeySpec(password, salt, 65536, 128);
		SecretKey tmp = factory.generateSecret(keySpec);
		SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");

		// Ottengo una istanza del cifrario e lo inizializzo
		Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);

		// Creo il SealedObject del KeyRing per poterlo proteggere
		SealedObject sealedObject = new SealedObject(keyRing, cipher);

		// Salvo il salt e l'IV sul disco
		os.write(salt);
		os.write(cipher.getIV());

		// Salvo il KeyRing sul disco
		CipherOutputStream cos = new CipherOutputStream(os, cipher);
		ObjectOutputStream oos = new ObjectOutputStream(cos);
		oos.writeObject(sealedObject);

		oos.close();
	}

}
