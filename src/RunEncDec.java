import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class RunEncDec {

	public static void main(String[] args) {
		// Crea il file in chiaro contenente il messaggio
		try {
			makePlainFile("plainFile.txt");
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Carico il KeyRing privato dal disco
		PrivateKeyRing skr = PrivateKeyRing.getInstance();
		try {
			skr.load(new FileInputStream(new File("privateKeyRing.enc")), "paperino".toCharArray());
		} catch (ClassNotFoundException | GeneralSecurityException | IOException e) {
			e.printStackTrace();
		}

		// Ottengo le due chiavi segrete AES e DESede dal PrivateKeyRing
		SecretKey AESKey = null, DESedeKey = null;
		try {
			AESKey = (SecretKey) skr.getKey("Foo_AES");
			DESedeKey = (SecretKey) skr.getKey("Foo_DESede");
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Cifro il file o con AES o con DESede
		try {
			encFile("plainFile.txt", AESKey);
			System.out.println("File cifrato con successo!");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IOException e) {
			e.printStackTrace();
		}

		// Decifro il file o con AES o con DESede
		try {
			decFile("plainFileENC.txt.enc", AESKey);
			System.out.println("File decifrato con successo!");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IOException e) {
			e.printStackTrace();
		}
	}

	private static void makePlainFile(String fileName) throws IOException {
		// Ottengo la data corrente nel formato dd/mm/yyyy
		Date date = Calendar.getInstance().getTime();
		DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
		String today = formatter.format(date);

		// Genero un nonce di 20 byte
		byte[] nonce = new byte[20];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(nonce);

		// Scrivo il messaggio sul disco
		FileOutputStream fos = new FileOutputStream(new File(fileName));
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos, "UTF-8"));
		bw.write("**********************************************" + System.getProperty("line.separator"));
		bw.write("* Laurea Magistrale in Ingegneria Informatica" + System.getProperty("line.separator"));
		bw.write("* Corso di Sicurezza Informatica" + System.getProperty("line.separator"));
		bw.write("* Messaggio del " + today + System.getProperty("line.separator"));
		bw.write("* Dal gruppo: Foo" + System.getProperty("line.separator"));
		bw.write("* Al gruppo: Foo" + System.getProperty("line.separator"));
		bw.write("* Nonce: " + Base64.getEncoder().encodeToString(nonce) + System.getProperty("line.separator"));
		bw.write("**********************************************");
		bw.close();
	}

	private static void encFile(String plainFileName, SecretKey key)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		// Inizializzo il cifrario in cifratura con chiave AES a 128 bit o
		// DESede a 168 bit
		Cipher cipher = Cipher.getInstance(key.getAlgorithm() + "/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);

		FileOutputStream fos = new FileOutputStream(new File(plainFileName.replace(".txt", "ENC.txt.enc")));
		// Salvo l'IV sul file
		fos.write(cipher.getIV());
		CipherOutputStream cos = new CipherOutputStream(fos, cipher);

		// Leggo il contenuto dal file in chiaro e lo scrivo, cifrandolo, nel
		// nuovo file
		FileInputStream fis = new FileInputStream(new File(plainFileName));
		byte[] buffer = new byte[1024];
		int len;
		while ((len = fis.read(buffer)) > 0)
			cos.write(buffer, 0, len);
		fis.close();
		cos.close();
	}

	private static void decFile(String encFileName, SecretKey key) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
		FileInputStream fis = new FileInputStream(new File(encFileName));
		byte[] IV = new byte[key.getAlgorithm().equals("AES") ? 16 : 8];
		// Leggo l'IV dal file cifrato
		fis.read(IV);

		// Inizializzo il cifrario in decifratura con chiave AES a 128 bit o
		// DESede a 168 bit
		Cipher cipher = Cipher.getInstance(key.getAlgorithm() + "/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));

		// Leggo il contenuto dal file cifrato e lo scrivo, decifrandolo, nel
		// nuovo file
		String plainFileName = encFileName.replace("ENC", "DEC").split(".enc")[0];
		FileOutputStream fos = new FileOutputStream(new File(plainFileName));
		CipherOutputStream cos = new CipherOutputStream(fos, cipher);

		byte[] buffer = new byte[1024];
		int len;
		while ((len = fis.read(buffer)) > 0)
			cos.write(buffer, 0, len);
		fis.close();
		cos.close();
	}

}