import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class RunGenPacket {

	private final static String groupName = "Foo";
	private final static String rcvGroupName = "LupLupi";

	public static void main(String[] args) {
		// Carico il KeyRing privato dal disco
		PrivateKeyRing skr = PrivateKeyRing.getInstance();
		try {
			skr.load(new FileInputStream(new File("privateKeyRing.enc")), "paperino".toCharArray());
		} catch (ClassNotFoundException | GeneralSecurityException | IOException e) {
			e.printStackTrace();
		}

		// Carico il KeyRing pubblico dal disco
		PublicKeyRing pkr = PublicKeyRing.getInstance();
		try {
			pkr.load(new FileInputStream(new File("publicKeyRing.bin")));
		} catch (ClassNotFoundException | IOException e) {
			e.printStackTrace();
		}

		// Genero una chiave AES a 128 bit
		SecretKey AESKey = null;
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			AESKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		// Ottengo una istanza di Cipher e lo inizializzo con la chiave AES
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, AESKey);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		}

		// Crea il file in chiaro contenente il messaggio
		try {
			makePlainFile("message.txt");
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Firmo il file in chiaro con la chiave privata DSA del nostro team
		byte[] signature = null;
		try {
			PrivateKey fooSSK = (PrivateKey) skr.getKey("Foo_SSK");
			signature = signPlainFile("message.txt", fooSSK);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Salvo flag e signature nel pacchetto
		try {
			FileOutputStream fos = new FileOutputStream(new File(groupName + "_to_" + rcvGroupName + ".txt.enc"));
			fos.write(0x00);
			fos.write(signature);
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Cifra la chiave AES (con la chiave pubblica RSA del team
		// destinatario) e la salva nel pacchetto
		try {
			PublicKey recvGroupEPK = (PublicKey) pkr.getKey(rcvGroupName + "_EPK");
			addEncAESKeyToPacket(AESKey, recvGroupEPK);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Salvo l'IV nel pacchetto
		try {
			FileOutputStream fos = new FileOutputStream(new File(groupName + "_to_" + rcvGroupName + ".txt.enc"), true);
			fos.write(cipher.getIV());
			fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Cifro il file in chiaro e lo salvo nel pacchetto
		try {
			addEncFileToPacket("message.txt", cipher);
		} catch (IOException e) {
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
		bw.write("* Al gruppo: " + rcvGroupName + System.getProperty("line.separator"));
		bw.write("* Nonce: " + Base64.getEncoder().encodeToString(nonce) + System.getProperty("line.separator"));
		bw.write("**********************************************");
		bw.close();
	}

	private static byte[] signPlainFile(String fileName, PrivateKey fooSSK)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		// Ottengo una istanza di Signature e la inizializzo con la Foo_SSK
		Signature sig = Signature.getInstance("SHA1withDSA");
		sig.initSign(fooSSK);

		// Prelevo i dati che devono essere firmati e li aggiorno con il metodo
		// update
		FileInputStream fis = new FileInputStream(new File(fileName));
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bis.read(buffer)) >= 0)
			sig.update(buffer, 0, len);
		bis.close();

		// Firmo i dati, ottenendo la signature
		byte[] signature = sig.sign();

		return signature;
	}

	private static void addEncAESKeyToPacket(SecretKey AESKey, PublicKey recvGroupEPK)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
		// Inizializzo il cifrario in modalità RSA con la recvGroupEPK
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, recvGroupEPK);

		// Salvo sul file la chiave AES generata in precedenza, cifrandola con
		// RSA
		FileOutputStream fos = new FileOutputStream(new File(groupName + "_to_" + rcvGroupName + ".txt.enc"), true);
		CipherOutputStream cos = new CipherOutputStream(fos, cipher);
		cos.write(AESKey.getEncoded());
		cos.close();
	}

	private static void addEncFileToPacket(String plainFileName, Cipher cipher) throws IOException {
		// Leggo il file in chiaro e lo cifro con AES/CBC/PKCS5Padding
		// scrivendolo sul file
		FileInputStream fis = new FileInputStream(new File(plainFileName));
		BufferedInputStream bis = new BufferedInputStream(fis);

		FileOutputStream fos = new FileOutputStream(new File(groupName + "_to_" + rcvGroupName + ".txt.enc"), true);
		CipherOutputStream cos = new CipherOutputStream(fos, cipher);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bis.read(buffer)) >= 0)
			cos.write(buffer, 0, len);
		bis.close();
		cos.close();
	}

}