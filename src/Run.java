import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class Run {

	private static final String groupName = "I2X3";
	
	public static void main(String[] args) throws Exception {
		PrivateKeyRing pkr = PrivateKeyRing.getInstance();

		KeyPair keyPairRSA, keyPairDSA;
		KeyPairGenerator keyPairGenRSA = KeyPairGenerator.getInstance("RSA");
		keyPairGenRSA.initialize(1024);
		keyPairRSA = keyPairGenRSA.genKeyPair();

		KeyPairGenerator keyPairGenDSA = KeyPairGenerator.getInstance("DSA");
		keyPairGenDSA.initialize(1024);
		keyPairDSA = keyPairGenDSA.genKeyPair();

		// EPK = public encryption key
		pkr.setKey(groupName + "_EPK", keyPairRSA.getPublic(), "EPK");
		// ESK = private decryption key
		pkr.setKey(groupName + "_ESK", keyPairRSA.getPrivate(), "ESK");
		// SPK = public verification key
		pkr.setKey(groupName + "_SPK", keyPairDSA.getPublic(), "SPK");
		// SSK = private signing key
		pkr.setKey(groupName + "_SSK", keyPairDSA.getPrivate(), "SSK");
		
		System.out.println(pkr.getKey(groupName + "_EPK"));
	}

}
