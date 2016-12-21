import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RunGenPKR {

	public static void main(String[] args) {
		// Ottengo l'istanza del PublicKeyRing
		PublicKeyRing pkr = PublicKeyRing.getInstance();

		try {
			// Gruppo Ancora
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] encodedKey = Base64.getDecoder().decode(
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC87UbZBsXHzim7q/b0nndJpabIHJy21kFu3KHwYoNGUSYO8FO3a4mBQJ7itDh6K/IoQS2DTp5NNyEr+0uRzE1RuTbWHpY24U/dRhkvju2KnZPFA64tdr1s6d07t3LHaMPApY1Rn5YOl0myS/aJRDCxRUiF6TL8C92GTf9nxSfUpwIDAQAB");
			PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("Ancora_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			keyFactory = KeyFactory.getInstance("DSA");
			encodedKey = Base64.getDecoder().decode(
					"MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAGDCs+acIrdVF/aBdADLb6rOHDyAs3/WFTuk8Bx7KY5PQhAgl+6cazxkwqZHM1DJR23pFCFEkj23+V3fUufCTPj++d9NFYMNEuv82ZoBMML2uvlQb4lCNK+WpPez5d6jOkfe7P4aHJjAmIH9JBEs4Gi0NHdfbut6MQ+Wfw8pEzVs=");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("Ancora_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			// Gruppo Linneo
			keyFactory = KeyFactory.getInstance("RSA");
			encodedKey = Base64.getDecoder().decode(
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbEoRGFuU3gw/1KYbgA05jANDgarKagEWlJblKnZ3AXlC00GetN9Evo6G4bo3z+r2eSlUaqFFJjTmiZgzb2fGHVFXoy9FyULV+HcOsWE6bJs/chYJ8hf78SxxCpqfBs9lj/vju2XoqTtizlDIx6ofuWq3LS58yDmLBNj2QWuVszQIDAQAB");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("Linneo_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			keyFactory = KeyFactory.getInstance("DSA");
			encodedKey = Base64.getDecoder().decode(
					"MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBANt+1c3mtZRGRP9xztdTKBZQhCGnsLbTIda4uAwKmstFOx53YsrQjG0c0kezdiH+NR3ER2y318pMUyRfEzCeS7rVQ2Pf6MOBbpqOHE9gaCDB4J0mLHVG2sQnjA+p7+smwtclsVEqJljq2/zW3E22Zf7lWLJatLbxp9UJDpgXEnt6");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("Linneo_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			// Gruppo Doriana
			keyFactory = KeyFactory.getInstance("RSA");
			encodedKey = Base64.getDecoder().decode(
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCKLSv1g+DJoaXlwnRMngt+Q9I4SRutTjrbY7JhSXNV2JcBWR9/cKbhrivbOoqVWQnfUjkRPJLZQfORoGI1YmNXrspxVQ7v75ZLn6lWjWd4QklzaayVW74RgN1HRnyU66iPikCTXMT9FkvIg+wh4IHX4afavQjg1dl6BIXnhUYoYQIDAQAB");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("Doriana_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			keyFactory = KeyFactory.getInstance("DSA");
			encodedKey = Base64.getDecoder().decode(
					"MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAHqFhTzkF8cV7D33wPwqBbYvhj72NG8yz3LMGVhNlQndliOavVMJiXG6K2wTjpOISES3ry7Ck+AkmWwhLoP0BST2+s+uxJM25wBly63DWKQ+LgJejNocL3BVnTtPtchPgCzVc43tYvrCt3+9NwFNlw9OUH+VuDTXKi0FCXVNHfvo=");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("Doriana_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			// Gruppo IPini
			keyFactory = KeyFactory.getInstance("RSA");
			encodedKey = Base64.getDecoder().decode(
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeQao+8CdgVOE54RaLAp4aO+cJsz+0i72wWS8RL7jrTPl9RUzh+eFC3KuvP7TWUadnmxQD+oLQGQUkmwlzX0b4L6e3a8lJWG+dqUvF5FkU7iMBFoPx0d1yw9GIj3FYXJw0HPGYu6PNfu7oZtwELS+06Rxc9BqKodXGVAq7VZ2YnQIDAQAB");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("IPini_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			keyFactory = KeyFactory.getInstance("DSA");
			encodedKey = Base64.getDecoder().decode(
					"MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBAIFmjUq0noM3N6TkGlP6fjZQHkMPRWiVUkm1TIldkMQiEQCn1sMv1nQ+mD+B9kszQHikaTLzgWg7dVjRMJbELZ/H2wep+K6i9Z9B71gZ+DWw88DYZ3s1MyY6E1sznujoB5ojxRdHjMdEvS/UEW7M+Iq8UKk0kh1M3F4YD+KI/GrB");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("IPini_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			// Gruppo MakeNao
			keyFactory = KeyFactory.getInstance("RSA");
			encodedKey = Base64.getDecoder().decode(
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7PqwXag83JgyvdXaTqexBSwnsY2R3iJhBCwXnwX2xb6zj16Kr5eBSECztWk81SLjqrazzgcC6+MJUz4feT4b5moCjxWttxrZd9pI8VwKEQtC/Wke1vjQS3XQ5Ytiriy6Y40d0Z0xoeUyj+v1BWIvoBW5PCFfETzFTxC7DuO4lbQIDAQAB");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("MakeNao_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			keyFactory = KeyFactory.getInstance("DSA");
			encodedKey = Base64.getDecoder().decode(
					"MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBAIP0Oaq1vcjLrREooOmYcA6nMMmaSnbxmGrspBFrwGPqmVwu4VdRKBnc5l6LiCiSn8fg2UYGREzNln2wPz8LZCKeq8BfMjp73zJz9QqgPQZ65N2HWw+QjbA2kLj96GAaNSnSkgWt9150lAqnJ71HC3v2/MXZC1/O47EpGchT2lOm");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("MakeNao_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			// Gruppo LupiLupi
			keyFactory = KeyFactory.getInstance("RSA");
			encodedKey = Base64.getDecoder().decode(
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCKYq0ub5qYjqqUoE39CVQArDa043B0U/ynHwOFQOPppKlT9tOBAa2K4i8cIRwvlass9oyP1hjB+rWtpyJtyUF3uwkFQtwnHXiGZFmRZ8/OGW/K+vGPhuVFfC6WPQJ/3QiubjLyNG+n3zsaDe04ThDyYBrk1qjb1AOWKGBxASp8ywIDAQAB");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("LupiLupi_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			keyFactory = KeyFactory.getInstance("DSA");
			encodedKey = Base64.getDecoder().decode(
					"MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBAL9JGHJ0Ne2QYO0HVW6t1lEvJVpVdQlylr8T8bS8I1sYzJBie0LQZfAwMRte0EtwwY3ZNLZVxxU166RmZBVn7EGAKqiOWW8GEa0H41yehXBVHQwlHmxP2N0BPf+PN5WZgedVW6tvpkHgXXsf51A9TDghkETfzAmT5zGPZCcrIXfz");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("LupiLupi_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			// Gruppo GalloSalvato
			keyFactory = KeyFactory.getInstance("RSA");
			encodedKey = Base64.getDecoder().decode(
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXSZ+H1Z2Z90Jyjb8r+8dmHQUF9Ac78Z8Eqx4OPk9wjW3F38FMqpUuzaivMm8nt2FlQANdQQ6aa6pv4lkyC1/7lsFzo9olsQTLe/LFqpi0rdTSkQWfSdWsfCNUB5fzLuQqUTcALgHxMwaadOIapi8isiauz6wI3eRSMpMmqB7EmwIDAQAB");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("GalloSalvato_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			keyFactory = KeyFactory.getInstance("DSA");
			encodedKey = Base64.getDecoder().decode(
					"MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAQt4jRJfROWmLDzoa8VRK+r7Xj59tpIi0d1a1fWAO+G51rCo5I8LELCYyoHalXK7mWC82Kub6bN4uHJ3Z11x0MTrbkEGzg8CJ7QBCpVJls7NoyPHOPQ9KoTgNho7rLbwGBMLd3LaoVFgZm4SO511A+CuN4PLOZ+QKMUJ+g7kAocg=");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("GalloSalvato_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());
			
			// Gruppo FrankAbba
			keyFactory = KeyFactory.getInstance("RSA");
			encodedKey = Base64.getDecoder().decode(
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCq5cN5gs7ym6fJg0B6aqIV6KXwWdkJ6FdUcscTev44CXxfVahGDv/0JsPOQBmDdDBae+V9Qzd2GmAsMJvM/09ZAMWl4Y6QuIwl1z492zcpv89iifYenSOpoaJm4WNFaK0YZzUcoikKWC4JgjrW4NPPcK2c/IkzJ6BqvjlIz79GwIDAQAB");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("FrankAbba_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			keyFactory = KeyFactory.getInstance("DSA");
			encodedKey = Base64.getDecoder().decode(
					"MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBANZILOTmWFDES/5xLt8Uw90BZZvNtWAjT9dxEydHthpVZeTqhPJAEsRq7xs2gdKj/Xs2KKhUR62U8DknbA84Of6Bu06E4kUo+m0OdgbDbtxhFHWMQNaGk2+Wndwi6K7IA0nJ/aVAB9vII50wuSZ8IIkC5yrVgkz0j8rGQMY3SbNR");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("FrankAbba_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());
			
			// Gruppo GAS
			keyFactory = KeyFactory.getInstance("RSA");
			encodedKey = Base64.getDecoder().decode(
					"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCECiOKl+CZkkM9YxZhwEMbLBalgxhwS6ksLSWt/6GTEaXvy3rYd1rti4dFb3oqLNXHMeXgwavfQrPpvqDRgW5vkn1PB4VhTmD7pfApE2RWJS2gZz4GlDImciAVtKMwH/NrJ/fzXb7+nN/VsH/b0ZGhwi985WF8PtpukAqS1oTSPwIDAQAB");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("GAS_EPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());

			keyFactory = KeyFactory.getInstance("DSA");
			encodedKey = Base64.getDecoder().decode(
					"MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGADw+C8jOMuJJVhZIeUjRCFy+rPJMqOTVkyJloINktSK1nhCIYET1+vOSMV8OG3/QL7Ms1f/OmYWrK+KZ0hlegv5os2RMC6uqHyfB++Gigwf6Xc1+7NcO9BK7TZMTJ22BS7kNwve4HMyDCB8QB9SdPYoNV8tJ3IgBXG/yR5sOvQuA=");
			publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
			pkr.setKey("GAS_SPK", publicKey, publicKey.getAlgorithm() + "/" + publicKey.getFormat());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}

		// Salvo sul disco il KeyRing pubblico
		try {
			pkr.store(new FileOutputStream(new File("publicKeyRing.bin")));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
