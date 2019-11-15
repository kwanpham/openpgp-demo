package openpgp_key_x509;

import java.security.PrivateKey;
import java.security.PublicKey;

public class TestPGP {
	
	static String publicKeyUrl = "openpgp_key_x509/nhbank_public.cer";
	static String privateKeyUrl = "openpgp_key_x509/nhbank_private.pem";
	static String password = "123456";
	
	public static void main(String[] args) {
		String filePath = "openpgp_key_x509/testpgp_sha256.txt";
		String decFIle = "openpgp_key_x509/dec.txt";
		String encPath =  filePath + ".pgp";
		PublicKey publicKey = PKICrypt.getPublickey(publicKeyUrl);
		PrivateKey privateKey = PKICrypt.getPrivateKey(privateKeyUrl , "123456");
		// execute only SL file
		try {
			PGPas.PGPencrypt(filePath, encPath, publicKey);			
			PGPas.PGPdecrypt(encPath , decFIle , privateKey);
		} catch (Exception e) {
			System.out.println("Error: " + e.toString());
		}	
	}

}
