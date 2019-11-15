/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package openpgp_key_x509;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

//import org.bouncycastle.util.encoders.Base64;

/**
 * 공개키(public key)와 개인키(private key) 생성
 * <pre>
 * 개발정보계서버에서 openssl로 생성, /home/weblogic/cert
 * pass 비밀번호 : wooribank123, 모든 단계에서 동일하게 입력할 것!!!!!
 * etc info 부가정보 : VN, Hanoni, Hanoi, WOORIBANK VIETNAM, WOORIBANK, WOORIBANK, parkys76@wooribank.com
 *
 * 1. private.key 생성
 *    openssl genrsa -des -out private.key 2048
 *
 * 2. wooribank.csr 생성
 *    openssl req -key private.key -out wooribank.csr -new -sha256
 *    부가정보 입력: VN, Hanoni, Hanoi, WOORIBANK VIETNAM, WOORIBANK, WOORIBANK, parkys76@wooribank.com
 *    
 *    openssl req -in wooribank.csr -noout -text
 *
 * 3. ca.key 생성
 *    openssl genrsa -des -out ca.key 2048
 *
 * 4. public key, 730=2년 유효기간
 *    openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -sha256
 *    부가정보 입력 : VN, Hanoni, Hanoi, WOORIBANK VIETNAM, WOORIBANK, WOORIBANK, parkys76@wooribank.com
 *    
 *    openssl x509 -text -in ca.crt
 *
 * 5. ca 서명, 730=2년 유효기간, 공개키, 나파스에 제공하는 공개키
 *    openssl x509 -req -CA ca.crt -CAkey ca.key -days 3650 -in wooribank.csr -out wooribank_public.cer -sha256 -CAcreateserial
 *
 * 6. private key to pem파일, 최종 개인키
 *    openssl rsa -in private.key -text > wooribank_private.pem
 *    
 * @author namnt
 */
public class PGPas {

	//Các ký tự xuống dòng \r \n
	private static char eol1 = (char) 13;

	private static char eol2 = (char) 10;

	public static String SYM_ALGORITHM = "AES";

	public static int SESSION_KEY_LENGTH = 128;

	/**
	 * @param args the command line arguments
	 */
	public static void main(String[] args) throws Exception {
		
		PKICrypt.generateKey();

		String oriFile = "./openpgp_key_x509/testpgp_sha256.txt";
		String encFile = oriFile + ".pgp";
		String outFile = oriFile.substring(0, oriFile.lastIndexOf(".")) + "_out"
				+ oriFile.substring(oriFile.lastIndexOf("."));
		
		//Load public key
		//PublicKey publicKey = PKICrypt.getPublickey("public01.cer");
		//PublicKey publicKey = PKICrypt.getPublickey("nap-public01.cer");	
		//PublicKey publicKey = PKICrypt.getPublickey("Napas_PGP_Certificate.cer");
		//PublicKey publicKey = PKICrypt.getPublickey("wooribank_public.cer");
		PublicKey publicKey = PKICrypt.getPublickey("wooribank_public_prod.cer");
		
		//Load private key
		//PrivateKey privateKey = PKICrypt.getPrivateKey("private01.pem", "hanoi12");
		//PrivateKey privateKey = PKICrypt.getPrivateKey("wooribank_private.pem", "wooribank123");
		PrivateKey privateKey = PKICrypt.getPrivateKey("wooribank_private_prod.pem", "wooribank123");

		PGPas.PGPencrypt(oriFile, encFile, publicKey);
		PGPas.PGPdecrypt(encFile, outFile, privateKey);
	}

	public static void PGPencrypt(String originalFile, String encryptedFile, PublicKey publicKey) throws Exception {

		System.out.println(new Date().toString() + ":  ----Begin encrypt----");
		//Sinh khóa phiên ngẫu nhiên sử dụng thuật toán AES-128-EBC
		SecretKey sessionKey = PGPas.generateSessionkey();

		Path path = Paths.get(originalFile);
		byte[] data = Files.readAllBytes(path);
		System.out.println(new Date().toString() + ": Read file successfully");

		//Mã hóa dữ liệu sử dụng khóa phiên đối xứng AES
		byte[] encData = symmetricEncrypt(data, sessionKey);
		System.out.println(new Date().toString() + ": Encrypt data successfully");

		//Mã hóa khóa phiên sử dụng thuật toán mã hóa bất đối xứng RSA với public key.
		byte[] sessionKeyByte = sessionKey.getEncoded();
		byte[] encSessionKey = PKICrypt.encrypt(sessionKeyByte, publicKey);
		System.out.println(new Date().toString() + ": Encrypt session key successfully");

		//Encode base64 khóa phiên và dữ liệu sau khi được mã hóa
		String base64EncData = Base64.encodeBase64String(encData);
		String base64EncSessionKey = Base64.encodeBase64String(encSessionKey).replaceAll("(?:\\r\\n|\\n\\r|\\n|\\r)",
				"");
		System.out.println(new Date().toString() + ": Encode base64 successfully");

		//Ghi ra file, khóa phiên và dữ liệu sau khi được mã hóa nằm trên 2 dòng
		BufferedWriter bw = new BufferedWriter(new FileWriter(encryptedFile));
		bw.write(base64EncSessionKey);
		//chèn thêm ký tự xuống dòng 
		bw.write(eol1);
		bw.write(eol2);
		bw.write(base64EncData);
		bw.flush();
		bw.close();
		System.out.println(new Date().toString() + ": Write encrypted file successfully");
	}

	public static void PGPdecrypt(String encryptedFile, String decryptedFile, PrivateKey privateKey) throws Exception {

		System.out.println(new Date().toString() + ":  ----Begin decrypt----");
		Path path = Paths.get(encryptedFile);
		byte[] allContent = Files.readAllBytes(path);
		System.out.println(new Date().toString() + ": Read file successfully");

		//Loại bỏ các ký tự xuống dòng vô nghĩa ở đầu file
		int i = 0, s = 0;
		while (((char) allContent[i] == eol1) || ((char) allContent[i] == eol2))
			i++;
		s = i;
		//Tìm đến ký tự xuống dòng để cắt chuỗi
		while ((eol1 != (char) allContent[i]) && (eol2 != (char) allContent[i]))
			i++;
		//Cắt lấy phần khóa phiên được mã hóa và encode
		byte[] base64EncSessionKey = Arrays.copyOfRange(allContent, s, i);
		//Loại bỏ các ký tự xuống dòng vô nghĩa ở giữa file
		while (((char) allContent[i] == eol1) || ((char) allContent[i] == eol2))
			i++;
		int len = allContent.length;
		//Loại bỏ các ký tự xuống dòng vô nghĩa ở cuối file
		while (((char) allContent[len - 1] == eol1) || ((char) allContent[len - 1] == eol2))
			len--;
		//Cắt lấy phần dữ liệu đã mã hóa và encode
		byte[] base64EncData = Arrays.copyOfRange(allContent, i, len);

		//Decode base64 khóa và dữ liệu
		byte[] encSessionKey = Base64.decodeBase64(base64EncSessionKey);
		byte[] decData = Base64.decodeBase64(base64EncData);
		System.out.println(new Date().toString() + ": Decode base64 successfully");
		//Giải mã khóa phiên sử dụng private key
		byte[] sessionKeyByte = PKICrypt.decrypt(encSessionKey, privateKey);
		SecretKey sessionKey = new SecretKeySpec(sessionKeyByte, PGPas.SYM_ALGORITHM);
		System.out.println(new Date().toString() + ": Decrypt session key successfully");
		//Giải mã dữ liệu sử dụng khóa phiên lấy được trong bước trước
		byte[] data = symmetricDecrypt(decData, sessionKey);
		System.out.println(new Date().toString() + ": Decrypt date successfully");
		//Ghi file
		path = Paths.get(decryptedFile);
		Files.write(path, data);
		System.out.println(new Date().toString() + ": Write data file successfully");

	}

	private static SecretKey generateSessionkey() {

		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance(SYM_ALGORITHM);
			keyGen.init(SESSION_KEY_LENGTH);
			return keyGen.generateKey();
		}
		catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(PGPas.class.getName()).log(Level.SEVERE, null, ex);
			return null;
		}
	}

	private static byte[] symmetricEncrypt(byte[] messageB, SecretKey key) throws Exception {

		//SecretKey key = new SecretKeySpec(keyBytes, "DESede");
		Cipher cipher = Cipher.getInstance(SYM_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] buf = cipher.doFinal(messageB);
		return buf;
	}

	private static byte[] symmetricDecrypt(byte[] encryptedTextB, SecretKey key) throws Exception {

		Cipher decipher = Cipher.getInstance(SYM_ALGORITHM);
		decipher.init(Cipher.DECRYPT_MODE, key);

		byte[] plainText = decipher.doFinal(encryptedTextB);
		return plainText;
	}

}
