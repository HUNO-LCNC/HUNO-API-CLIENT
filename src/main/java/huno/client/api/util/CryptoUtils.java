package huno.client.api.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CryptoUtils {
	
	public static byte[] getRandomNonce(int numBytes) {
	        byte[] nonce = new byte[numBytes];
	        new SecureRandom().nextBytes(nonce);
	        return nonce;
	    }
	 
	// AES secret key
    public static SecretKey getAESKey(int keysize) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keysize, SecureRandom.getInstanceStrong());
        return keyGen.generateKey();
    }
    public static String dynamicKeyGeneration() {
    	byte[] raw;
    	String aeskeybase64="";
    	try {
    		KeyGenerator keyGen=KeyGenerator.getInstance("AES");
    		SecureRandom rn=new SecureRandom();
    		keyGen.init(256, rn);
    		SecretKey secretKey=keyGen.generateKey();
    		raw=secretKey.getEncoded();
    		aeskeybase64=Base64.getEncoder().encodeToString(raw).substring(0,32);
    	}catch(Exception ex) {
    		ex.printStackTrace();
    		
    	}
    	return aeskeybase64;
    }
    
}

