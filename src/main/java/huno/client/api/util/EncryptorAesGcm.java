package huno.client.api.util;


import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class EncryptorAesGcm {
	private static final Logger  logger1 = LoggerFactory.getLogger(EncryptorAesGcm.class);
	private static final String ENCRYPT_ALGO = "AES/CBC/PKCS5Padding";
	 private static final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 16;
    private static final int AES_KEY_BIT = 128;
    private static final int LENGTH = 256;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final String ALGO = "AES";
    // AES-GCM needs GCMParameterSpec
    public static String encrypt(String Data, String secret) throws Exception {
    	
    	Key key = generateKey(secret);
    	Cipher c = Cipher.getInstance(ALGO);
    	c.init(Cipher.ENCRYPT_MODE, key);
    	byte[] encVal = c.doFinal(Data.getBytes());
    	String encryptedValue = Base64.getEncoder().encodeToString(encVal);
    	return encryptedValue;
    }
    
    public static String decryptCryptoJS(String cipherText, String secret) throws Exception {
    	byte[] cipherData = Base64.getDecoder().decode(cipherText);
    	byte[] saltData = Arrays.copyOfRange(cipherData, 8, 16);
    	MessageDigest md5 = MessageDigest.getInstance("MD5");
    	final byte[][] keyAndIV = GenerateKeyAndIV(32, 16, 1, saltData, secret.getBytes(StandardCharsets.UTF_8), md5);
    	SecretKeySpec key = new SecretKeySpec(keyAndIV[0], "AES");
    	IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);

    	byte[] encrypted = Arrays.copyOfRange(cipherData, 16, cipherData.length);
    	Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	aesCBC.init(Cipher.DECRYPT_MODE, key, iv);
    	byte[] decryptedData = aesCBC.doFinal(encrypted);
    	String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);
    	System.out.println(decryptedText);
    	return decryptedText;
    	
    }
    public static byte[][] GenerateKeyAndIV(int keyLength, int ivLength, int iterations, byte[] salt, byte[] password, MessageDigest md) {

        int digestLength = md.getDigestLength();
        int requiredLength = (keyLength + ivLength + digestLength - 1) / digestLength * digestLength;
        byte[] generatedData = new byte[requiredLength];
        int generatedLength = 0;

        try {
            md.reset();

            // Repeat process until sufficient data has been generated
            while (generatedLength < keyLength + ivLength) {

                // Digest data (last digest if available, password data, salt if available)
                if (generatedLength > 0)
                    md.update(generatedData, generatedLength - digestLength, digestLength);
                md.update(password);
                if (salt != null)
                    md.update(salt, 0, 8);
                md.digest(generatedData, generatedLength, digestLength);

                // additional rounds
                for (int i = 1; i < iterations; i++) {
                    md.update(generatedData, generatedLength, digestLength);
                    md.digest(generatedData, generatedLength, digestLength);
                }

                generatedLength += digestLength;
            }

            // Copy key and IV into separate byte arrays
            byte[][] result = new byte[2][];
            result[0] = Arrays.copyOfRange(generatedData, 0, keyLength);
            if (ivLength > 0)
                result[1] = Arrays.copyOfRange(generatedData, keyLength, keyLength + ivLength);

            return result;

        } catch (DigestException e) {
            throw new RuntimeException(e);

        } finally {
            // Clean out temporary data
            Arrays.fill(generatedData, (byte)0);
        }
    }
    public static String encryptCryptoJS(String content, String password) {
        try {
            Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            byte[] byteContent = content.getBytes("utf-8");
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(password));
            byte[] result = cipher.doFinal(byteContent);
            return Base64.getEncoder().encodeToString(result);
        } catch (Exception ex) {
            logger1.error("encrypt error", ex);
        }
        return null;
    }
    private static SecretKeySpec getSecretKey(final String password) {
        KeyGenerator kg = null;
        try {
            kg = KeyGenerator.getInstance(KEY_ALGORITHM);
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(password.getBytes());
            kg.init(LENGTH, random);
            SecretKey secretKey = kg.generateKey();
            return new SecretKeySpec(secretKey.getEncoded(), KEY_ALGORITHM);
        } catch (Exception ex) {
            logger1.error("error", ex);
        }
        return null;
    }
    private static Key generateKey(String secret) throws Exception {
    	byte[] decoded = Base64.getDecoder().decode(secret.getBytes());
    	Key key = new SecretKeySpec(decoded, ALGO);
    	return key;
    }
    public static byte[] encrypt(byte[] pText, SecretKey secret, String initVector) throws Exception {
    	IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret,iv);
        byte[] encryptedText = cipher.doFinal(pText);
        return encryptedText;
    }
   
    public static String AESEncryption(String plainText,String keyStr) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    	String encryptedStr="";
    	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	byte[] keybyte=keyStr.getBytes("UTF-8");
    	byte[] iv=Arrays.copyOf(keybyte, 16);
    	SecretKey key=new SecretKeySpec(keybyte,"AES");
    	cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(iv));
    	byte[] encryptedBytes=cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    	encryptedStr=Base64.getEncoder().encodeToString(encryptedBytes);
    	return encryptedStr;
    }
    
    public static String AESDecryption(String plainText,String keyStr) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    	String encryptedStr="";
    	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	byte[] keybyte=keyStr.getBytes("UTF-8");
    	byte[] iv=Arrays.copyOf(keybyte, 16);
    	SecretKey key=new SecretKeySpec(keybyte,"AES");
    	cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(iv));
    	byte[] encryptedBytes=cipher.doFinal(Base64.getDecoder().decode(plainText));
    	encryptedStr=new String(encryptedBytes, UTF_8) ;
    	return encryptedStr; 
    } 
    public static PrivateKey getPrivateKey(String cerPath) throws IOException, GeneralSecurityException 
    {
      PrivateKey key = null;
      FileInputStream fis = null;
      boolean isRSAKey = false;
      try {
          File f = new File(cerPath);
          fis = new FileInputStream(f);

          BufferedReader br = new BufferedReader(new InputStreamReader(fis));
          StringBuilder builder = new StringBuilder();
          boolean inKey = false;
          for (String line = br.readLine(); line != null; line = br.readLine()) {
              if (!inKey) {
                  if (line.startsWith("-----BEGIN ") && 
                          line.endsWith(" PRIVATE KEY-----")) {
                      inKey = true;
                      isRSAKey = line.contains("RSA");
                  }
                  continue;
              }
              else {
                  if (line.startsWith("-----END ") && 
                          line.endsWith(" PRIVATE KEY-----")) {
                      inKey = false;
                      isRSAKey = line.contains("RSA");
                      break;
                  }
                  builder.append(line);
              }
          }
          KeySpec keySpec = null;
          byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());          
          if (isRSAKey)
          {
            keySpec = getRSAKeySpec(encoded);
          }
          else
          {
            keySpec = new PKCS8EncodedKeySpec(encoded);
          }
          KeyFactory kf = KeyFactory.getInstance("RSA");
          key = kf.generatePrivate(keySpec);
      } finally {
        if (fis != null)
          try { fis.close(); } catch (Exception ign) {}  }
      return key;
    }
    
    public static String readFileAsString(String fileName)throws Exception 
    {
    	String data = ""; 
	    data = new String(Files.readAllBytes(Paths.get(fileName))); 
	    return data; 
    }
    
    public static RSAPrivateCrtKeySpec getRSAKeySpec(byte[] keyBytes) throws IOException  {

        DerParser parser = new DerParser(keyBytes);

        Asn1Object sequence = parser.read();
          if (sequence.getType() != DerParser.SEQUENCE)
            throw new IOException("Invalid DER: not a sequence"); //$NON-NLS-1$

          // Parse inside the sequence
          parser = sequence.getParser();

          parser.read(); // Skip version
          BigInteger modulus = parser.read().getInteger();
          BigInteger publicExp = parser.read().getInteger();
          BigInteger privateExp = parser.read().getInteger();
          BigInteger prime1 = parser.read().getInteger();
          BigInteger prime2 = parser.read().getInteger();
          BigInteger exp1 = parser.read().getInteger();
          BigInteger exp2 = parser.read().getInteger();
          BigInteger crtCoef = parser.read().getInteger();

          RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
              modulus, publicExp, privateExp, prime1, prime2,
              exp1, exp2, crtCoef);

          return keySpec;
    }  
}
class DerParser {

	  // Classes
	  public final static int UNIVERSAL = 0x00;
	  public final static int APPLICATION = 0x40;
	  public final static int CONTEXT = 0x80;
	  public final static int PRIVATE = 0xC0;

	  // Constructed Flag
	  public final static int CONSTRUCTED = 0x20;

	  // Tag and data types
	  public final static int ANY = 0x00;
	  public final static int BOOLEAN = 0x01;
	  public final static int INTEGER = 0x02;
	  public final static int BIT_STRING = 0x03;
	  public final static int OCTET_STRING = 0x04;
	  public final static int NULL = 0x05;
	  public final static int OBJECT_IDENTIFIER = 0x06;
	  public final static int REAL = 0x09;
	  public final static int ENUMERATED = 0x0a;
	  public final static int RELATIVE_OID = 0x0d;

	  public final static int SEQUENCE = 0x10;
	  public final static int SET = 0x11;

	  public final static int NUMERIC_STRING = 0x12;
	  public final static int PRINTABLE_STRING = 0x13;
	  public final static int T61_STRING = 0x14;
	  public final static int VIDEOTEX_STRING = 0x15;
	  public final static int IA5_STRING = 0x16;
	  public final static int GRAPHIC_STRING = 0x19;
	  public final static int ISO646_STRING = 0x1A;
	  public final static int GENERAL_STRING = 0x1B;

	  public final static int UTF8_STRING = 0x0C;
	  public final static int UNIVERSAL_STRING = 0x1C;
	  public final static int BMP_STRING = 0x1E;

	  public final static int UTC_TIME = 0x17;
	  public final static int GENERALIZED_TIME = 0x18;

	  protected InputStream in;

	  /**
	   * Create a new DER decoder from an input stream.
	   * 
	   * @param in
	   *            The DER encoded stream
	   */
	  public DerParser(InputStream in) throws IOException {
	    this.in = in;
	  }

	  /**
	   * Create a new DER decoder from a byte array.
	   * 
	   * @param The
	   *            encoded bytes
	   * @throws IOException 
	   */
	  public DerParser(byte[] bytes) throws IOException {
	    this(new ByteArrayInputStream(bytes));
	  }

	  /**
	   * Read next object. If it's constructed, the value holds
	   * encoded content and it should be parsed by a new
	   * parser from <code>Asn1Object.getParser</code>.
	   * 
	   * @return A object
	   * @throws IOException
	   */
	  public Asn1Object read() throws IOException {
	    int tag = in.read();

	    if (tag == -1)
	      throw new IOException("Invalid DER: stream too short, missing tag"); //$NON-NLS-1$

	    int length = getLength();

	    byte[] value = new byte[length];
	    int n = in.read(value);
	    if (n < length)
	      throw new IOException("Invalid DER: stream too short, missing value"); //$NON-NLS-1$

	    Asn1Object o = new Asn1Object(tag, length, value);

	    return o;
	  }

	  /**
	   * Decode the length of the field. Can only support length
	   * encoding up to 4 octets.
	   * 
	   * <p/>In BER/DER encoding, length can be encoded in 2 forms,
	   * <ul>
	   * <li>Short form. One octet. Bit 8 has value "0" and bits 7-1
	   * give the length.
	     * <li>Long form. Two to 127 octets (only 4 is supported here). 
	     * Bit 8 of first octet has value "1" and bits 7-1 give the 
	     * number of additional length octets. Second and following 
	     * octets give the length, base 256, most significant digit first.
	   * </ul>
	   * @return The length as integer
	   * @throws IOException
	   */
	  private int getLength() throws IOException {

	    int i = in.read();
	    if (i == -1)
	      throw new IOException("Invalid DER: length missing"); //$NON-NLS-1$

	    // A single byte short length
	    if ((i & ~0x7F) == 0)
	      return i;

	    int num = i & 0x7F;

	    // We can't handle length longer than 4 bytes
	    if ( i >= 0xFF || num > 4) 
	      throw new IOException("Invalid DER: length field too big (" //$NON-NLS-1$
	          + i + ")"); //$NON-NLS-1$

	    byte[] bytes = new byte[num];     
	    int n = in.read(bytes);
	    if (n < num)
	      throw new IOException("Invalid DER: length too short"); //$NON-NLS-1$

	    return new BigInteger(1, bytes).intValue();
	  }

	}

	class Asn1Object {

	  protected final int type;
	  protected final int length;
	  protected final byte[] value;
	  protected final int tag;
	  public Asn1Object(int tag, int length, byte[] value) {
	    this.tag = tag;
	    this.type = tag & 0x1F;
	    this.length = length;
	    this.value = value;
	  }

	  public int getType() {
	    return type;
	  }

	  public int getLength() {
	    return length;
	  }

	  public byte[] getValue() {
	    return value;
	  }

	  public boolean isConstructed() {
	    return  (tag & DerParser.CONSTRUCTED) == DerParser.CONSTRUCTED;
	  }

	  public DerParser getParser() throws IOException {
	    if (!isConstructed()) 
	      throw new IOException("Invalid DER: can't parse primitive entity"); //$NON-NLS-1$

	    return new DerParser(value);
	  }
	  public BigInteger getInteger() throws IOException {
	      if (type != DerParser.INTEGER)
	        throw new IOException("Invalid DER: object is not integer"); //$NON-NLS-1$

	      return new BigInteger(value);
	  }

	  public String getString() throws IOException {

	    String encoding;

	    switch (type) {

	    // Not all are Latin-1 but it's the closest thing
	    case DerParser.NUMERIC_STRING:
	    case DerParser.PRINTABLE_STRING:
	    case DerParser.VIDEOTEX_STRING:
	    case DerParser.IA5_STRING:
	    case DerParser.GRAPHIC_STRING:
	    case DerParser.ISO646_STRING:
	    case DerParser.GENERAL_STRING:
	      encoding = "ISO-8859-1"; //$NON-NLS-1$
	      break;

	    case DerParser.BMP_STRING:
	      encoding = "UTF-16BE"; //$NON-NLS-1$
	      break;

	    case DerParser.UTF8_STRING:
	      encoding = "UTF-8"; //$NON-NLS-1$
	      break;

	    case DerParser.UNIVERSAL_STRING:
	      throw new IOException("Invalid DER: can't handle UCS-4 string"); //$NON-NLS-1$

	    default:
	      throw new IOException("Invalid DER: object is not a string"); //$NON-NLS-1$
	    }

	    return new String(value, encoding);
	  }
	}