package huno.client.api.Controller;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import huno.client.api.dao.BpmApiExecution;
import huno.client.api.util.EncryptorAesGcm;
import huno.client.api.util.GenrateJWTToken;

@RestController
public class UserAuthController {
private static final Logger  logger1 = LoggerFactory.getLogger(UserAuthController.class);
	private static final String  hashkey = "mustbe16byteskey";
	private static final int IV_LENGTH_BYTE = 16;
	private static final int AES_KEY_BIT = 256;
	
	@Value("${spring.aes.key}")
	 private String aesKey_enc ;
	
	@Autowired
	BpmApiExecution bpmapiExecution;
	
	@Autowired
	GenrateJWTToken genrateJWTToken;
	
	@Value("${spring.hds.privatekey}")
	private String hunoprivatekey;
	
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/genrateJwtToken", method = RequestMethod.POST)
	public ResponseEntity<String> genrateJwtToken(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
		try {
			HashMap<String, Object> bodyJson= new HashMap<>();
			logger1.info("+++++++++++++++++++++++++++++++++++++genrateJwtToken++++++++++++++++++++++++++++++++++++++++++++++++++++");
			
			//RSA Decription of AES-128 KEY
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			
			String username=decryptedJsonObject.get("username").getAsString();
			String userpassword=decryptedJsonObject.get("usercred").getAsString();
			String strQuery="select sy.varibale_name,user_password, usr.user_id, usr.user_fname,usr.user_mname,\r\n"
					+ "usr.user_lname,usr.user_emailid,usr.user_mobile,usr.user_pan \r\n"
					+ "from app_tbluser_vdv usr left join app_tblsystemenum sy on sy.id = usr.user_prifix \r\n"
					+ "where  usr.isactive=true and lower(usr.user_loginname)= lower('" + username.trim() + "')\r\n"
					+ "and ( usr.effective_to is null or DATE_PART('day',usr.effective_to- CURRENT_TIMESTAMP)>=0 ) and DATE_PART('day',CURRENT_TIMESTAMP-usr.effective_from) >=0\r\n";
			//logger1.info("loginNew Query/1.0==>"+strQuery);
			List<Map<String, Object>> resQueueData=bpmapiExecution.getQueryForRowList(strQuery);
			if(resQueueData.size()>0) {
				String tempPassword=resQueueData.get(0).get("user_password").toString();
				String decryptedUserCredential = EncryptorAesGcm.AESDecryption(tempPassword,aesKey_enc);
				if (userpassword == tempPassword || userpassword.toString().equals(decryptedUserCredential)) {
					String token=genrateJWTToken.generateToken(username);
					String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(token),aesKey_enc);
					Map<String, Object> resMap=new HashMap<>();
					resMap.putIfAbsent("response_code", "00");
					resMap.putIfAbsent("rows",encryptedResponse);
					return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
					
				}else {
			    	String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
					Map<String, Object> resMap=new HashMap<>();
					resMap.putIfAbsent("response_code", "01");
					resMap.putIfAbsent("message", "Invalid User or Password");
					resMap.putIfAbsent("rows",encryptedResponse);
					return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			    }
			}else {
				logger1.info("User Not Exist Exception!!");
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("message", "Invalid User or Password");
				resMap.putIfAbsent("rows",encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}
		}catch(Exception e) {
			String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(""),aesKey_enc);
			Map<String, Object> resMap=new HashMap<>();
			resMap.putIfAbsent("response_code", "01");
			resMap.putIfAbsent("message", e.getMessage());
			resMap.putIfAbsent("rows",encryptedResponse);
			return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
		}
	 }
	
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/loginNew", method = RequestMethod.POST)
	public ResponseEntity<String> loginNew(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
		try {
			HashMap<String, Object> bodyJson= new HashMap<>();
			logger1.info("+++++++++++++++++++++++++++++++++++++loginNew++++++++++++++++++++++++++++++++++++++++++++++++++++");
			logger1.info("v1/hds/loginNew"+payload);
			//JsonObject jsonObject = new com.google.gson.JsonParser().parse(payload).getAsJsonObject();
			logger1.info("==========================RSA Decription of AES-228 KEY"+aesKey);
			
			//RSA Decription of AES-128 KEY
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			
			//logger1.info("==========================RSA Decription of token"+token);
			
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			//String encryptedRequestData=jsonObject.get("REQUEST").getAsString();//"ehcDdeAK7F68nMc2BEjACkIkiTfCizUMynj9U+MQLwsEe/s9rQ==";
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			
			String username=decryptedJsonObject.get("username").getAsString();
			String userpassword=decryptedJsonObject.get("usercred").getAsString();
			
			String strQuery="select sy.varibale_name,user_password, usr.user_id, usr.user_fname,usr.user_mname,usr.user_lname,usr.user_emailid,usr.user_mobile,usr.user_pan from app_tbluser usr left join app_tblsystemenum sy on sy.id = usr.user_prifix where  usr.isactive=true and lower(usr.user_loginname)= lower('" + username + "')" + " and ( usr.effective_to is null or DATE_PART('day',usr.effective_to- CURRENT_TIMESTAMP)>=0 ) and DATE_PART('day',CURRENT_TIMESTAMP-usr.effective_from) >=0";
			logger1.info("loginNew Query/1.0==>"+strQuery);
			List<Map<String, Object>> resQueueData=bpmapiExecution.getQueryForRowList(strQuery);
			if(resQueueData.size()>0) {
				String SecreatKey = "abc";
				String tempPassword=resQueueData.get(0).get("user_password").toString();
				String tempUserid=resQueueData.get(0).get("user_id").toString();
				String decryptedUserCredential = EncryptorAesGcm.decryptCryptoJS(tempPassword,SecreatKey);
				if (userpassword == tempPassword || userpassword.toString().equals(decryptedUserCredential)) {
					String sqlRoleQuery="select updated_date, DATE_PART('day', CURRENT_TIMESTAMP-created_date) as d_diff,DATE_PART('hour', CURRENT_TIMESTAMP-created_date )as h_diff "
							+ " from app_authuser_session where user_id="+tempUserid+" order by id desc limit 1;"
							
							+"select app.userprofile_id,app.access_type,app.block_id,app.district_id,app.user_id,usr.user_fname,usr.user_mname,usr.user_lname,usr.user_emailid,usr.user_mobile,usr.user_pan,sy.varibale_name,usr.actor_type_id,app.role_id,role.role_name from app_tbluserprofile app\r\n"
							+ "left join app_tbluser usr on usr.user_id=app.user_id\r\n"
							+ "left join app_tblsystemenum sy on sy.id = usr.user_prifix\r\n"
							+ "left join app_tblrole role on role.role_id = app.role_id\r\n"
							+ "where usr.user_id="+tempUserid +" and app.isactive=true";
					
					List<List<Map<String, Object>>> resFinalData=bpmapiExecution.getQueryForRowNested(sqlRoleQuery);
					
					if(resFinalData.size()>0) {
						String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resFinalData),aesKey_enc);
						Map<String, Object> resMap=new HashMap<>();
						resMap.putIfAbsent("response_code", "00");
						resMap.putIfAbsent("rows", encryptedResponse);
						return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
					}else {
						String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resFinalData),aesKey_enc);
						Map<String, Object> resMap=new HashMap<>();
						resMap.putIfAbsent("response_code", "01");
						resMap.putIfAbsent("message", "User Not Exist !");
						resMap.putIfAbsent("rows", encryptedResponse);
						return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
					}
					
			    } else {
			    	String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
					Map<String, Object> resMap=new HashMap<>();
					resMap.putIfAbsent("response_code", "01");
					resMap.putIfAbsent("message", "Invalid User or Password");
					resMap.putIfAbsent("rows",encryptedResponse);
					return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			    }
			}else {
				logger1.info("User Not Exist Exception!!");
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("message", "Invalid User or Password");
				resMap.putIfAbsent("rows",encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}
		}catch(Exception e) {
			logger1.error("catch Exception"+e.getMessage());
			String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(""),aesKey_enc);
			Map<String, Object> resMap=new HashMap<>();
			resMap.putIfAbsent("response_code", "01");
			resMap.putIfAbsent("message", "Network Error...");
			resMap.putIfAbsent("rows",encryptedResponse);
			return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
		}
	 }
	
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/UserChangePassword", method = RequestMethod.POST)
	public ResponseEntity<String> UserChangePassword(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
		try {
			HashMap<String, Object> bodyJson= new HashMap<>();
			logger1.info("+++++++++++++++++++++++++++++++++++++UserChangePassword++++++++++++++++++++++++++++++++++++++++++++++++++++");
			logger1.info("v1/hds/UserChangePassword"+payload);
			//JsonObject jsonObject = new com.google.gson.JsonParser().parse(payload).getAsJsonObject();
			logger1.info("==========================RSA Decription of AES-228 KEY"+aesKey);
			
			//RSA Decription of AES-128 KEY
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			
			//logger1.info("==========================RSA Decription of token"+token);
			
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			//String encryptedRequestData=jsonObject.get("REQUEST").getAsString();//"ehcDdeAK7F68nMc2BEjACkIkiTfCizUMynj9U+MQLwsEe/s9rQ==";
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			
			String userid=decryptedJsonObject.get("userid").getAsString();
			String userpassword=decryptedJsonObject.get("usercred").getAsString();
			String old_password=decryptedJsonObject.get("old_password").getAsString();
			
			String strQuery="select user_password, user_id from app_tbluser where user_id="+userid+" limit 1";
			logger1.info("UserChangePassword Query/1.0==>"+strQuery);
			List<Map<String, Object>> resQueueData=bpmapiExecution.getQueryForRowList(strQuery);
			if(resQueueData.size()>0) {
				String SecreatKey = "abc";
				String tempPassword=resQueueData.get(0).get("user_password").toString();
				String decryptedUserCredential = EncryptorAesGcm.decryptCryptoJS(tempPassword,SecreatKey);
				if (old_password.equalsIgnoreCase(decryptedUserCredential)) {
					String sqlRoleQuery="update app_tbluser set user_password='"+userpassword+"' where user_id="+userid;
					
					Map<Integer, String> resFinalData=bpmapiExecution.excQueryInsertUpdate(sqlRoleQuery);
					
					if(resFinalData.size()>0) {
						String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resFinalData),aesKey_enc);
						Map<String, Object> resMap=new HashMap<>();
						resMap.putIfAbsent("response_code", "00");
						resMap.putIfAbsent("message", "Password Update Successful");
						resMap.putIfAbsent("rows", encryptedResponse);
						return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
					}else {
						String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resFinalData),aesKey_enc);
						Map<String, Object> resMap=new HashMap<>();
						resMap.putIfAbsent("response_code", "01");
						resMap.putIfAbsent("message", "User Not Exist !");
						resMap.putIfAbsent("rows", encryptedResponse);
						return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
					}
					
			    } else {
			    	String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
					Map<String, Object> resMap=new HashMap<>();
					resMap.putIfAbsent("response_code", "01");
					resMap.putIfAbsent("message", "Old Password Miss Matched");
					resMap.putIfAbsent("rows",encryptedResponse);
					return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			    }
			}else {
				logger1.info("User Not Exist Exception!!");
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("message", "Invalid User or Password");
				resMap.putIfAbsent("rows",encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}
		}catch(Exception e) {
			logger1.error("catch Exception"+e.getMessage());
			String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(""),aesKey_enc);
			Map<String, Object> resMap=new HashMap<>();
			resMap.putIfAbsent("response_code", "01");
			resMap.putIfAbsent("message", "Network Error...");
			resMap.putIfAbsent("rows",encryptedResponse);
			return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
		}
	 }
	
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/dcsloginNew", method = RequestMethod.POST)
	public ResponseEntity<String> dcsloginNew(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
		try {
			HashMap<String, Object> bodyJson= new HashMap<>();
			logger1.info("+++++++++++++++++++++++++++++++++++++dcsloginNew++++++++++++++++++++++++++++++++++++++++++++++++++++");
			logger1.info("v1/hds/dcsloginNew"+payload);
			//JsonObject jsonObject = new com.google.gson.JsonParser().parse(payload).getAsJsonObject();
			logger1.info("==========================RSA Decription of AES-228 KEY"+aesKey);
			
			//RSA Decription of AES-128 KEY
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			
			//logger1.info("==========================RSA Decription of token"+token);
			
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			//String encryptedRequestData=jsonObject.get("REQUEST").getAsString();//"ehcDdeAK7F68nMc2BEjACkIkiTfCizUMynj9U+MQLwsEe/s9rQ==";
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			
			String username=decryptedJsonObject.get("username").getAsString();
			String userpassword=decryptedJsonObject.get("usercred").getAsString();
			String referanceno=decryptedJsonObject.get("referanceno").getAsString();		
			
			
			String strQuery="select sy.varibale_name,user_password, usr.user_id, usr.user_fname,usr.user_mname,\r\n"
					+ "usr.user_lname,usr.user_emailid,usr.user_mobile,usr.user_pan \r\n"
					+ "from app_tbluser_vdv usr left join app_tblsystemenum sy on sy.id = usr.user_prifix \r\n"
					+ "where  usr.isactive=true and lower(usr.user_loginname)= lower('" + username.trim() + "')\r\n"
					+ "and ( usr.effective_to is null or DATE_PART('day',usr.effective_to- CURRENT_TIMESTAMP)>=0 ) and DATE_PART('day',CURRENT_TIMESTAMP-usr.effective_from) >=0\r\n and usr.isactive=true";
			logger1.info("dcsloginNew Query/1.0==>"+strQuery);
			List<Map<String, Object>> resQueueData=bpmapiExecution.getQueryForRowList(strQuery);
			if(resQueueData.size()>0) {
				
				String tempPassword=resQueueData.get(0).get("user_password").toString();
				String tempUserid=resQueueData.get(0).get("user_id").toString();
				
				String refrenceCheck="select * from z_entitydtl_manange_vdv_details_001 where user_id="+tempUserid+" and reference_no='"+referanceno+"' and isactive=true";
				List<Map<String, Object>> refrenceList=bpmapiExecution.getQueryForRowList(refrenceCheck);
				if(refrenceList.size()==0) {
					String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(refrenceList),aesKey_enc);
					Map<String, Object> resMap=new HashMap<>();
					resMap.putIfAbsent("response_code", "01");
					resMap.putIfAbsent("message", "Reference Number Not Allocated ! Please Contact Administrator");
					resMap.putIfAbsent("rows", encryptedResponse);
					return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
				}		
				
				
//				String decryptedUserCredential = EncryptorAesGcm.decryptCryptoJS(tempPassword,SecreatKey);
				String decryptedUserCredential = EncryptorAesGcm.AESDecryption(tempPassword,aesKey_enc);
				if (userpassword == tempPassword || userpassword.toString().equals(decryptedUserCredential)) {
					String sqlRoleQuery="select updated_date, DATE_PART('day', CURRENT_TIMESTAMP-created_date) as d_diff,DATE_PART('hour', CURRENT_TIMESTAMP-created_date )as h_diff "
							+ " from app_authuser_session where user_id="+tempUserid+" order by id desc limit 1;"
							
							+"select app.userprofile_id,app.user_id,usr.user_fname,usr.user_mname,usr.user_lname,usr.user_emailid,\r\n"
							+ "usr.user_mobile,usr.user_pan,sy.varibale_name,app.role_id,role.role_name,usr.vdv_type\r\n"
							+ ",dst.district_name,dst.district_id,blk.block_name,blk.block_id,CASE WHEN usr1.user_fname LIKE '%MSOM%' THEN 'MSOM'\r\n"
							+ "WHEN usr1.user_fname LIKE '%MOVCDNER%' THEN 'MOVCDNER'\r\n"
							+ "ELSE 'Other' END AS form_fill_type,"
							+ "blk.latitude as block_latitude,blk.longitude as block_longitude,dst.latitude as dst_latitude,dst.longitude as dst_longitude from app_tbluserprofile_vdv app\r\n"
							+ "left join app_tbluser_vdv usr on usr.user_id=app.user_id\r\n"
							+ "left join app_tblsystemenum sy on sy.id = usr.user_prifix\r\n"
							+ "left join app_tblrole role on role.role_id = app.role_id\r\n"
							+ "left join z_entitymast_district_001 dst on dst.district_id = app.district_id\r\n"
							+ "left join z_entitymast_block_001 blk on blk.block_id = app.block_id\r\n"
							+ "left join app_tbluserprofile app1 on app1.userprofile_id = app.reporting_user \r\n"
							+ "left join app_tbluser usr1 on usr1.user_id=app1.user_id \r\n"
							+ "where usr.user_id="+tempUserid +" and app.isactive=true";
					
					List<List<Map<String, Object>>> resFinalData=bpmapiExecution.getQueryForRowNested(sqlRoleQuery);
					
					if(resFinalData.get(1).size()>0) {
						String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resFinalData),aesKey_enc);
						Map<String, Object> resMap=new HashMap<>();
						resMap.putIfAbsent("response_code", "00");
						resMap.putIfAbsent("rows", encryptedResponse);
						return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
					}else {
						String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resFinalData),aesKey_enc);
						Map<String, Object> resMap=new HashMap<>();
						resMap.putIfAbsent("response_code", "01");
						resMap.putIfAbsent("message", "User Not Exist !");
						resMap.putIfAbsent("rows", encryptedResponse);
						return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
					}
					
			    } else {
			    	String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
					Map<String, Object> resMap=new HashMap<>();
					resMap.putIfAbsent("response_code", "01");
					resMap.putIfAbsent("message", "Invalid User or Password");
					resMap.putIfAbsent("rows",encryptedResponse);
					return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			    }
			}else {
				logger1.info("User Not Exist Exception!!");
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("message", "Invalid User or Password");
				resMap.putIfAbsent("rows",encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}
		}catch(Exception e) {
			logger1.error("catch Exception"+e.getMessage());
			String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(""),aesKey_enc);
			Map<String, Object> resMap=new HashMap<>();
			resMap.putIfAbsent("response_code", "01");
			resMap.putIfAbsent("message", "Network Error...");
			resMap.putIfAbsent("rows",encryptedResponse);
			return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
		}
	 }
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/bindMenu", method = RequestMethod.POST)
	public ResponseEntity<String> bindMenu(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, JsonProcessingException {
		try {

			HashMap<String, Object> bodyJson= new HashMap<>();
			logger1.info("+++++++++++++++++++++++++++++++++++++bindMenu++++++++++++++++++++++++++++++++++++++++++++++++++++");
			
			//RSA Decription of AES-128 KEY
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			
			String roleId=decryptedJsonObject.get("roleId").getAsString();
			//String organizationId=decryptedJsonObject.get("organizationId").getAsString();
			String actor_type_id= decryptedJsonObject.get("actor_type_id").isJsonNull()||decryptedJsonObject.get("actor_type_id")==null || decryptedJsonObject.get("actor_type_id").getAsString().equalsIgnoreCase("") ? "":decryptedJsonObject.get("actor_type_id").getAsString();
			String strQuery="select rdm.menu_id, am.menu_txt,mlm.view_id,mlm.page_id,mlm.is_default_dashboard,mlm.link_type,rdm.department_id,am.profile_name ,mlm.role_id,mlm.orders,\r\n"
					+ "fd.order_id,fd.form_id,fd.form_template,fd.is_custom_form, case when link_type ='F' then fd.form_link_name  else page.page_link_name end form_link,case when link_type ='F' then v.link_name  else page.page_link_name end form_link_name ,v.view_type,v.view_id,v.child_form_ids,v.is_attachment,fd.module_id,\r\n"
					+ "fd.is_table_required \r\n"
					+ "from z_entitymast_menu_role_department_mapping_001 rdm\r\n"
					+ "left join app_menu am on am.menu_id=rdm.menu_id \r\n"
					+ "left join app_menu_link_mapping mlm on am.menu_id=mlm.menu_id \r\n"
					+ "left join app_form_view_details v on mlm.view_id=v.view_id \r\n"
					+ "left join app_pages page on mlm.page_id=page.page_id  \r\n"
//					+ "left join app_forms fd on v.form_id=fd.form_id where rdm.role_id="+roleId+" and  rdm.actor_type_id="+actor_type_id;
					+ "left join app_forms fd on v.form_id=fd.form_id where rdm.role_id="+roleId;
			logger1.info("bindMenu Query/1.0==>"+strQuery);
			List<Map<String, Object>> resQueueData=bpmapiExecution.getQueryForRowList(strQuery);
			
			if(resQueueData.size()>0) {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "00");
				resMap.putIfAbsent("rows", encryptedResponse);	
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}else {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("message", "No Role Assign");
				resMap.putIfAbsent("rows",encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}
		}catch(Exception e) {
			String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(""),aesKey_enc);
			Map<String, Object> resMap=new HashMap<>();
			resMap.putIfAbsent("response_code", "01");
			resMap.putIfAbsent("message", e.getMessage());
			resMap.putIfAbsent("rows",encryptedResponse);
			return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
		}
	 }
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/checkIfAlreadyLogin", method = RequestMethod.POST)
	ResponseEntity<String>  checkIfAlreadyLogin(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey) throws Exception{
		try {				

            HashMap<String, Object> bodyJson= new HashMap<>();
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));		    	  
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			String user_name = decryptedJsonObject.get("user_name").getAsString();
			String strQuery="select aus.id from app_authuser_session aus\r\n"
					+ "left join app_tbluser at on at.user_id=aus.user_id\r\n"
					+ "where user_loginname ilike'"+user_name+"' and aus.is_login_session_active='true'";				
			logger1.info("checkIfAlreadyLogin/1.0==>"+strQuery);
			List<Map<String, Object>> resQueueData=bpmapiExecution.getQueryForRowList(strQuery);
			logger1.info("checkIfAlreadyLogin/1.0 resQueueData response==>"+resQueueData);	
			if(resQueueData !=null) {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "00");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}else {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}	
		}
		catch(Exception ex)
		{
			//ex.printStackTrace();
			logger1.error("Exception api/checkIfAlreadyLogin/1.0==>"+ex.getMessage());
			return ResponseEntity.badRequest().body("{\"status\": \"error\", \"errorcode\": \"400\",\"errormessage\":\""+ex.getMessage()+"\"}");
		}
	}
	
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/getAVAuthUserSession", method = RequestMethod.POST)
	ResponseEntity<String>  getBranchAuthUserSession(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey) throws Exception{
		try {
			 
            HashMap<String, Object> bodyJson= new HashMap<>();
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));		    	  
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			String user_name = decryptedJsonObject.get("user_name").getAsString();
			String query="select user_loginname,user_password,user_id from app_tbluser where user_loginname ilike '"+user_name+"'";
			List<Map<String, Object>> resQueueData1=bpmapiExecution.getQueryForRowList(query);
			if(resQueueData1.size()>0) {
			String strQuery="select aus.* ,TO_CHAR(aus.created_date, 'YYYY-MM-DD HH12:MM') as \"created_date\" , aus.user_id   \r\n"
					+ "from APP_AUTHUSER_SESSION aus\r\n"
					+ "where aus.user_name ='"+user_name+ "' order by id desc FETCH FIRST 1 ROWS ONLY";
			
			logger1.info("getAVAuthUserSession/1.0==>"+strQuery);
			List<Map<String, Object>> resQueueData=bpmapiExecution.getQueryForRowList(strQuery);
			//System.out.println("getAVAuthUserSession/1.0 resQueueData response==>"+resQueueData);
			
			if(resQueueData.size()>0) {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "00");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}else {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("message", "Record Not Found");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			 }	
			}else {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData1),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("rows" ,encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}
		}
		catch(Exception ex)
		{
			//ex.printStackTrace();
			logger1.error("Exception api/getAVAuthUserSession/1.0==>"+ex.getMessage());
			return ResponseEntity.badRequest().body("{\"status\": \"error\", \"errorcode\": \"400\",\"errormessage\":\""+ex.getMessage()+"\"}");
		}
	}
	
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/updateAuthUserSessionById", method = RequestMethod.POST)
	ResponseEntity<String>  updateAuthUserSessionById(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey) throws Exception{
		try {
			 
            HashMap<String, Object> bodyJson= new HashMap<>();
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));		    	  
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			String user_id = decryptedJsonObject.get("user_id").getAsString();
			String ip_address = decryptedJsonObject.get("ip_address").getAsString().equalsIgnoreCase("") ? null : "'"+decryptedJsonObject.get("ip_address").getAsString()+"'";
			String strQuery="update app_authuser_session  set logout_ip_address="+ip_address+",updated_date=NOW(),is_login_session_active=false where id in("+user_id+")";				
			logger1.info("updateAuthUserSessionById/1.0==>"+strQuery);
			Map<Integer, String> resQueueData=bpmapiExecution.excQueryInsertUpdate(strQuery);
			logger1.info("updateAuthUserSessionById/1.0 resQueueData response==>"+resQueueData);	
			if(resQueueData !=null) {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "00");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}else {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}	
		}
		catch(Exception ex)
		{
			//ex.printStackTrace();
			logger1.error("Exception api/updateAuthUserSessionById/1.0==>"+ex.getMessage());
			return ResponseEntity.badRequest().body("{\"status\": \"error\", \"errorcode\": \"400\",\"errormessage\":\""+ex.getMessage()+"\"}");
		}
	}
	
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/saveAVAuthUserSession", method = RequestMethod.POST)
	ResponseEntity<String>  saveAuthUserSession(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey) throws Exception{
		try {
			//RSA Decription of AES-128 KEY
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			String userid = decryptedJsonObject.get("userid").getAsString();
			String user_name = decryptedJsonObject.get("user_name").getAsString();
			String ipaddress = decryptedJsonObject.get("ipaddress").getAsString().equalsIgnoreCase("")? null:decryptedJsonObject.get("ipaddress").getAsString();
			String login_uuid = decryptedJsonObject.get("login_uuid").getAsString();
			String strQuery ="insert into APP_AUTHUSER_SESSION (USER_ID,USER_NAME ,IP_ADDRESS,is_login_session_active,login_uuid) values('"+userid+"','"+user_name+"' ,'"+ipaddress+"',true,'"+login_uuid+"')";
			
			logger1.info("saveAVAuthUserSession/1.0==>"+strQuery);
			Map<Integer,String> resQueueData=bpmapiExecution.excQueryInsertUpdate(strQuery);
			//List<Map<String, Object>> resQueueData=bpmapiExecution.getQueryForRowList(strQuery);
			logger1.info("saveAVAuthUserSession/1.0 resQueueData response==>"+resQueueData);	
			if(resQueueData.size() >0) {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "00");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));	
			}else {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("message", "Record Not Found");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));	
			}	
		}
		catch(Exception ex)
		{
			//ex.printStackTrace();
			logger1.error("Exception api/saveAVAuthUserSession/1.0==>"+ex.getMessage());
			return ResponseEntity.badRequest().body("{\"status\": \"error\", \"errorcode\": \"400\",\"errormessage\":\""+ex.getMessage()+"\"}");
		}
	}
	
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/getAuthUserByUuId", method = RequestMethod.POST)
	ResponseEntity<String>  getAuthUserByUuId(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey,@RequestHeader("Authorization") String authorizationHeaderValue) throws Exception{
		try {
            HashMap<String, Object> bodyJson= new HashMap<>();
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));		    	  
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			String user_id = decryptedJsonObject.get("user_id").getAsString();
			String login_uuid = decryptedJsonObject.get("login_uuid").getAsString();
			String strQuery="select aus.id from app_authuser_session aus where aus.user_name='"+user_id+"' and login_uuid='"+login_uuid+"'";				
			logger1.info("getAuthUserByUuId/1.0==>"+strQuery);
			List<Map<String, Object>> resQueueData=bpmapiExecution.getQueryForRowList(strQuery);
			logger1.info("getAuthUserByUuId/1.0 resQueueData response==>"+resQueueData);	
			if(resQueueData !=null) {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "00");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}else {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}	
		}
		catch(Exception ex)
		{
			//ex.printStackTrace();
			logger1.error("Exception api/getAuthUserByUuId/1.0==>"+ex.getMessage());
			return ResponseEntity.badRequest().body("{\"status\": \"error\", \"errorcode\": \"400\",\"errormessage\":\""+ex.getMessage()+"\"}");
		}
	}
	
	
	@CrossOrigin(origins = "*", allowedHeaders = "*")
	@RequestMapping(value = "api/v1/hdsbpm/logOutAvById", method = RequestMethod.POST)
	ResponseEntity<String>  logOutAvById(@RequestBody String payload,@RequestHeader(value="AccessToken") String aesKey,@RequestHeader("Authorization") String authorizationHeaderValue) throws Exception{
		try {

            HashMap<String, Object> bodyJson= new HashMap<>();
			byte[] aesKeydata=Base64.getDecoder().decode(aesKey.getBytes(StandardCharsets.UTF_8));		    	  
			PrivateKey privateKey =EncryptorAesGcm.getPrivateKey(hunoprivatekey);
			logger1.info("==========================RSA PrivateKey "+privateKey);
			Cipher oaepFromInit = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			oaepFromInit.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] pt = oaepFromInit.doFinal(aesKeydata);
			String aeskeyStr =new String(pt);
			logger1.info("==========================RSA Decription of AES-228 KEY aeskeyStr"+aeskeyStr);
			
			//Decript JSON DATA AES/GCM/NoPadding
			logger1.info("==========================Decript JSON DATA RSA/ECB/PKCS1Padding");
			String decryptedRequestData = EncryptorAesGcm.AESDecryption(payload,aeskeyStr);
			logger1.info("decryptedText===================="+decryptedRequestData);
			
			JsonObject decryptedJsonObject = new com.google.gson.JsonParser().parse(decryptedRequestData).getAsJsonObject();
			String id = decryptedJsonObject.get("id").getAsString();
			String strQuery="update app_authuser_session set is_login_session_active=false where id="+id;				
			logger1.info("logOutAvById/1.0==>"+strQuery);
			Map<Integer, String> resQueueData=bpmapiExecution.excQueryInsertUpdate(strQuery);
			logger1.info("logOutAvById/1.0 resQueueData response==>"+resQueueData);	
			if(resQueueData !=null) {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "00");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}else {
				String encryptedResponse = EncryptorAesGcm.AESEncryption(new ObjectMapper().writeValueAsString(resQueueData),aesKey_enc);
				Map<String, Object> resMap=new HashMap<>();
				resMap.putIfAbsent("response_code", "01");
				resMap.putIfAbsent("message", "Failed To Updated");
				resMap.putIfAbsent("rows", encryptedResponse);
				return ResponseEntity.status(HttpStatus.OK).body(new ObjectMapper().writeValueAsString(resMap));
			}	
		}
		catch(Exception ex)
		{
			//ex.printStackTrace();
			logger1.error("Exception api/logOutAvById/1.0==>"+ex.getMessage());
			return ResponseEntity.badRequest().body("{\"status\": \"error\", \"errorcode\": \"400\",\"errormessage\":\""+ex.getMessage()+"\"}");
		}
	}

}
