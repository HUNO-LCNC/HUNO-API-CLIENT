package huno.client.api.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BatchPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementCreator;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Component;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;


@Component
public class BpmApiExecution {
	private static final Logger logger = LoggerFactory.getLogger(BpmApiExecution.class);
	@Autowired
	private JdbcTemplate jdbcTemplate;
	
	@Autowired
	private  DataSource dataSource;
	
	
	
	public List<Map<String, Object>> getQueryForRowList(String strQuery)
	{
		List<Map<String, Object>> rowData=null;
		try{
			rowData = jdbcTemplate.queryForList(strQuery);
		}
		catch(Exception ex){
			logger.error(ex.getMessage());
			ex.printStackTrace();
		}
		return rowData;
	}
	public Map<Integer, String> excQueryInsertUpdate(String strQuery)
	{
		Map<Integer, String> rowDataNested=null;
		int status=0;
		String[] arrStrQuery= strQuery.split(";");
		try{
			 rowDataNested= new HashMap<>()  ;
			for(int i=0;i<arrStrQuery.length;i++) {
				 status = jdbcTemplate.update(arrStrQuery[i]);
				rowDataNested.putIfAbsent(i,String.valueOf(status));
			}
		}
		catch(Exception ex){
			logger.error(ex.getMessage());
			ex.printStackTrace();
		}
		return rowDataNested;
	}
	public Map<Integer, String> excQueryInsertUpdateBtch(Map<String, Object> strQueryMap)
	{
		Map<Integer, String> rowDataNested=null;
		int status=0;
		try{
			for(int j=1;j<=strQueryMap.size();j++) {
				String[] arrStrQuery= strQueryMap.get(""+j).toString().split(";");				
					 rowDataNested= new HashMap<>()  ;
					for(int i=0;i<arrStrQuery.length;i++) {
						 status = jdbcTemplate.update(arrStrQuery[i]);
						rowDataNested.putIfAbsent(i,String.valueOf(status));
					}				
			}
		}
		catch(Exception ex){
			logger.error(ex.getMessage());
			ex.printStackTrace();
		}
		return rowDataNested;
	}
	public Map<Integer, String> excQueryInsertUpdateBatch(Map<String, Object> strQuery)
	{
		Map<Integer, String> rowDataNested=null;
		int[] status;
		try{
			 rowDataNested= new HashMap<>()  ;
			for(int i=1;i<=strQuery.size();i++) {
				status = new SimpleJdbcCall(dataSource).getJdbcTemplate().batchUpdate(strQuery.get(""+i).toString());
				rowDataNested.putIfAbsent(0,String.valueOf(status));
			}
		}
		catch(Exception ex){
			logger.error(ex.getMessage());
			ex.printStackTrace();
		}
		return rowDataNested;
	}
	
	public int excQueryInsertPS(String strQuery,String strPk)
	{
		int newUserId=0;
			KeyHolder holder = new GeneratedKeyHolder();
			jdbcTemplate.update(
				    new PreparedStatementCreator() {
				        public PreparedStatement createPreparedStatement(Connection connection) throws SQLException {
				            PreparedStatement ps =
				                connection.prepareStatement(strQuery, new String[] {strPk});
				            return ps;
				        }
				    },
				    holder);
			newUserId = holder.getKey().intValue();	
		return newUserId;
	}
	
	public List<List<Map<String, Object>>> getQueryForRowNested(String strQuery)
	{
		List<List<Map<String, Object>>> rowDataNested=null;
		List<Map<String, Object>> rowData=null;
		String[] arrStrQuery= strQuery.split(";");
		try{
			 rowDataNested= new ArrayList<List<Map<String, Object>>>();
			for(int i=0;i<arrStrQuery.length;i++) {
				rowData = jdbcTemplate.queryForList(arrStrQuery[i]);
				rowDataNested.add(rowData);
			}
		}
		catch(Exception ex){
			logger.error(ex.getMessage());
			ex.printStackTrace();
		}
		return rowDataNested;
	}
	public Map<String, Object> getQueryForRow(String strQuery)
	{
		Map<String, Object> rowData=null;
		try{
			rowData = jdbcTemplate.queryForMap(strQuery);
		}
		catch(Exception ex){
			logger.error(ex.getMessage());
			ex.printStackTrace();
		}
		return rowData;
	}
	
	public Object callStoreProcedure(JsonArray argList,String sp_name) {
		try{
			SimpleJdbcCall jdbcCall = new SimpleJdbcCall(dataSource).withProcedureName(sp_name);
			MapSqlParameterSource params = new MapSqlParameterSource();
			for(int i=0;i<argList.size();i++) {
				JsonObject argObject=argList.get(i).getAsJsonObject(); 
				if(argObject.get("datatype").getAsString().trim().equalsIgnoreCase("integer")){
					params.addValue(argObject.get("id").getAsString(),argObject.get("value").getAsInt());	  
				}else if(argObject.get("datatype").getAsString().trim().equalsIgnoreCase("Character") || argObject.get("datatype").getAsString().trim().equalsIgnoreCase("Date")){
					params.addValue(argObject.get("id").getAsString(),argObject.get("value").getAsString());	  
				}else if(argObject.get("datatype").getAsString().trim().equalsIgnoreCase("Boolean")){
					params.addValue(argObject.get("id").getAsString(),argObject.get("value").getAsBoolean());	  
				}else if(argObject.get("datatype").getAsString().trim().equalsIgnoreCase("Double")){
					params.addValue(argObject.get("id").getAsString(),argObject.get("value").getAsDouble());	  
				}
			}
			return jdbcCall.execute(params);
		}
		catch(Exception ex){
			logger.error(ex.getMessage());
			ex.printStackTrace();
			return null;
		}
	}
	
	public int[] batchUpdateFormAttachmentRecordId(List<Map<String,Object>> attachmentRecordId) {
		return jdbcTemplate.batchUpdate(
				"update app_form_attachemnts set record_id = ? where id = ?",
				new BatchPreparedStatementSetter() {
					public void setValues(PreparedStatement ps, int i)
					throws SQLException {
						ps.setInt(1,Integer.parseInt(attachmentRecordId.get(i).get("record_id").toString()));
						ps.setInt(2, Integer.parseInt(attachmentRecordId.get(i).get("id").toString()));
					}
					public int getBatchSize() {
                        return attachmentRecordId.size();
                    }
                });
    }

}
