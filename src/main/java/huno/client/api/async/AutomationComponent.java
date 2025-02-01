package huno.client.api.async;

import org.springframework.stereotype.Component;

import com.google.gson.JsonArray;

@Component("AutomationComponent")
public interface AutomationComponent {
	void callFieldUpdateAction(String tableName,String primaryKey,int rowid,JsonArray object_criteria,JsonArray object_fieldupdate);
	void callMailAlertAction(String tableName,String primaryKey,int rowid,JsonArray object_criteria,JsonArray object_mailalert);

}