package huno.client.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

@SpringBootApplication
public class HunoClientApiApplication extends SpringBootServletInitializer implements EnvironmentAware {

	
	private Environment environment;
	
	public static void main(String[] args) {
		SpringApplication.run(HunoClientApiApplication.class, args);
	}
	
	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		System.out.println("==============Spring initializer called=========");
		return application.sources(HunoClientApiApplication.class);
	}
	@Override
	public void setEnvironment(Environment environment) {
		// TODO Auto-generated method stub
		this.environment = environment;
		
		
		
	System.out.print("hi srikant patel");
	}

}