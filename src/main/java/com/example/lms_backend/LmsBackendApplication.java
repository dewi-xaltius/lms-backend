package com.example.lms_backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.cdimascio.dotenv.Dotenv; // Importing dotenv for environment variable management

@SpringBootApplication
public class LmsBackendApplication {

	public static void main(String[] args) {
		 // Load the .env file 
     	Dotenv dotenv = Dotenv.configure().load(); 
     	dotenv.entries().forEach(entry -> System.setProperty(entry.getKey(), 
			entry.getValue())); 
		SpringApplication.run(LmsBackendApplication.class, args);
	}

}
