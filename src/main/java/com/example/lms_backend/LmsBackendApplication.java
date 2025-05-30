package com.example.lms_backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder; // Import this
import io.github.cdimascio.dotenv.Dotenv;
import java.util.HashMap; // Import this
import java.util.Map; // Import this

@SpringBootApplication
public class LmsBackendApplication {

    public static void main(String[] args) {
        System.out.println("Attempting to load .env file for SpringApplicationBuilder...");
        Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load(); // Load .env

        Map<String, Object> properties = new HashMap<>();

        // Load values from dotenv and prepare them for SpringApplicationBuilder
        String dbUsername = dotenv.get("LMS_DB_USERNAME");
        String dbPassword = dotenv.get("LMS_DB_PASSWORD");
        String jwtSecret = dotenv.get("LMS_APP_JWT_SECRET");
        String jwtExpiration = dotenv.get("LMS_APP_JWT_EXPIRATION_MS", "86400000"); // Default if not in .env

        if (dbUsername != null) properties.put("spring.datasource.username", dbUsername);
        if (dbPassword != null) properties.put("spring.datasource.password", dbPassword);
        if (jwtSecret != null) properties.put("lms.app.jwtSecret", jwtSecret); // Use the direct property key here
        if (jwtExpiration != null) properties.put("lms.app.jwtExpirationMs", jwtExpiration);


        System.out.println("---- DEBUGGING .env Values for SpringApplicationBuilder ----");
        System.out.println("spring.datasource.username: " + properties.get("spring.datasource.username"));
        System.out.println("spring.datasource.password: " + (properties.get("spring.datasource.password") != null ? "[PASSWORD_SET]" : "[PASSWORD_NOT_SET]"));
        System.out.println("lms.app.jwtSecret: " + properties.get("lms.app.jwtSecret"));
        System.out.println("lms.app.jwtExpirationMs: " + properties.get("lms.app.jwtExpirationMs"));
        System.out.println("-------------------------------------------------------------");

        if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
            System.err.println("CRITICAL: LMS_APP_JWT_SECRET from .env is NOT found or is empty for SpringApplicationBuilder!");
        }
        if (dbUsername == null || dbUsername.trim().isEmpty()) {
            System.err.println("CRITICAL: LMS_DB_USERNAME from .env is NOT found or is empty for SpringApplicationBuilder!");
        }


        new SpringApplicationBuilder(LmsBackendApplication.class)
                .properties(properties) // Add properties directly to Spring's environment
                .run(args);
    }
}