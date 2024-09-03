package com.example.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ImportResource;


@SpringBootApplication
@ImportResource("security.xml")
public class SecurityApplication {

	
	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

}
