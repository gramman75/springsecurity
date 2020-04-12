package me.gramman75;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;

import java.net.StandardProtocolFamily;

@SpringBootApplication
@EnableAsync
public class SpringSecurityApplication {

	@Bean
	public PasswordEncoder passwordEncoder(){
//		PasswordEncoder delegatingPasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		PasswordEncoder delegatingPasswordEncoder = new StandardPasswordEncoder();
		return delegatingPasswordEncoder;
	}

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

}
