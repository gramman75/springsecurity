package me.gramman75;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import me.gramman75.form.SampleController;

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

	@Bean
    UserDetailsService users() {

		UserBuilder users = User.builder();

		UserDetails user = users
			.username("gramman75")
            .password(passwordEncoder().encode("123"))
            .roles("USER")
            .build();
        
            UserDetails admin = users
            .username("admin")
            .password(passwordEncoder().encode("123"))
            .roles("ADMIN")
            .build();

        return new InMemoryUserDetailsManager(user, admin);
        
    }

	
    

}
