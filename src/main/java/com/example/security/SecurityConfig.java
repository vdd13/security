package com.example.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.security.jwt.AuthEntryPointJwt;
import com.example.security.jwt.AuthTokenFilter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity //metody z kontrollera z PreAuthorize
public class SecurityConfig {

	@Autowired
	DataSource dataSource;
	
	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;
	

	
	
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception { //metoda dla zmian dla JWT
		
		http.authorizeHttpRequests(authorizeRequest -> 
				authorizeRequest.requestMatchers("/app/signin").permitAll()
				.anyRequest().authenticated());
		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
		http.csrf(csrf -> csrf.disable()); 
		http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
		
		return http.build();
	}
	
//	@Bean
//	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception { //metoda przed JWT
//		http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
////		http.authorizeHttpRequests((requests) -> requests.requestMatchers("/app/**").permitAll());
////		http.formLogin(withDefaults());
//		http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//		http.httpBasic(withDefaults());
//		return http.build();
//	}

    @Bean
    UserDetailsService userDetailService() { 
		UserDetails user1 = User.withUsername("user1")
				.password(passwordEncoder().encode("pass"))
				.roles("USER")
				.build();
		
		JdbcUserDetailsManager userDatailsManager = new JdbcUserDetailsManager(dataSource);
//		userDatailsManager.createUser(user1); // wpis do bazy nowego uzytkowania
		return userDatailsManager;
		
//		return new InMemoryUserDetailsManager(user1);
	}
	
    @Bean
    PasswordEncoder passwordEncoder() {
    	return new BCryptPasswordEncoder();
    }
    
	@Bean
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration auth) throws Exception{
		return auth.getAuthenticationManager();
	}
    
//	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
// 		http.authorizeHttpRequests().requestMatchers("/public/**").permitAll().anyRequest()
// 				.hasRole("USER").and()
// 				// Possibly more configuration ...
// 				.formLogin() // enable form based log in
// 				// set permitAll for all URLs associated with Form Login
// 				.permitAll();
// 		return http.build();
// 	}
    
}
