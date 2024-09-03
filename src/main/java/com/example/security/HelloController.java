package com.example.security;


import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.security.jwt.JwtUtils;
import com.example.security.jwt.LoginRequest;
import com.example.security.jwt.LoginResponse;

@RestController
@RequestMapping("/app")
public class HelloController {

	@Autowired
	JwtUtils jwtUtils;
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@PreAuthorize("hasRole('ROLE_USER')")
	@GetMapping("/hi/{name}")
	public ResponseEntity<String> welcome(@PathVariable String name) {
		return new ResponseEntity<String>("Welcome " + name, HttpStatus.ACCEPTED);
	}
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
		Authentication authentication;
		try {
			System.out.println("4444444444444444444");
			authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					loginRequest.getUsername(), loginRequest.getPassword()));
			System.out.println("5555555555555555555555555");
		} catch (AuthenticationException e) {
			Map<String, Object> map = new HashMap<String, Object>();
			map.put("message", "Bad credentials");
			map.put("status", false);
			return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
		}
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		UserDetails userDetails = (UserDetails) authentication.getPrincipal();
		
		String jwtToken = jwtUtils.generateTokenFromUserName(userDetails);
		
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());
		
		LoginResponse response = new LoginResponse(jwtToken, userDetails.getUsername(), roles);
		return ResponseEntity.ok(response);
	}
	
}
