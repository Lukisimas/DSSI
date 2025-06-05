package mx.unam.feu.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import mx.unam.feu.models.Role;
import mx.unam.feu.models.TypeRole;
import mx.unam.feu.models.User;
import mx.unam.feu.payload.request.LoginRequest;
import mx.unam.feu.payload.request.SignupRequest;
import mx.unam.feu.payload.response.MessageResponse;
import mx.unam.feu.payload.response.UserInfoResponse;
import mx.unam.feu.repository.RoleRepository;
import mx.unam.feu.repository.UserRepository;
import mx.unam.feu.security.jwt.JwtUtils;
import mx.unam.feu.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	UserRepository userRepository;
	
	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		
		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

	    SecurityContextHolder.getContext().setAuthentication(authentication);

	    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

	    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

	    List<String> roles = userDetails.getAuthorities().stream()
	    		.map(item -> item.getAuthority())
	    		.collect(Collectors.toList());

	    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
	        .body(new UserInfoResponse(userDetails.getId(),
	        		userDetails.getUsername(),
	        		userDetails.getEmail(),
	        		roles));
	    
	    }

	  @PostMapping("/signup")
	  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		  
		  if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			  
			  return ResponseEntity.badRequest().body(new MessageResponse("Error: El nombre de usuario ya existe"));
			  
		  }
		  
		  if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			  
			  return ResponseEntity.badRequest().body(new MessageResponse("Error: El correo electrónico ya existe"));

		  }
		  
		  User user = new User(signUpRequest.getUsername(),
				  signUpRequest.getEmail(),
				  encoder.encode(signUpRequest.getPassword()));
		  
		  Set<String> strRoles = signUpRequest.getRole();
		  
		  Set<Role> roles = new HashSet<>();
		  
		  if (strRoles == null) {
			  
			  Role userRole = roleRepository.findByName(TypeRole.ROLE_USER)
					  .orElseThrow(() -> new RuntimeException("Error: No se encuentra el rol de usuario"));

			  roles.add(userRole);
	      
		  } else {
			  
			  strRoles.forEach(role -> {
				  
				  switch (role) {
				  
				  case "admin":
					  Role adminRole = roleRepository.findByName(TypeRole.ROLE_ADMIN)
					  .orElseThrow(() -> new RuntimeException("Error: No se encuentra el rol"));

					  roles.add(adminRole);
					  
					  break;
					  
				  case "mod":
					  Role modRole = roleRepository.findByName(TypeRole.ROLE_MODERATOR)
					  .orElseThrow(() -> new RuntimeException("Error: No se encuentra el rol"));

					  roles.add(modRole);

					  break;
					  
				  default:
					  
					  Role userRole = roleRepository.findByName(TypeRole.ROLE_USER)
					  .orElseThrow(() -> new RuntimeException("Error: No se encuentra el rol"));

					  roles.add(userRole);
					  
				  }
				  
			  });
			  
		  }
		  
		  user.setRoles(roles);
		  
		  userRepository.save(user);

		  return ResponseEntity.ok(new MessageResponse("Usuario registrado correctamente"));

	  }

	  @PostMapping("/signout")
	  public ResponseEntity<?> logoutUser() {
		  
		  ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
		  
		  return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
				  .body(new MessageResponse("Has cerrado la sesión"));

	  }

}
