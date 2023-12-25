package com.rachvik.security.auth;

import com.rachvik.security.config.JWTService;
import com.rachvik.security.user.Role;
import com.rachvik.security.user.User;
import com.rachvik.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository repository;
  private final JWTService jwtService;
  private final AuthenticationManager authenticationManager;
  private final PasswordEncoder passwordEncoder;

  public AuthenticationResponse signup(final SignupRequest request) {
    val user =
        User.builder()
            .firstname(request.getFirstname())
            .lastname(request.getLastname())
            .email(request.getUserEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .role(Role.USER)
            .build();
    repository.save(user);
    return AuthenticationResponse.builder().token(jwtService.generateToken(user)).build();
  }

  public AuthenticationResponse login(final AuthenticationRequest request) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
    val user = repository.findByEmail(request.getUsername()).orElseThrow();
    return AuthenticationResponse.builder().token(jwtService.generateToken(user)).build();
  }
}
