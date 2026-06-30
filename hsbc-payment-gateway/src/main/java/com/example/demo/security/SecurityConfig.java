package com.example.demo.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration for the demo app.
 *
 * This sets up:
 *  1. Which routes require login, and which roles can access which routes.
 *  2. A simple form-based login page.
 *  3. Two in-memory demo users (no database needed) — one regular user
 *     and one admin user — so students can see role-based access control
 *     without setting up persistence first.
 *
 * Credentials are read from application.yml rather than hardcoded, so they
 * can be changed without touching this file. See: app.demo-users.*
 */
@Configuration
public class SecurityConfig {

  // Injected from application.yml: app.demo-users.user.*
  @Value("${app.demo-users.user.username}")
  private String regularUsername;

  @Value("${app.demo-users.user.password}")
  private String regularPassword;

  // Injected from application.yml: app.demo-users.admin.*
  @Value("${app.demo-users.admin.username}")
  private String adminUsername;

  @Value("${app.demo-users.admin.password}")
  private String adminPassword;

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
      // authorizeHttpRequests defines which URLs need authentication/roles.
      // Rules are checked top-to-bottom, so put more specific rules first.
      .authorizeHttpRequests(auth -> auth
        // Anyone can view these without logging in.
        .requestMatchers("/public", "/public/**", "/css/**", "/js/**", "/images/**", "/error", "/login").permitAll()
        // Only users with the ADMIN role can reach /admin.
        .requestMatchers("/admin", "/admin/**").hasRole("ADMIN")
        // Everything else just needs the user to be logged in (any role).
        .anyRequest().authenticated()
      )
      // formLogin configures Spring Security's built-in login form handling.
      .formLogin(form -> form
        .loginPage("/login")        // our custom login page
        .permitAll()                // the login page itself must be public
        .defaultSuccessUrl("/", true) // where to send users after a successful login
      )
      .logout(logout -> logout
        .logoutSuccessUrl("/public") // where to send users after logging out
        .permitAll()
      );

    return http.build();
  }

  /**
   * Creates two demo users, stored in memory (not a database).
   * Good for learning/demos; for a real app you'd back this with a
   * UserDetailsService backed by a database (e.g. Spring Data JPA).
   */
  @Bean
  UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    UserDetails regularUser = User.builder()
      .username(regularUsername)
      .password(passwordEncoder.encode(regularPassword))
      .roles("USER")
      .build();

    UserDetails adminUser = User.builder()
      .username(adminUsername)
      .password(passwordEncoder.encode(adminPassword))
      .roles("ADMIN")
      .build();

    return new InMemoryUserDetailsManager(regularUser, adminUser);
  }

  /**
   * BCrypt is the standard, recommended way to hash passwords in Spring
   * Security. Never store plain-text passwords, even in demo apps.
   */
  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
