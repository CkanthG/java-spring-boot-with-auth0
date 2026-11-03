package com.sree.auth.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.client.provider.auth0.issuer-uri}")
    private String issuer;
    @Value("${spring.security.oauth2.client.registration.auth0.client-id}")
    private String clientId;

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(autherize ->
                        autherize.requestMatchers("/", "/images/**").permitAll().
                        anyRequest().authenticated()
                )
                .oauth2Login(withDefaults())
                .logout(logout -> logout.addLogoutHandler(logoutHandler()))
                .build();
    }

    private LogoutHandler logoutHandler() {
        return ((request, response, authentication) -> {
            String returnTo = ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
            String logoutUrl = UriComponentsBuilder.fromUriString(issuer)
                    .pathSegment("v2", "logout")
                    .queryParam("client_id", clientId)
                    .queryParam("returnTo", returnTo)
                    .build()
                    .encode()
                    .toUriString();
            try {
                response.sendRedirect(logoutUrl);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

}
