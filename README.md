package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/login", "/public/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login();
        http.addFilterBefore(tokenRefreshFilter(), OAuth2LoginAuthenticationFilter.class);
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository) {

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .build());
        return authorizedClientManager;
    }

    @Bean
    public OncePerRequestFilter tokenRefreshFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                try {
                    OAuth2AuthorizedClientService clientService = getApplicationContext().getBean(OAuth2AuthorizedClientService.class);
                    OAuth2AuthorizedClientManager authorizedClientManager = getApplicationContext().getBean(OAuth2AuthorizedClientManager.class);

                    Authentication authentication = (Authentication) request.getUserPrincipal();
                    OAuth2AuthorizedClient authorizedClient = clientService.loadAuthorizedClient("okta", authentication.getName());

                    if (authorizedClient != null && shouldRefreshToken(authorizedClient.getAccessToken())) {
                        OAuth2AuthorizedClient updatedClient = refreshAccessToken(authorizedClientManager, authorizedClient, authentication);
                        clientService.saveAuthorizedClient(updatedClient, authentication);
                    }
                } catch (Exception e) { }
                filterChain.doFilter(request, response);
            }

            private boolean shouldRefreshToken(OAuth2AccessToken accessToken) {
                return accessToken.getExpiresAt().isBefore(Instant.now().plusSeconds(60));
            }

            private OAuth2AuthorizedClient refreshAccessToken(OAuth2AuthorizedClientManager authorizedClientManager,
                                                              OAuth2AuthorizedClient authorizedClient,
                                                              Authentication principal) {
                OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(authorizedClient)
                        .principal(principal)
                        .build();
                return authorizedClientManager.authorize(authorizeRequest);
            }
        };
    }
}
