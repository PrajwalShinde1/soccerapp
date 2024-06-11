import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

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
            .oauth2Login()
                .defaultSuccessUrl("/default-url", true)
                .userInfoEndpoint()
                .oidcUserService(this.oidcUserService())
            .and()
                .successHandler(authenticationSuccessHandler());
        
        http.addFilterBefore(tokenRefreshFilter(), OAuth2LoginAuthenticationFilter.class);
    }

    private OidcUserService oidcUserService() {
        OidcUserService delegate = new OidcUserService();
        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            // Custom processing of the OIDC user can be done here
            return oidcUser;
        };
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
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            // Custom logic on successful authentication
            response.sendRedirect("/default-url");
        };
    }

    @Bean
    public OncePerRequestFilter tokenRefreshFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                OAuth2AuthorizedClientManager authorizedClientManager = authorizedClientManager(
                        getApplicationContext().getBean(ClientRegistrationRepository.class),
                        getApplicationContext().getBean(OAuth2AuthorizedClientRepository.class));
                
                OAuth2AuthorizedClientService clientService = getApplicationContext().getBean(OAuth2AuthorizedClientService.class);
                OAuth2AuthorizedClient authorizedClient = clientService.loadAuthorizedClient("okta", request.getUserPrincipal().getName());

                if (authorizedClient != null && shouldRefreshToken(authorizedClient.getAccessToken())) {
                    OAuth2AuthorizedClient updatedClient = refreshAccessToken(authorizedClientManager, authorizedClient);
                    clientService.saveAuthorizedClient(updatedClient, request.getUserPrincipal());
                }

                filterChain.doFilter(request, response);
            }

            private boolean shouldRefreshToken(OAuth2AccessToken accessToken) {
                return accessToken.getExpiresAt().isBefore(Instant.now().minusSeconds(60));
            }

            private OAuth2AuthorizedClient refreshAccessToken(OAuth2AuthorizedClientManager authorizedClientManager,
                                                              OAuth2AuthorizedClient authorizedClient) {
                OAuth2AuthorizationContext context = OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
                        .principal(authorizedClient.getPrincipal())
                        .build();
                return authorizedClientManager.authorize(context);
            }
        };
    }
}
