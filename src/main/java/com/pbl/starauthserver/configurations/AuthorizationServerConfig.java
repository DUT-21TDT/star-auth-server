package com.pbl.starauthserver.configurations;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.pbl.starauthserver.services.CustomOauth2UserService;
import com.pbl.starauthserver.services.CustomUserDetailsService;
import com.pbl.starauthserver.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Autowired
    private CustomOauth2UserService customOauth2UserService;

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
//                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/oauth2/jwks").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(
                        oauth2Login -> oauth2Login
                                .userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
                                        .userService(customOauth2UserService)
                                )
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults())
//                .formLogin(
//                        form -> form.loginPage("/login")
//                                .permitAll()
//                )
                .logout(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient starClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("star-client")
                .clientSecret("{noop}star-client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:5500/callback.html")
//                .postLogoutRedirectUri("http://localhost:8081/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .tokenSettings(tokenSettings())
                .build();

        return new InMemoryRegisteredClientRepository(starClient);
    }

    private final CustomUserDetailsService userDetailsService;

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        authenticationProvider.setUserDetailsService(userDetailsService);
        return authenticationProvider;
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // Tạo một RSA key pair và cấu hình vào JWKSet
        KeyPair keyPair = JwtUtil.generateRsaKey(); // Tạo RSA Key pair
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(15))
                .refreshTokenTimeToLive(Duration.ofDays(1))
                .build();
    }
}
