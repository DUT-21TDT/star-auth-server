package com.pbl.starauthserver.configurations;

import com.pbl.starauthserver.security.CustomOAuth2User;
import com.pbl.starauthserver.security.CustomUserDetails;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.List;

@Configuration
public class JwtConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {

            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {

                Authentication principal = context.getPrincipal();

                if (principal != null && principal.getPrincipal() instanceof CustomOAuth2User oAuth2User) {
                    context.getClaims().subject(oAuth2User.getUsername());
                    context.getClaims().claim("roles", List.of(oAuth2User.getRole().name()));
                }

                else if (principal != null && principal.getPrincipal() instanceof CustomUserDetails customUserDetails) {
                    context.getClaims().claim("roles", List.of(customUserDetails.getRole().name()));
                }

            }
        };
    }

}
