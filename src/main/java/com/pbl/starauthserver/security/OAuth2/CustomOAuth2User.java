package com.pbl.starauthserver.security.OAuth2;

import com.pbl.starauthserver.enums.UserRole;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

public class CustomOAuth2User implements OAuth2User {
    private final OAuth2User oAuth2User;
    @Getter
    private final String username;
    @Getter
    private final UserRole role;

    public CustomOAuth2User(OAuth2User oAuth2User, String username, UserRole role) {
        this.oAuth2User = oAuth2User;
        this.username = username;
        this.role = role;
    }

    @Override
    public String getName() {
        return oAuth2User.getName();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return oAuth2User.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return oAuth2User.getAuthorities();
    }

}
