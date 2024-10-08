package com.pbl.starauthserver.services;

import com.pbl.starauthserver.entities.AuthUser;
import com.pbl.starauthserver.enums.AccountStatus;
import com.pbl.starauthserver.enums.UserRole;
import com.pbl.starauthserver.repositories.UserRepository;
import com.pbl.starauthserver.security.OAuth2.CustomOAuth2User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

import static com.pbl.starauthserver.utils.UsernameGenerator.generateUniqueName;

@Service
@RequiredArgsConstructor
public class CustomOauth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        // Extract user details from OAuth2User
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        // Check if user exists in the database
        List<AuthUser> users = userRepository.findByEmailAndStatus(email, AccountStatus.ACTIVE);

        AuthUser user;
        if (users.isEmpty()) {
            // Create a new user record if this is the first login

            String username = generateUniqueName(name);
            while (userRepository.existsByUsername(username)) {
                username = generateUniqueName(name);
            }

            AuthUser newUser = AuthUser.builder()
                    .username(username)
                    .email(email)
                    .role(UserRole.USER)
                    .registerAt(Instant.now())
                    .status(AccountStatus.ACTIVE)
                    .privateProfile(false)
                    .build();

            userRepository.deleteAll(userRepository.findByEmailAndStatus(email, AccountStatus.INACTIVE));

            user = userRepository.save(newUser);
        } else {
            user = users.getFirst();
        }

        return new CustomOAuth2User(oAuth2User, user.getId(), user.getRole());
    }

}
