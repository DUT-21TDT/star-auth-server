package com.pbl.starauthserver.security.OAuth2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class CustomOAuth2AuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final Map<String, String> loginUrls;
    private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String clientLoginUri = "/login?error=true"; // Default login URI
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest == null) {
            response.sendRedirect(clientLoginUri);
            return;
        }

        String redirectUrl = savedRequest.getRedirectUrl();
        Map<String, String> queryParams = UriComponentsBuilder.fromUriString(redirectUrl).build().getQueryParams().toSingleValueMap();
        String clientId = queryParams.get("client_id");

        // Retrieve the client-specific login URI if available
        if (clientId != null) {
            if (loginUrls != null && loginUrls.containsKey(clientId)) {
                clientLoginUri = loginUrls.get(clientId) + "?error=true";
            }
        }

        response.sendRedirect(clientLoginUri);
    }
}