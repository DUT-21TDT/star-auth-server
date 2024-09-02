package com.pbl.starauthserver.properties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
class ClientProperties {
    protected String clientId;
    protected String clientSecret;
    protected String redirectUri;
    protected String authorizationUri;
    protected String logoutUri;
}
