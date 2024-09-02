package com.pbl.starauthserver.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "star.client.web")
public class StarClientProperties extends ClientProperties {

}
