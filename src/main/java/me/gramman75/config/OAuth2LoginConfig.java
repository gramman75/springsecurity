package me.gramman75.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

@Configuration
public class OAuth2LoginConfig {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.googleClientResitration(), this.githubClientRegistration());
    }

    private ClientRegistration githubClientRegistration() {
        return CommonOAuth2Provider.GITHUB.getBuilder("github")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .clientId("a6cb870badf481ece5ae")
            .clientSecret("54278b558eeb36b85638eb2398ce6d940dfa582e")
            .build();
    }

    private ClientRegistration googleClientResitration() {
        return CommonOAuth2Provider.GOOGLE.getBuilder("google")
        .clientId("234310243630-b8h8hshhor5qvsuviol64paoco5mq40i.apps.googleusercontent.com")
        .clientSecret("rWIEYaXge4zPHmaeGaEDpr4h")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .build();
        // return ClientRegistration.withRegistrationId("google")
        //         .clientId("234310243630-b8h8hshhor5qvsuviol64paoco5mq40i.apps.googleusercontent.com")
        //         .clientSecret("rWIEYaXge4zPHmaeGaEDpr4h")
        //         .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
        //         .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        //         .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
        //         .redirectUriTemplate("{baseUrl}/login/oauth2/code/google")
        //         .scope("openid", "profile", "email", "address", "phone") 
        //         .tokenUri("https://www.googleapis.com/oauth2/v4/token")
        //         .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
        //         .userNameAttributeName(IdTokenClaimNames.SUB)
        //         .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
        //         .clientName("Google")
        //         .build();

//         ClientRegistration.Builder builder = getBuilder(registrationId,
//         ClientAuthenticationMethod.BASIC, DEFAULT_REDIRECT_URL);
// builder.scope("openid", "profile", "email");
// builder.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth");
// builder.tokenUri("https://www.googleapis.com/oauth2/v4/token");
// builder.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs");
// builder.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo");
// builder.userNameAttributeName(IdTokenClaimNames.SUB);
// builder.clientName("Google");
       
    }               

}