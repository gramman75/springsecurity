package me.gramman75.common;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import me.gramman75.account.Account;
import me.gramman75.account.AccountRepository;

@Service
public class CustomOidcUserService extends OidcUserService {

    @Autowired
    AccountRepository accountRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        OidcUser oauth2 = super.loadUser(userRequest);
        CommonOAuth2User commonOAuth2User = new CommonOAuth2User();

        if (userRequest.getClientRegistration().getRegistrationId().equals("google")){
            commonOAuth2User.setLogin((String)oauth2.getAttributes().get("email"));
            commonOAuth2User.setId((String)oauth2.getAttributes().get("email"));
        } 

        updateUser(commonOAuth2User);

        return oauth2;

    }

    @Transactional
    private void updateUser(CommonOAuth2User auth2User) {
        Account findByUsername = accountRepository.findByUsername(auth2User.getLogin());
        if (findByUsername == null){
            Account account = new Account();
            account.setUsername(auth2User.getLogin());
            accountRepository.save(account);
        }
    }

}