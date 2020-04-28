package me.gramman75.common;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import me.gramman75.account.Account;
import me.gramman75.account.AccountRepository;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    AccountRepository accountRepository;



    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException { 

        OAuth2User oauth2 = super.loadUser(userRequest);
        CommonOAuth2User commonOAuth2User = new CommonOAuth2User();

        if (userRequest.getClientRegistration().getRegistrationId().equals("github")){
            commonOAuth2User.setLogin((String)oauth2.getAttributes().get("login"));
            commonOAuth2User.setId((String)oauth2.getAttributes().get("id"));
        } 

        updateUser(commonOAuth2User);

        return oauth2;

    }

    private void updateUser(CommonOAuth2User auth2User) {
        Account findByUsername = accountRepository.findByUsername(auth2User.getLogin());
        if (findByUsername == null){
            Account account = new Account();
            account.setUsername(auth2User.getLogin());
            accountRepository.save(account);
        }
    }
}