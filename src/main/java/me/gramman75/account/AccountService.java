package me.gramman75.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class AccountService  implements UserDetailsService{
    @Autowired
    AccountRepository accountRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        Account account = accountRepository.findByUsername(username);

        if (account == null){
            throw new UsernameNotFoundException(username);
        }

        List<SimpleGrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority("ROLE_USER"));

        AccountUser accountUser = new AccountUser(account, roles);

        return accountUser;


//        return User.builder()
//                .username(username)
//                .password(account.getPassword())
//                .roles(account.getRole())
//                .build();
    }

    @Transactional
    public Account createUser(Account account){

        account.setEncodePassword(passwordEncoder);
        Account save = accountRepository.save(account);
        return save;
    }

   


}
