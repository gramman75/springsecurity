package me.gramman75.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccountService implements UserDetailsService {
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

        return User.builder()
                .username(username)
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

    @Transactional
    public Account createUser(Account account){

        account.setEncodePassword(passwordEncoder);
        Account save = accountRepository.save(account);
        return save;
    }


}
