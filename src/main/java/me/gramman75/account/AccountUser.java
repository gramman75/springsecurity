package me.gramman75.account;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;

public class AccountUser extends User {

    private Account account;

    public AccountUser(Account account, List<SimpleGrantedAuthority> roles) {

        super(account.getUsername(), account.getPassword(), roles);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
