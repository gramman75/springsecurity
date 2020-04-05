package me.gramman75.account;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.*;

@Entity
@Getter @Setter
public class Account {

    @Id @GeneratedValue
    private Long id;

    @Column(unique = true)
    private String username;

    private String password;

    private String role;

    public void setEncodePassword(PasswordEncoder encodePassword) {

        this.password = encodePassword.encode(this.password);
    }
}
