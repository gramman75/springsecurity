package me.gramman75.common;

import org.springframework.security.crypto.password.PasswordEncoder;

public class CommonPasswordEncoder implements PasswordEncoder{

    @Override
    public String encode(CharSequence rawPassword) {

        return rawPassword + "123"; 
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return (rawPassword+"123").equals(encodedPassword);
    }


}