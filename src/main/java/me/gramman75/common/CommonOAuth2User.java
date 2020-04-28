package me.gramman75.common;

import lombok.Data;

@Data
public class CommonOAuth2User {

    private String login;

    private String id;

    private String followersUrl;

}