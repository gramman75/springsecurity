package me.gramman75.account;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import javax.swing.*;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AccountControllerTest {

    @Autowired
    MockMvc mockMvc;


    @Autowired
    AccountService accountService;


    @Test
    public void index() throws Exception{
        mockMvc.perform(get("/"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    public void info() throws Exception {
        mockMvc.perform(get("/info"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "gramman75")
    public void dashboard() throws Exception {
        mockMvc.perform(get("/dashboard"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "gramman75", roles = "ADMIN")
    public void admin() throws Exception {
        mockMvc.perform(get("/admin"))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    public void login() throws Exception{
        Account account = new Account();
        account.setUsername("gramman75");
        account.setPassword("123");
        account.setRole("USER");
        accountService.createUser(account);
        mockMvc.perform(formLogin().user("gramman75").password("123"))
        .andExpect(authenticated());
    }

    @Test
    public void signupform() throws Exception {
        mockMvc.perform(get("/account"))
                .andDo(print())
                .andExpect(content().string(containsString("_csrf")));
    }

    @Test
    public void signupProcess() throws Exception {
        mockMvc.perform(post("/signup")
                        .param("username", "gramman75")
                        .param("password", "123").with(csrf()))
                .andDo(print())
                .andExpect(status().is3xxRedirection());

    }




}