package me.gramman75.form;

import me.gramman75.account.Account;
import me.gramman75.account.AccountService;
import me.gramman75.account.AccountUser;
import me.gramman75.common.SecurityLog;
import me.gramman75.controller.SampleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;
import java.util.concurrent.Callable;

@Controller
public class SampleController {

    @Autowired
    SampleService sampleService;

    @Autowired
    AccountService accountService;


    @GetMapping("/")
    public String index(Model model, @AuthenticationPrincipal AccountUser principal) {
        if (principal == null) {
            model.addAttribute("message", "Hello Spring Security");
        } else {
            model.addAttribute("message", "Hello, " + principal.getAccount().getUsername());
        }
        return "index";
    }

    @GetMapping("/info")
    public String info(Model model) {
        model.addAttribute("message", "Hello, Info");

        return "info";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, Principal principal) {
        model.addAttribute("message", "Hello, " + principal.getName());
        sampleService.dashboard();
        return"dashboard";
    }

    @GetMapping("/admin")
    public String admin(Model model, Principal principal) {
        model.addAttribute("message", "Hello, Admin " +  principal.getName());

        return "admin";
    }


    @GetMapping("/user")
    public String user(Model model) {
        model.addAttribute("message", "Hello, User");

        return "user";
    }


    /**
     * WebAsyncManagerIntegrationFilter
     * 비동기 처리시 새로운 Thread에서도 동일한 principal이 적용될 수 있도록 함.
     * 아래 예제어서는 main thread와 비동기 thread에서 동일한 principal이 사용되는 예제.
     * @return
     */
    @GetMapping("/async-handler")
    @ResponseBody
    public Callable<String> async() {
        SecurityLog.log("MVC");
        return new Callable<String>() {
            @Override
            public String call() throws Exception {
                SecurityLog.log("Callable");
                return "Callable";
            }
        };
    }

    /**
     * @Async annotation 사용시에는 SecuContextHolder전략을 MODE_INHERITABLETHREADLOCAL 울 세팅해야함.
     * Spring 에서 Async사용을 위해서는 @EnableAsync annotaion을 사용해야 함.
     * @return
     */
    @GetMapping("/async-service")
    @ResponseBody
    private String asyncService() {
        SecurityLog.log("Before MVC");
        String s = sampleService.asyncService();
        SecurityLog.log("After MVC");

        return s;

    }

    @GetMapping("/account")
    public String account(Model model) {
        Account account = new Account();

        model.addAttribute("account", account);

        return "signup";
    }

    @PostMapping("/signup")
    public String signup(@ModelAttribute Account account) {
        accountService.createUser(account);
        return "redirect:/";
    }

    @GetMapping("/signin")
    public String signin() {
        return "signin";
    }

    @GetMapping("/logout")
    public String logout() {
        return "logout";
    }

    @GetMapping("/access-denied")
    public String accessDenied(Principal principal, Model model){
        model.addAttribute("username", principal.getName());
        return "accessDenied";
    }

    @GetMapping("/security")
    public String security(){
        return "security";
    }



}

