package com.imooc.distributedsession.controller;

import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;

/**
 * @author: bizy
 * @date: 2020/11/19 19:34
 */
@RequestMapping("/user")
@RestController
public class UserController {

    @GetMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpSession session) {
        //账号密码正确
        session.setAttribute("login_user",username);
        return "登录成功";
    }

    @GetMapping("/info")
    public String info(HttpSession session) {
        return "当前登录的是:" +  session.getAttribute("login_user");
    }
}
