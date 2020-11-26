package com.imooc.distributedsession.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static com.imooc.distributedsession.LoginIntercepter.JWT_KEY;
import static com.imooc.distributedsession.LoginIntercepter.UID;

/**
 * @author: bizy
 * @date: 2020/11/19 19:34
 */
@RequestMapping("/user")
@RestController
public class UserController {

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

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

    @GetMapping("/loginWithToken")
    public String loginWithToken(@RequestParam String username,
                        @RequestParam String password) {
        //账号密码正确
        String key = "token_" + UUID.randomUUID().toString();
        stringRedisTemplate.opsForValue().set(key,username,3600, TimeUnit.SECONDS);
        return key;
    }

    @GetMapping("/infoWithToken")
    public String info(@RequestHeader String token) {
        return "当前登录的是:" +  stringRedisTemplate.opsForValue().get(token);
    }

    @GetMapping("/loginWithJwt")
    public String loginWithJwt(@RequestParam String username,
                               @RequestParam String password) {
        Algorithm algorithm = Algorithm.HMAC256(JWT_KEY);
        String token = JWT.create()
//                .withIssuer("auth0")
                .withClaim("login_user",username)
                .withClaim(UID,1)
                .withExpiresAt(new Date(System.currentTimeMillis() + 3600000)) //设置过期时间
                .sign(algorithm);
        return token;
    }

    @GetMapping("/infoWithJwt")
    public String infoWithJwt(@RequestAttribute String login_user){
        return login_user;
    }

    //获取地址
    @GetMapping("/address")
    public Integer address(@RequestAttribute Integer uid){
        return uid;
    }
}
