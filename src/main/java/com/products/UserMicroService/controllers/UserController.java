package com.products.UserMicroService.controllers;


import com.products.UserMicroService.jwt.JWTUtils;
import com.products.UserMicroService.jwt.LoginRequest;
import com.products.UserMicroService.jwt.LoginResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class UserController {

    AuthenticationManager authenticationManager;

    JWTUtils jwtUtils;

    private Logger logger = LoggerFactory.getLogger(UserController.class);

    @Autowired
    public UserController(AuthenticationManager authenticationManager, JWTUtils jwtUtils) {
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
        this.logger = logger;
    }

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String userEndPoint(){
        return "user end point!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndPoint(){
        return "admin end point!";
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signIn(@RequestBody LoginRequest loginRequest){

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        }
        catch (BadCredentialsException e) {
            logger.error("Authentication Failed : {}",e.getMessage());
            Map<String,Object> map = new HashMap<>();
            map.put("message","Authentication Failed");
            map.put("status",false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = jwtUtils.generateToken(userDetails);
        List<String> roles = userDetails.getAuthorities().stream().map(item->item.getAuthority()).collect(Collectors.toList());

        LoginResponse loginResponse = new LoginResponse(token,userDetails.getUsername(),roles);
        return ResponseEntity.ok(loginResponse);
    }
}
