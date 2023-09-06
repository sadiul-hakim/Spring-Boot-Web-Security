package com.hakim.accessandrefreshtokensecurity.controller;

import com.hakim.accessandrefreshtokensecurity.model.User;
import com.hakim.accessandrefreshtokensecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    @PostMapping("/public/save")
    public ResponseEntity<?> saveUser(@RequestBody User user){
        User savedUser = userService.save(user);
        return ResponseEntity.ok(savedUser);
    }

    @GetMapping("/public/get")
    public ResponseEntity<?> getUserById(@RequestParam long userId){
        User user = userService.getById(userId);
        return ResponseEntity.ok(user);
    }

    @GetMapping("/secure/get-all")
    public ResponseEntity<?> getAll(){
        List<User> users = userService.getAll();
        return ResponseEntity.ok(users);
    }
}
