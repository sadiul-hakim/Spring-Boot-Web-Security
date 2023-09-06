package com.hakim.accessandrefreshtokensecurity.controller;

import com.hakim.accessandrefreshtokensecurity.model.Role;
import com.hakim.accessandrefreshtokensecurity.pojo.UserRole;
import com.hakim.accessandrefreshtokensecurity.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/role")
@RequiredArgsConstructor
public class RoleController {

    private final RoleService roleService;

    @PostMapping("/secure/save")
    public ResponseEntity<?> saveRole(@RequestBody Role role){
        Role savedRole = roleService.save(role);
        return ResponseEntity.ok(savedRole);
    }

    @GetMapping("/public/get")
    public ResponseEntity<?> getUserById(@RequestParam long roleId){
        Role role = roleService.getById(roleId);
        return ResponseEntity.ok(role);
    }

    @GetMapping("/public/get-all")
    public ResponseEntity<?> getAll(){
        List<Role> roles = roleService.getAll();
        return ResponseEntity.ok(roles);
    }

    @PostMapping("/secure/addToUser")
    public ResponseEntity<?> addRoleToUser(@RequestBody UserRole userRole){
        roleService.addRoleToUser(userRole);

        return ResponseEntity.ok(Collections.singletonMap("message","Successfully added role to the user."));
    }
}
