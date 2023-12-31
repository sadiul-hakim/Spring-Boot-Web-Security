package com.hakim.accessandrefreshtokensecurity.service;

import com.hakim.accessandrefreshtokensecurity.exception.ResourceNotFoundException;
import com.hakim.accessandrefreshtokensecurity.model.Role;
import com.hakim.accessandrefreshtokensecurity.model.User;
import com.hakim.accessandrefreshtokensecurity.pojo.UserRole;
import com.hakim.accessandrefreshtokensecurity.repository.RoleRepository;
import com.hakim.accessandrefreshtokensecurity.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class RoleService {
    private final RoleRepository repository;
    private final UserRepository userRepository;

    public Role save(Role role) {
        return repository.save(role);
    }

    public Role getById(long roleId) {
        return repository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found with id : " + roleId));
    }

    public List<Role> getAll() {
        return repository.findAll();
    }

    public void addRoleToUser(UserRole userRole){
        Role role = repository.findByAuthority(userRole.getAuthority())
                .orElseThrow(() -> new ResourceNotFoundException("Role not found with authority : " + userRole.getAuthority()));
        User user = userRepository.findByUsername(userRole.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username : " + userRole.getUsername()));

        user.getRoles().add(role);
    }
}
