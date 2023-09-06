package com.hakim.accessandrefreshtokensecurity.service;

import com.hakim.accessandrefreshtokensecurity.exception.ResourceNotFoundException;
import com.hakim.accessandrefreshtokensecurity.model.User;
import com.hakim.accessandrefreshtokensecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repository;
    private final PasswordEncoder encoder;

    public User save(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return repository.save(user);
    }

    public User getById(long userId) {
        return repository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User fot found with id : " + userId));
    }

    public User getByUsername(String username) {
        return repository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User fot found with username : " + username));
    }

    public List<User> getAll() {
        return repository.findAll();
    }
}
