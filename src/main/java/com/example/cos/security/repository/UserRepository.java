package com.example.cos.security.repository;

import com.example.cos.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Integer> {

    //findBy 규칙 -> Username문법
    // select * from user where username= ?
    public User findByUsername(String username);
}