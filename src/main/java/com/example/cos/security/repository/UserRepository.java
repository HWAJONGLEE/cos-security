package com.example.cos.security.repository;

import com.example.cos.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepository extends JpaRepository<User, Integer> {

}