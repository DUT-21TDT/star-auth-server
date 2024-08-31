package com.pbl.starauthserver.repositories;

import com.pbl.starauthserver.entities.AuthUser;
import com.pbl.starauthserver.enums.AccountStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<AuthUser, Long> {
    Optional<AuthUser> findByUsername(String username);
    List<AuthUser> findByEmailAndStatus(String email, AccountStatus status);
    Boolean existsByUsername(String username);
}
