package spring.security.practice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.practice.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUserName(String userName);
}
