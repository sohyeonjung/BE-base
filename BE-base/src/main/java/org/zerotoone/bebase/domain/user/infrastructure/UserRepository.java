package org.zerotoone.bebase.domain.user.infrastructure;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.zerotoone.bebase.domain.user.domain.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
}
