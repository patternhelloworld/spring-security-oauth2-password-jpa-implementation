package com.patternknife.securityhelper.oauth2.domain.customer.dao;

import com.patternknife.securityhelper.oauth2.domain.customer.entity.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.querydsl.QuerydslPredicateExecutor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;


public interface CustomerRepository extends JpaRepository<Customer, Long>, QuerydslPredicateExecutor<Customer> {

    Optional<Customer> findByIdName(String idName);

    Boolean existsByNameAndHpAndBirthdayAndSex(String name, String hp, LocalDate birthday, String sex);

    Optional<Customer> findByKakaoIdName(String idName);
    Optional<Customer> findByNaverIdName(String idName);
    Optional<Customer> findByGoogleIdName(String idName);
    Optional<Customer> findByAppleIdName(String idName);

    Optional<Customer> findByCi(String ci);

    Optional<List<Customer>> findByNameAndHp(String name, String hp);

    Boolean existsByIdName(String idName);
    Boolean existsByHp(String hp);
    Boolean existsByCi(String ci);
    Boolean existsByDi(String di);


    @Query(value = "SELECT * FROM Customer c WHERE c.last_point_expiration_checked_at IS NULL OR c.last_point_expiration_checked_at <= :oneHourBeforeLocalDateTime ORDER BY c.last_point_expiration_checked_at ASC LIMIT 1", nativeQuery = true)
    Optional<Customer> findPointExpirationCheckedNullOrOldestFirstMySQL(LocalDateTime oneHourBeforeLocalDateTime);

    @Query(value = "SELECT TOP 1 * FROM Customer c WHERE c.last_point_expiration_checked_at IS NULL OR c.last_point_expiration_checked_at <= :oneHourBeforeLocalDateTime ORDER BY c.last_point_expiration_checked_at ASC", nativeQuery = true)
    Optional<Customer> findPointExpirationCheckedNullOrOldestFirstMSSQL(LocalDateTime oneHourBeforeLocalDateTime);
}