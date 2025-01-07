package com.patternhelloworld.securityhelper.oauth2.client.domain.customer.dao;

import com.patternhelloworld.securityhelper.oauth2.client.domain.customer.entity.Customer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.querydsl.QuerydslPredicateExecutor;

import java.util.List;
import java.util.Optional;


public interface CustomerRepository extends JpaRepository<Customer, Long>, QuerydslPredicateExecutor<Customer> {

    Optional<Customer> findByIdName(String idName);

    Optional<List<Customer>> findByNameAndHp(String name, String hp);

    Boolean existsByIdName(String idName);
    Boolean existsByHp(String hp);

}