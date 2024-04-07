package com.patternknife.securityhelper.oauth2.domain.customer.entity;

import com.patternknife.securityhelper.oauth2.domain.role.entity.Role;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@Entity
@Table(name ="customer_role")
public class CustomerRole {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "customer_id")
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private Customer customer;

    @ManyToOne
    @JoinColumn(name = "role_id")
    private Role role;

}
