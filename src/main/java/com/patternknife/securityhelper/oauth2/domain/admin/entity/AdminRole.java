package com.patternknife.securityhelper.oauth2.domain.admin.entity;

import com.patternknife.securityhelper.oauth2.domain.role.entity.Role;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.sql.Timestamp;


@Getter
@Setter
@Entity
@Table(name ="admin_role")
public class AdminRole {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "admin_id")
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private Admin admin;

    @ManyToOne
    @JoinColumn(name = "role_id")
    private Role role;

    @Column(name="created_at", updatable = false)
    @CreationTimestamp
    private Timestamp createdAt;

    @Column(name="updated_at")
    @UpdateTimestamp
    private Timestamp updatedAt;


}
