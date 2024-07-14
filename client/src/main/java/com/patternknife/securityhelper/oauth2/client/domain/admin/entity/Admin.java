package com.patternknife.securityhelper.oauth2.client.domain.admin.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name="admin")
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@AllArgsConstructor
public class Admin
{
	@Id
	@GeneratedValue(strategy= GenerationType.IDENTITY)
	private Long id;

	@Column(name="id_name")
	private String idName;

	@Column(name="description")
	private String description;

	@Embedded
	private Password password;

	@OneToMany(mappedBy = "admin")
	private final List<AdminRole> adminRoles = new ArrayList<>();

	@Column(name="created_at", updatable = false)
	@CreationTimestamp
	private Timestamp createdAt;

	@Column(name="updated_at")
	@UpdateTimestamp
	private Timestamp updatedAt;

	@Column(name="deleted_at")
	private LocalDateTime deletedAt;

}
