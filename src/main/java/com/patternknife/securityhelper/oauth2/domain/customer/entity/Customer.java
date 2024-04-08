package com.patternknife.securityhelper.oauth2.domain.customer.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.patternknife.securityhelper.oauth2.config.response.error.CustomExceptionUtils;
import com.patternknife.securityhelper.oauth2.domain.admin.entity.Admin;
import com.patternknife.securityhelper.oauth2.domain.customer.dto.CustomerReqDTO;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.format.annotation.DateTimeFormat;

import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name="customer")
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@AllArgsConstructor
@DynamicUpdate
public class Customer
{
	@Id
	@GeneratedValue(strategy= GenerationType.IDENTITY)
	private Long id;

	@Column(name="id_name")
	private String idName;
	@Column(name="deleted_id_name")
	private String deletedIdName;

	private String email;
	@Embedded
	private Password password;
	private String name;
	private String hp;

	@DateTimeFormat(pattern = "yyyy-MM-dd")
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd", timezone = "Asia/Seoul")
	private LocalDate birthday;
	@Column(length = 1)
	private String sex;


	@OneToMany(mappedBy = "customer")
	private final List<CustomerRole> customerRoles = new ArrayList<>();


	@Column(name="created_at", updatable = false)
	@CreationTimestamp
	private Timestamp createdAt;

	@Column(name="updated_at")
	@UpdateTimestamp
	private Timestamp updatedAt;


	@Column(name="deleted_at")
	private LocalDateTime deletedAt;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "delete_admin_id")
	private Admin deleteAdmin;

	@Column(name="delete_admin_id", insertable = false, updatable = false)
	private Long deleteAdminId;

	
	public void updateCustomer(CustomerReqDTO.Update dto) {
		this.idName = dto.getIdName();
		this.name = dto.getName();
		this.hp = dto.getHp();
		this.email = dto.getEmail();
	}


	public void updatePasswordAndEmail(CustomerReqDTO.UpdatePasswordAndEmail dto) {
		this.password = Password.builder().value(dto.getPassword()).build();
		this.email = dto.getEmail();
	}

	public String getOneWeekAfterDeletedAsString() {

		try {

			LocalDateTime oneWeekAfter = this.deletedAt.plusWeeks(1);

			DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

			return oneWeekAfter.format(formatter);

		}catch (Exception e){
			CustomExceptionUtils.createNonStoppableErrorMessage(e.getMessage(), e);
			return null;
		}
	}

}
