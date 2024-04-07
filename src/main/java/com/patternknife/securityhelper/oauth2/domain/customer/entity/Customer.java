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

	@Column(name="telecom_provider")
	private Integer telecomProvider;
	

	@DateTimeFormat(pattern = "yyyy-MM-dd")
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd", timezone = "Asia/Seoul")
	private LocalDate birthday;
	@Column(length = 1)
	private String sex;


	// 핸드폰 인증을 통해 들어온 유저의 고유값 ci
	private String ci;
	// 회원 탈퇴 시 CI Unique Key 를 활용하기 위해, CI 값을 여기에 저장하고 ci 컬럼의 값은 지워 버린다.
	@Column(name="deleted_ci")
	private String deletedCi;
	// 이도 ci와 유사한 속성이나, 참고로 값만 받고, 인증은 그래도 ci 를 기준으로 함
	private String di;

	@Column(name="kakao_id_name")
	private String kakaoIdName;
	@Column(name="deleted_kakao_id_name")
	private String deletedKakaoIdName;

	@Column(name="naver_id_name")
	private String naverIdName;
	@Column(name="deleted_naver_id_name")
	private String deletedNaverIdName;

	@Column(name="google_id_name")
	private String googleIdName;
	@Column(name="deleted_google_id_name")
	private String deletedGoogleIdName;

	@Column(name="apple_id_name")
	private String appleIdName;
	@Column(name="deleted_apple_id_name")
	private String deletedAppleIdName;

	// 비즈니스 로직 파트
	@Column(name = "current_point")
	private Long currentPoint;



	// 인증 & 인가
	@OneToMany(mappedBy = "customer")
	private final List<CustomerRole> customerRoles = new ArrayList<>();


	@Column(name = "sensitive_info")
	private String sensitiveInfo;

	@Column(name="sensitive_info_updated_at")
	private LocalDateTime sensitiveInfoUpdatedAt;

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

	@Column(name="last_point_expiration_checked_at")
	private LocalDateTime lastPointExpirationCheckedAt;
	
	public void updateCustomer(CustomerReqDTO.Update dto) {
		this.idName = dto.getIdName();
		this.name = dto.getName();
		this.hp = dto.getHp();
		this.email = dto.getEmail();
	}

	public void updateSensitiveInfo(CustomerReqDTO.UpdateSensitiveInfoWithPushAgrees dto) {
		this.sensitiveInfo = dto.getSensitiveInfo();
		this.sensitiveInfoUpdatedAt = LocalDateTime.now();
	}

	public void updatePasswordAndEmail(CustomerReqDTO.UpdatePasswordAndEmail dto) {
		this.password = Password.builder().value(dto.getPassword()).build();
		this.email = dto.getEmail();
	}

	public String getOneWeekAfterDeletedAsString() {

		try {
			// deletedAt 으로부터 정확히 1주일 후의 LocalDateTime 객체를 계산
			LocalDateTime oneWeekAfter = this.deletedAt.plusWeeks(1);

			// 원하는 날짜 및 시간 형식을 지정
			DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

			// LocalDateTime 객체를 지정된 형식의 문자열로 변환
			return oneWeekAfter.format(formatter);
		}catch (Exception e){
			CustomExceptionUtils.createNonStoppableErrorMessage(e.getMessage(), e);
			return null;
		}
	}

}
