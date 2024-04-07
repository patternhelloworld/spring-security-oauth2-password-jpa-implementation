package com.patternknife.securityhelper.oauth2.config.security.principal;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/*
* 	해당 클래스는 다른 프로젝트들이 있을 경우, 동일 하게  com.patternknife.securityhelper.oauth2.interestedtreatmentpart.dto.security 에 위치해야 한다.
* */
public class AccessTokenUserInfo extends User implements OAuth2AuthenticatedPrincipal
{
	public AccessTokenUserInfo(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
	}

	public AccessTokenUserInfo(String username, String password, boolean enabled, boolean accountNonExpired,
							   boolean credentialsNonExpired, boolean accountNonLocked,
							   Collection<? extends GrantedAuthority> authorities) {


		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
	}


	private AdditionalAccessTokenUserInfo additionalAccessTokenUserInfo;

	public AdditionalAccessTokenUserInfo getAdditionalAccessTokenUserInfo() {
		return additionalAccessTokenUserInfo;
	}

	public void setAdditionalAccessTokenUserInfo(AdditionalAccessTokenUserInfo additionalAccessTokenUserInfo) {
		this.additionalAccessTokenUserInfo = additionalAccessTokenUserInfo;
	}

	@Override
	public Map<String, Object> getAttributes() {
		// 권한 목록을 추출하여 Map에 추가
		Map<String, Object> attributes = new HashMap<>();
		List<String> authorities = this.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());
		attributes.put("authorities", authorities);

		// 추가적으로 필요한 사용자 정보를 attributes Map에 추가할 수 있습니다.
		// 예를 들어, 추가 정보가 AdditionalAccessTokenUserInfo 객체에 있다면,
		// 이 정보를 Map에 추가할 수 있습니다.
		if (this.additionalAccessTokenUserInfo != null) {
			// additionalAccessTokenUserInfo의 내용을 Map에 추가하는 로직
			// 예: attributes.put("email", this.additionalAccessTokenUserInfo.getEmail());
		}

		return attributes;
	}

	@Override
	public String getName() {
		return this.getUsername();
	}
}
