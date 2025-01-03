package com.patternknife.securityhelper.oauth2.client.config.securityimpl.guard;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/*
* 	If you are using another Resource server, this class must also be located in com.patternknife.securityhelper.oauth2.interestedtreatmentpart.dto.security.
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
		Map<String, Object> attributes = new HashMap<>();
		List<String> authorities = this.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toList());
		attributes.put("authorities", authorities);

		return attributes;
	}

	@Override
	public String getName() {
		return this.getUsername();
	}
}
