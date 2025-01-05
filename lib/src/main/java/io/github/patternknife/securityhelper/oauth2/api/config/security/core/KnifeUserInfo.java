package io.github.patternknife.securityhelper.oauth2.api.config.security.core;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The {@code KnifeUserInfo} class extends {@link User} and implements {@link OAuth2AuthenticatedPrincipal}.
 * This class is designed to serve as both a {@link org.springframework.security.core.userdetails.UserDetails}
 * and an {@link OAuth2AuthenticatedPrincipal}.
 *
 * @param <T> the type of customizable user information to be associated with the authenticated user.
 *
 * Although this is located in the core folder, its usage is optional and will not impact functionality if omitted.
 */
public class KnifeUserInfo<T> extends User implements OAuth2AuthenticatedPrincipal {

	private T customizedUserInfo;
	public T getCustomizedUserInfo() {
		return customizedUserInfo;
	}
	public void setCustomizedUserInfo(T customizedUserInfo) {
		this.customizedUserInfo = customizedUserInfo;
	}

	public KnifeUserInfo(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
	}

	public KnifeUserInfo(String username, String password, boolean enabled, boolean accountNonExpired,
						 boolean credentialsNonExpired, boolean accountNonLocked,
						 Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
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
