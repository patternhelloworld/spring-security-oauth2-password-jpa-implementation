package com.patternhelloworld.securityhelper.oauth2.client;

import org.assertj.core.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class SpringSecurityOauth2PasswordJpaImplApplicationTests {

	@Autowired
	private TestRestTemplate restTemplate;

	@Test
	public void contextLoads() {

	}

	private Boolean checkProfileValidation(String profile) {
		String[] profiles = new String[]  {"local", "alpha", "production"};
		return Arrays.asList(profiles).contains(profile);

	}
}
