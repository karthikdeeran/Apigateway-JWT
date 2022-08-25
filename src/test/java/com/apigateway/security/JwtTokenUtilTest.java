package com.apigateway.security;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import com.apigateway.config.JwtConfig;
import com.apigateway.exception.JwtTokenIncorrectStructureException;
import com.apigateway.exception.JwtTokenMalformedException;
import com.apigateway.exception.JwtTokenMissingException;
import com.apigateway.security.JwtTokenUtil;

@ExtendWith(MockitoExtension.class)
class JwtTokenUtilTest {

	@Mock
	JwtConfig config;
	private JwtTokenUtil tokenUtil;

	@BeforeEach
	public void setup() {
		tokenUtil = new JwtTokenUtil(config);
	}

	@Test
	@DisplayName("Generate a valid JWT authentication token test.")
	void generateToken_ValidConfig() {
		Mockito.when(config.getSecret()).thenReturn("testing");
		Mockito.when(config.getValidity()).thenReturn((long) 20);

		String token = tokenUtil.generateToken("test");
		Assertions.assertNotNull(token);
		Assertions.assertTrue(token.length() > 0);
	}

	@Test
	@DisplayName("Validate a malformed token test.")
	void validateToken_Malformed() {
		Mockito.when(config.getSecret()).thenReturn("testing");

		Assertions.assertThrows(JwtTokenMalformedException.class, () -> tokenUtil.validateToken("Bearer qwerty"),
				"JwtTokenMalformedException was expected");
	}

	@Test
	@DisplayName("Validate incorrect structure token test.")
	void validateToken_IncorrectStructure() {
		Assertions.assertThrows(JwtTokenIncorrectStructureException.class, () -> tokenUtil.validateToken("foo"),
				"JwtTokenIncorrectStructureException was expected");
	}

	@DisplayName("Validate missing token test.")
	void validateToken_TokenMissing() {
		Assertions.assertThrows(JwtTokenMissingException.class, () -> tokenUtil.validateToken("Bearer Foo"),
				"JwtTokenMissingException was expected");
	}
}