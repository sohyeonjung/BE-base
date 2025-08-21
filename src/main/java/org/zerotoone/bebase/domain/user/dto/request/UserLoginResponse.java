package org.zerotoone.bebase.domain.user.dto.request;

import org.zerotoone.bebase.global.security.jwt.JwtToken;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class UserLoginResponse {
	private String grantType;
	private String accessToken;
	private String refreshToken;

	public static UserLoginResponse of(JwtToken jwtToken) {
		return UserLoginResponse.builder()
			.grantType(jwtToken.getGrantType())
			.accessToken(jwtToken.getAccessToken())
			.refreshToken(jwtToken.getRefreshToken())
			.build();
	}
}