package org.zerotoone.bebase.domain.user.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.zerotoone.bebase.domain.user.application.UserService;
import org.zerotoone.bebase.domain.user.dto.request.RefreshTokenRequest;
import org.zerotoone.bebase.domain.user.dto.request.UserLoginRequest;
import org.zerotoone.bebase.domain.user.dto.request.UserLoginResponse;
import org.zerotoone.bebase.domain.user.dto.request.UserRegisterRequest;
import org.zerotoone.bebase.global.common.ApiResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;

	@PostMapping("/register")
	public ResponseEntity<ApiResponse<Void>> register(
		@RequestBody @Valid UserRegisterRequest userRegisterRequest
	) {
		userService.register(userRegisterRequest);
		return ResponseEntity.ok(ApiResponse.success());
	}

	@PostMapping("/login")
	public ResponseEntity<ApiResponse<UserLoginResponse>> login(
		@RequestBody @Valid UserLoginRequest userLoginRequest
	) {
		UserLoginResponse loginResponse = userService.login(userLoginRequest);
		return ResponseEntity.ok(ApiResponse.success(loginResponse));
	}

	@PostMapping("/reissue")
	public ResponseEntity<ApiResponse<UserLoginResponse>> reissue(
		@RequestBody @Valid RefreshTokenRequest refreshTokenRequest
	) {
		UserLoginResponse newTokens = userService.reissue(refreshTokenRequest.getRefreshToken());
		return ResponseEntity.ok(ApiResponse.success(newTokens));
	}

	@GetMapping("/test")
	public ResponseEntity<ApiResponse<Void>> test() {
		return ResponseEntity.ok(ApiResponse.success());
	}
}
