package org.zerotoone.bebase.domain.user.application;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.zerotoone.bebase.domain.user.domain.User;
import org.zerotoone.bebase.domain.user.dto.request.UserLoginRequest;
import org.zerotoone.bebase.domain.user.dto.request.UserLoginResponse;
import org.zerotoone.bebase.domain.user.dto.request.UserRegisterRequest;
import org.zerotoone.bebase.domain.user.infrastructure.UserRepository;
import org.zerotoone.bebase.global.exception.CustomException;
import org.zerotoone.bebase.global.exception.ErrorCode;
import org.zerotoone.bebase.global.security.jwt.JwtToken;
import org.zerotoone.bebase.global.security.jwt.JwtTokenProvider;
import org.zerotoone.bebase.global.util.RedisUtil;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserService {

	private final UserRepository userRepository;
	private final RedisUtil redisUtil;
	private final PasswordEncoder passwordEncoder;
	private final JwtTokenProvider jwtTokenProvider;
	private final AuthenticationManager authenticationManager;

	private final Long EXPIRATION = 10 * 60L;
	private final Long REFRESH_TOKEN_EXPIRE_SECONDS = 7 * 24 * 60 * 60L;

	@Transactional
	public void register(UserRegisterRequest userRegisterRequest) {
		userRepository.findByEmail(userRegisterRequest.getEmail()).ifPresent(it -> {
			throw new CustomException(ErrorCode.EMAIL_DUPLICATION);
		});

		userRepository.findByName(userRegisterRequest.getName()).ifPresent(it -> {
			throw new CustomException(ErrorCode.NICKNAME_DUPLICATION);
		});

		String encodedPassword = passwordEncoder.encode(userRegisterRequest.getPassword());
		User user = User.create(userRegisterRequest.getEmail(), encodedPassword, userRegisterRequest.getName());
		userRepository.save(user);
	}

	@Transactional
	public UserLoginResponse login(UserLoginRequest userLoginRequest) {
		User user = userRepository.findByEmail(userLoginRequest.getEmail())
			.orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

		UsernamePasswordAuthenticationToken authenticationToken =
			new UsernamePasswordAuthenticationToken(userLoginRequest.getEmail(), userLoginRequest.getPassword());

		try {
			Authentication authentication = authenticationManager.authenticate(authenticationToken);
			JwtToken jwtToken = jwtTokenProvider.generateToken(authentication);
			redisUtil.setDataExpire(authentication.getName(), jwtToken.getRefreshToken(), REFRESH_TOKEN_EXPIRE_SECONDS);

			return UserLoginResponse.of(jwtToken);
		} catch (BadCredentialsException e) {
			log.error("login error: not valid password");
			throw new CustomException(ErrorCode.PASSWORD_MISMATCH);
		} catch (Exception e) {
			log.error("server error: {} ", e);
			throw new CustomException(ErrorCode.INTERNAL_SERVER_ERROR);
		}
	}

}
