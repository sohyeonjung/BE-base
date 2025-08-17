package org.zerotoone.bebase.global.exception;

import org.springframework.http.HttpStatus;

import lombok.Getter;

@Getter
public enum ErrorCode {

	// Bad Request
	BAD_REQUEST("C001", "잘못된 요청입니다.", HttpStatus.BAD_REQUEST),
	INVALID_INPUT_VALUE("C002", "유효하지 않은 입력 값입니다.", HttpStatus.BAD_REQUEST),
	INVALID_TYPE_VALUE("C003", "요청 데이터 타입이 올바르지 않습니다.", HttpStatus.BAD_REQUEST),
	MISSING_REQUIRED_FIELD("C004", "필수 입력 항목이 누락되었습니다.", HttpStatus.BAD_REQUEST),

	// HTTP 401 Unauthorized
	UNAUTHORIZED_ACCESS("C101", "인증 정보가 유효하지 않습니다.", HttpStatus.UNAUTHORIZED),
	TOKEN_EXPIRED("C102", "인증 토큰이 만료되었습니다.", HttpStatus.UNAUTHORIZED),
	INVALID_TOKEN("C103", "유효하지 않은 인증 토큰입니다.", HttpStatus.UNAUTHORIZED),
	ACCESS_TOKEN_BLACKLISTED("C104", "블랙리스트에 등록된 토큰입니다.", HttpStatus.UNAUTHORIZED),

	// HTTP 403 Forbidden
	FORBIDDEN_ACCESS("C201", "접근 권한이 없습니다.", HttpStatus.FORBIDDEN),

	// Internal Server Error
	INTERNAL_SERVER_ERROR("C999", "서버 내부 오류가 발생했습니다.", HttpStatus.INTERNAL_SERVER_ERROR),
	EXTERNAL_SERVICE_ERROR("C901", "외부 서비스 연동 중 오류가 발생했습니다.", HttpStatus.INTERNAL_SERVER_ERROR),

	// User
	USER_NOT_FOUND("U001", "사용자를 찾을 수 없습니다.", HttpStatus.NOT_FOUND),
	EMAIL_DUPLICATION("U002", "이미 사용 중인 이메일입니다.", HttpStatus.CONFLICT),
	NICKNAME_DUPLICATION("U003", "이미 사용 중인 이름입니다.", HttpStatus.CONFLICT),
	PASSWORD_MISMATCH("U004", "비밀번호가 일치하지 않습니다.", HttpStatus.BAD_REQUEST),
	USER_UPDATE_FAILED("U005", "사용자 정보 수정에 실패했습니다.", HttpStatus.INTERNAL_SERVER_ERROR)
	;

	private final HttpStatus status;
	private final String code;
	private String message;

	ErrorCode(final String code, final String message, final HttpStatus status) {
		this.status = status;
		this.code = code;
		this.message = message;
	}
}
