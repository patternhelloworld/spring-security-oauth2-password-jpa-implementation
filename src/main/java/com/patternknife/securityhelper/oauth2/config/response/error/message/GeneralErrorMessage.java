package com.patternknife.securityhelper.oauth2.config.response.error.message;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum GeneralErrorMessage {

    UNHANDLED_ERROR("G_000", "처리되지 않은 오류 입니다.","불편을 끼쳐드려 송구합니다. 재시도 해도 문제가 지속될 경우 관리자에게 문의 하십시오. 로그 확인이 필요합니다.", HttpStatus.INTERNAL_SERVER_ERROR),

    NULL_VALUE_FOUND("G_001", "빈 값이 확인되었습니다.", "불편을 끼쳐드려 송구합니다. 재시도 해도 문제가 지속될 경우 관리자에게 문의 하십시오. 로그 확인이 필요합니다.", HttpStatus.BAD_REQUEST),
    DUPLICATE_VALUE_FOUND("G_002", "중복된 값이 확인 되었습니다.","중복된 값이 확인 되었습니다.",  HttpStatus.CONFLICT),
    INPUT_VALUE_INVALID("G_003", "입력값이 올바르지 않습니다.","입력값이 올바르지 않습니다.", HttpStatus.BAD_REQUEST),

    ACCOUNT_NOT_FOUND("S_000", "해당 회원을 찾을 수 없습니다.","해당 회원을 찾을 수 없습니다.", HttpStatus.NOT_FOUND),
    EMAIL_DUPLICATION("S_001", "이메일이 중복되었습니다.","이메일이 중복되었습니다.", HttpStatus.CONFLICT),
    PASSWORD_FAILED_EXCEEDED("S_002", "비밀번호 실패 횟수가 초과했습니다.","비밀번호 실패 횟수가 초과했습니다.", HttpStatus.BAD_REQUEST);


    private final String code;
    private final String message;
    private final String userMessage;
    private final HttpStatus status;

    GeneralErrorMessage(String code, String message, String userMessage, HttpStatus status) {
        this.code = code;
        this.message = message;
        this.userMessage = userMessage;
        this.status = status;
    }

}
