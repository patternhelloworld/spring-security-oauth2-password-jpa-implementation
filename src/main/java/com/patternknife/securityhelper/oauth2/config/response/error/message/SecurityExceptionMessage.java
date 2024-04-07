package com.patternknife.securityhelper.oauth2.config.response.error.message;


public enum SecurityExceptionMessage implements ExceptionMessageInterface {

    // GENERAL (Failure : errors that customers need to recognize / Error : system errors that customers shouldn't understand.)
    AUTHENTICATION_FAILURE("인증이 해제되었습니다. 다시 로그인을 진행해주세요."),
    AUTHENTICATION_ERROR("인증 상의 오류가 발생하였습니다. 문제가 지속되면 고객센터에 문의 바랍니다."),
    AUTHORIZATION_FAILURE("접근 권한이 없습니다. 관리자에게 요청하십시오."),
    AUTHORIZATION_ERROR("접근 권한 상의 오류가 발생하였습니다. 문제가 지속되면 고객센터에 문의 바랍니다."),

    // OTP
    OTP_NOT_FOUND("OTP 값이 확인되지 않습니다."),
    OTP_MISMATCH("현재 OTP 값이 만료되어 입력하신 OTP 값과 서버 OTP 값이 일치하지 않습니다. 재입력 하십시오."),

    // ID PASSWORD
    ID_NO_EXISTS("해당 아이디가 존재하지 않습니다."),
    WRONG_ID_PASSWORD("사용자 정보가 확인 되지 않습니다. ID 또는 비밀번호를 확인하십시오. 문제가 지속된다면 고객센터에 문의주십시오."),
    PASSWORD_FAILED_EXCEEDED( "비밀번호 실패 횟수가 초과했습니다.");

    private String message;

    @Override
    public String getMessage() {
        return message;
    }

    SecurityExceptionMessage(String message) {
        this.message = message;
    }

}
