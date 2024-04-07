package com.patternknife.securityhelper.oauth2.config.response.error;


import com.patternknife.securityhelper.oauth2.config.database.SelectablePersistenceConst;
import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorDetails;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.ErrorMessagesContainedException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.*;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.*;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.*;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.*;
import com.patternknife.securityhelper.oauth2.config.response.error.message.GeneralErrorMessage;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.file.FileNotFoundException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.payload.DaouHandledException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.payload.SearchFilterException;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityExceptionMessage;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.transaction.HeuristicCompletionException;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.context.request.WebRequest;

import java.util.HashMap;
import java.util.Map;

@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class GlobalExceptionHandler {

    /*
    *   General
    * */
    // Login Failure
    @ExceptionHandler({InsufficientAuthenticationException.class, UnauthenticatedException.class, AuthenticationException.class})
    public ResponseEntity<?> authenticationException(Exception ex, WebRequest request) {
        ErrorDetails errorDetails;
        if(ex instanceof ErrorMessagesContainedException && ((ErrorMessagesContainedException) ex).getErrorMessages() != null) {
            errorDetails = new ErrorDetails(((ErrorMessagesContainedException) ex).getErrorMessages(),
                    ex, request.getDescription(false), CustomExceptionUtils.getAllStackTraces(ex),
                    CustomExceptionUtils.getAllCauses(ex), null);
        }else {
            errorDetails = new ErrorDetails(CustomExceptionUtils.getAllCauses(ex), request.getDescription(false), SecurityExceptionMessage.AUTHENTICATION_FAILURE.getMessage(),
                    ex.getMessage(), ex.getStackTrace()[0].toString());
        }
        return new ResponseEntity<>(errorDetails, HttpStatus.UNAUTHORIZED);
    }
    // Role (=Permission) Failure
    @ExceptionHandler({UnauthorizedException.class, AccessDeniedException.class, DisabledException.class})
    public ResponseEntity<?> authorizationException(Exception ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage() != null ? ex.getMessage() : CustomExceptionUtils.getAllCauses(ex), request.getDescription(false),
                ex.getMessage() == null ? SecurityExceptionMessage.AUTHENTICATION_ERROR.getMessage() : ex.getMessage(), ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(errorDetails, HttpStatus.FORBIDDEN);
    }
    // Custom or Admin
    @ExceptionHandler({CustomAuthGuardException.class})
    public ResponseEntity<?> customAuthorizationException(Exception ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(CustomExceptionUtils.getAllCauses(ex), request.getDescription(false), SecurityExceptionMessage.AUTHORIZATION_FAILURE.getMessage(),
                ex.getMessage(), ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(errorDetails, HttpStatus.FORBIDDEN);
    }

    /*
    *  Issues with ID, Password
    * */
    @ExceptionHandler({UsernameNotFoundException.class, BadCredentialsException.class})
    public ResponseEntity<?> usernameOrPasswordIssueException(Exception ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(CustomExceptionUtils.getAllCauses(ex), request.getDescription(false), ex.getMessage(),
                ex.getMessage(), ex.getStackTrace()[0].toString());

        return new ResponseEntity<>(errorDetails, HttpStatus.UNAUTHORIZED);
    }

    /*
    *   Social Login (Access Token Failure)
    * */
    // 1. NoSocialRegisteredException: Trying to do social login but the user does not exist (TO DO. Need separation. The app is branching based on the message of this Exception)
    // 2. AlreadySocialRegisteredException: Trying to create a social user but it already exists
    @ExceptionHandler({ AlreadySocialRegisteredException.class, NoSocialRegisteredException.class })
    public ResponseEntity<?> socialLoginFailureException(Exception ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false), ex.getMessage(),
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNAUTHORIZED);
    }
    // SocialEmailNotProvidedException: The app received a 200 status from the social platform using the access token store, but the social platform did not provide the user's email information. In this case, the company needs to obtain authorization from the social platform.
    @ExceptionHandler({ SocialEmailNotProvidedException.class})
    public ResponseEntity<?> accessToSocialSuccessButIssuesWithReturnedValue(Exception ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false), ex.getMessage(),
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.FORBIDDEN);
    }

    // Social Resource Access Failure (Access Token OK but No Permission)
    // The social platform has blocked access to the requested resource.
    @ExceptionHandler({SocialUnauthorizedException.class})
    public ResponseEntity<?> accessToSocialDenied(Exception ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage() != null ? ex.getMessage() : CustomExceptionUtils.getAllCauses(ex),
                request.getDescription(false),"Not a valid access token." , ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(errorDetails, HttpStatus.FORBIDDEN);
    }

    // OTP (Only for Admin)
    @ExceptionHandler({OtpValueUnauthorizedException.class})
    public ResponseEntity<?> otpException(Exception ex, WebRequest request) {

        Map<String, String> userValidationMessages = new HashMap<>();
        userValidationMessages.put("otp_value", ex.getMessage());

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                null,
                userValidationMessages,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));

        return new ResponseEntity<>(errorDetails, HttpStatus.UNAUTHORIZED);
    }

    // UserDeletedException : caused by the process of user deactivation
    // UserRestoredException : caused by the process of user reactivation
    @ExceptionHandler({UserDeletedException.class, UserRestoredException.class})
    public ResponseEntity<?> activationException(Exception ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage() != null ? ex.getMessage() : CustomExceptionUtils.getAllCauses(ex),
                request.getDescription(false),ex.getMessage() , ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(errorDetails, HttpStatus.FORBIDDEN);
    }


    // 2. data
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<?> resourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {

        ErrorDetails errorDetails;
        if(ex.getErrorMessages() != null){

            errorDetails = new ErrorDetails(ex.getErrorMessages(),
                    ex, request.getDescription(false), CustomExceptionUtils.getAllStackTraces(ex),
                    CustomExceptionUtils.getAllCauses(ex), null);

        }else{
            errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                    ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex),
                    CustomExceptionUtils.getAllCauses(ex));
        }
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);

    }
    
    @ExceptionHandler(NoUpdateTargetException.class)
    public ResponseEntity<?> noUpdateTargetException(NoUpdateTargetException ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(SearchFilterException.class)
    public ResponseEntity<?> searchFilterException(SearchFilterException ex, WebRequest request) {

        //logger.error(ex.getMessage());
        ErrorDetails errorDetails = new ErrorDetails(ex.getCause().getMessage(), request.getDescription(false),
                ex.getMessage(), ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }



    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<?> nullPointerException(NullPointerException ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                GeneralErrorMessage.NULL_VALUE_FOUND.getUserMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
    }
    

    @ExceptionHandler(PreconditionFailedException.class)
    public ResponseEntity<?> preconditionFailedException(PreconditionFailedException ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex),
                CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(HeuristicCompletionException.class)
    public ResponseEntity<?> heuristicCompletionException(HeuristicCompletionException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                "JPA 처리되지 않은 오류입니다.", CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(FileNotFoundException.class)
    public ResponseEntity<?> fileNotFoundException(FileNotFoundException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex),
                CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);

    }


    // 3. Request @Valid 와 같은 Spring 자체의 유효성 검증

    /* 1. request body 를 검증( @RequestParam 이 아닌 경우) : @Valid 가 토스 : Throw 되는 오류 */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> methodArgumentNotValidException(MethodArgumentNotValidException ex, WebRequest request) {

        Map<String, String> userValidationMessages = CustomExceptionUtils.extractMethodArgumentNotValidErrors(ex);

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                null,
                userValidationMessages,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }
    // request body 의 개별 파라매터들의 타입 (String, Date, Integer) 이 다르거나, json 양식 오류.
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<?> httpMessageNotReadableExceptionHandler(HttpMessageNotReadableException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                "전달 받은 양식이 일치하지 않습니다. 다음 내용을 관리자에게 문의하십시오. (오류 내용 : " + ex.getMostSpecificCause().getMessage() + ")",
                null,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    /* 2-1. @RequestParam 인 경우 : @Validated 가 토스 : 유효성 검사  */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<?> missingServletRequestParameterException(ConstraintViolationException ex, WebRequest request, HttpServletRequest h) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }
    /* 2-2. @RequestParam 인 경우 : Contoller 의 @RequestParam 이 아예 없을 경우 Throw 되는 오류 */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<?> missingServletRequestParameterException(MissingServletRequestParameterException ex, WebRequest request, HttpServletRequest h) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                "필수 파라매터 (" + ex.getParameterName()  + ") 항목이 없습니다.", CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    /* 3. 기타 Custom Validation : ex) @ValidPart 로 소스에서 검색  */
    @ExceptionHandler(BindException.class)
    public ResponseEntity<?> bindExceptionHandler(BindException ex, WebRequest request) {

        Map<String, String> errorMessages = new HashMap<>();

        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            errorMessages.put(fieldError.getField(), fieldError.getDefaultMessage());
        }

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false), null,
                errorMessages,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }


    // 4. DB에서 조회(select) 에서 유효성을 검사

    @ExceptionHandler(AlreadyExistsException.class)
    public ResponseEntity<?> alreadyExistsException(AlreadyExistsException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<?> illegalStateException(IllegalStateException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }


    @Value("${spring.jpa.properties.hibernate.dialect}")
    String dbDialect;
    /*
    *   5. DB 레이어에서 토스하는 유효성
    *     - 양/음수, Unique Key 등과 같은 동시성 문제를 방지하는 조건들로 유효성을 검사. (1차적으로는 select 문을 사용하는 것을 권장)
    * */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<?> dataIntegrityViolationException(DataIntegrityViolationException ex, WebRequest request) {
        //DataIntegrityViolationException - 데이터의 삽입/수정이 무결성 제약 조건을 위반할 때 발생하는 예외이다.
        //logger.error(ex.getMessage());

        Map<String, String> userValidationMessages = null;
        String userMessage = null;

        /*  1. POINT 컬럼은 부호 없음으로 해서 음수를 막음. */
        String signedErrorMsg = dbDialect.equals(SelectablePersistenceConst.MYSQL_8.getValue()) ?
                "Data truncation: Out of range value for column 'current_point' at row 1" :
                "CK__customer__current_point";
        /* 2. FK ON delete restrict 를 걸이서 사용중인 항목 삭제 금지 */
        String deleteConstraintKeyErrorMsg = dbDialect.equals(SelectablePersistenceConst.MYSQL_8.getValue()) ?
                "Cannot delete or update a parent row: a foreign key constraint fails" :
                "Arithmetic overflow error";

        if(ex.getMostSpecificCause().getMessage() != null
                    && ex.getMostSpecificCause().getMessage().contains(signedErrorMsg)){
            /* Data truncation: Out of range value for column 'current_point' at row 1 */
            /* Customer 테이블에서 point 컬럼이 음수가 될 경우 exception */
            /* PointDetailRepositorySupport 클래스의 주석 참조 */
            userValidationMessages = new HashMap<>();
            userValidationMessages.put("point", "포인트가 부족합니다.");

        }else if(ex.getMostSpecificCause().getMessage() != null
                && ex.getMostSpecificCause().getMessage().contains(deleteConstraintKeyErrorMsg)){
            userValidationMessages = new HashMap<>();
            userValidationMessages.put("id", "다른 곳에서 사용 중이라 삭제가 불가합니다.");

        }else{
            /*  UNIQUE, NULL */
            if(dbDialect.equals(SelectablePersistenceConst.MYSQL_8.getValue())) {
                // 1. UNIQUE 부터 검사
                userValidationMessages = CustomExceptionUtils.convertDataIntegrityExceptionMessageToObjMySql(ex.getMessage());
                if (userValidationMessages == null) {
                    // 2. NULL 값에 해당하는 오류
                    userMessage = GeneralErrorMessage.NULL_VALUE_FOUND.getMessage();
                    userValidationMessages = null;
                }
            }else{
                if(ex.getMostSpecificCause().getMessage() != null){
                    userValidationMessages = CustomExceptionUtils.convertDataIntegrityExceptionMessageToObjMSSql(ex.getMostSpecificCause().getMessage());
                    if (userValidationMessages == null) {
                        // 2. NULL 값에 해당하는 오류
                        userMessage = GeneralErrorMessage.NULL_VALUE_FOUND.getMessage();
                        userValidationMessages = null;
                    }
                }
            }
        }

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                userMessage,
                userValidationMessages,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));

        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(AlreadyInProgressException.class)
    public ResponseEntity<?> alreadyInProgressException(AlreadyInProgressException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    // 기프트-포인트 전용 (중요도 높아서 별도로...)

/*    @ExceptionHandler(CustomerGiftRequestStatusUpdateException.class)
    public ResponseEntity<?> customerGiftRequestStatusUpdateException(CustomerGiftRequestStatusUpdateException ex, WebRequest request, HttpServletRequest h) {

        Map<String, String> userValidationMessages = new HashMap<>();

        userValidationMessages.put("", ex.getMessage());

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                null,
                userValidationMessages,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }*/

    @ExceptionHandler(DaouHandledException.class)
    public ResponseEntity<?> daouRequestException(DaouHandledException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    // config/resttemplate 참조
    @ExceptionHandler(ResourceAccessException.class)
    public ResponseEntity<?> restTemplateAccessException(ResourceAccessException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                "불편을 끼쳐 드려 송구합니다. 3rd Party API 제공 업체의 호출에 실패하였습니다. 문제가 지속되면 고객센터에 문의 주십시오.", CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.REQUEST_TIMEOUT);
    }


    // 마지막 : Unhandled
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> unhandledExceptionHandler(Exception ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false), GeneralErrorMessage.UNHANDLED_ERROR.getUserMessage(),
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }

/*    @ExceptionHandler(value = .class)
    public @ResponseBody
    ResponseEntity<?> validationRuntimeExceptionHandler(WebRequest request, Exception ex) {
        ex.printStackTrace();
          = () ex;
        String middle = "이(가) ";
        String suffix = StringUtils.isEmpty(.getMessage()) ? .DEFAULT_MESSAGE : .getMessage();
        String message = StringUtils.isEmpty(.getField()) ? .DEFAULT_MESSAGE : String.format("%s%s%s", .getField(), middle, suffix);
        ErrorDetails errorDetails = new ErrorDetails(new Date(), message, request.getDescription(false), message,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }*/

}
