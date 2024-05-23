package com.patternknife.securityhelper.oauth2.config.response.error;


import com.patternknife.securityhelper.oauth2.config.logger.dto.ErrorDetails;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.ErrorMessagesContainedExceptionForSecurityAuthentication;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.auth.*;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.data.*;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.file.FileNotFoundException;
import com.patternknife.securityhelper.oauth2.config.response.error.exception.payload.SearchFilterException;
import com.patternknife.securityhelper.oauth2.config.response.error.message.GeneralErrorMessage;
import com.patternknife.securityhelper.oauth2.config.response.error.message.SecurityExceptionMessage;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
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
        if(ex instanceof ErrorMessagesContainedExceptionForSecurityAuthentication && ((ErrorMessagesContainedExceptionForSecurityAuthentication) ex).getErrorMessages() != null) {
            errorDetails = new ErrorDetails(((ErrorMessagesContainedExceptionForSecurityAuthentication) ex).getErrorMessages(),
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
                ex.getMessage() == null || ex.getMessage().equals("Access Denied") ? SecurityExceptionMessage.AUTHORIZATION_FAILURE.getMessage() : ex.getMessage(), ex.getStackTrace()[0].toString());
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
                GeneralErrorMessage.UNHANDLED_ERROR.getUserMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(FileNotFoundException.class)
    public ResponseEntity<?> fileNotFoundException(FileNotFoundException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex),
                CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);

    }


    // 3. Request @Valid
    /* 1. Validating the request body (when not using @RequestParam): Error thrown by @Valid. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> methodArgumentNotValidException(MethodArgumentNotValidException ex, WebRequest request) {

        Map<String, String> userValidationMessages = CustomExceptionUtils.extractMethodArgumentNotValidErrors(ex);

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                null,
                userValidationMessages,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }
    //
    //The types of individual parameters in the request body (String, Date, Integer) are different, or there is a JSON format error.
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<?> httpMessageNotReadableExceptionHandler(HttpMessageNotReadableException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                "The received form does not match. Please contact the administrator with the following information. (Error details: " + ex.getMostSpecificCause().getMessage() + ")",
                null,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }

    /* 2-1. In the case of @RequestParam: Validity check thrown by @Validated. */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<?> missingServletRequestParameterException(ConstraintViolationException ex, WebRequest request, HttpServletRequest h) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }
    /* 2-2. In the case of @RequestParam: The error thrown when @RequestParam is completely missing in the Controller. */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<?> missingServletRequestParameterException(MissingServletRequestParameterException ex, WebRequest request, HttpServletRequest h) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                "Required parameter (" + ex.getParameterName() + ") is missing.", CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    /* 3. Other Custom Validation: For example, search in the source with @ValidPart.  */
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


    // 4. Custom Validation using DB(select)

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


    @ExceptionHandler(AlreadyInProgressException.class)
    public ResponseEntity<?> alreadyInProgressException(AlreadyInProgressException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.UNPROCESSABLE_ENTITY);
    }


    // config/resttemplate
    @ExceptionHandler(ResourceAccessException.class)
    public ResponseEntity<?> restTemplateAccessException(ResourceAccessException ex, WebRequest request) {

        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false),
                "We apologize for the inconvenience. The call to the 3rd Party API provider has failed. If the problem persists, please contact customer service.", CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.REQUEST_TIMEOUT);
    }


    // Unhandled
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> unhandledExceptionHandler(Exception ex, WebRequest request) {
        ErrorDetails errorDetails = new ErrorDetails(ex.getMessage(), request.getDescription(false), GeneralErrorMessage.UNHANDLED_ERROR.getUserMessage(),
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }



}
