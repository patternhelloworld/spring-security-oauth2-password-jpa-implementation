package com.patternknife.securityhelper.oauth2.client.config.response.error;


import com.patternknife.securityhelper.oauth2.api.config.response.error.dto.ErrorResponsePayload;
import com.patternknife.securityhelper.oauth2.api.config.response.error.exception.auth.KnifeOauth2AuthenticationException;
import com.patternknife.securityhelper.oauth2.api.config.response.error.message.SecurityUserExceptionMessage;
import com.patternknife.securityhelper.oauth2.client.config.response.error.dto.CustomErrorResponsePayload;
import com.patternknife.securityhelper.oauth2.client.config.response.error.exception.auth.*;
import com.patternknife.securityhelper.oauth2.client.config.response.error.exception.data.*;

import com.patternknife.securityhelper.oauth2.client.config.response.error.exception.payload.SearchFilterException;

import com.patternknife.securityhelper.oauth2.client.config.response.error.message.GeneralErrorMessage;
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


@ControllerAdvice
public class GlobalExceptionHandler {


    // UserDeletedException : caused by the process of user deactivation
    // UserRestoredException : caused by the process of user reactivation
    @ExceptionHandler({UserDeletedException.class, UserRestoredException.class})
    public ResponseEntity<?> activationException(Exception ex, WebRequest request) {
        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage() != null ? ex.getMessage() : CustomExceptionUtils.getAllCauses(ex),
                request.getDescription(false),ex.getMessage() , ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.FORBIDDEN);
    }


    // 2. data
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<?> resourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {

        CustomErrorResponsePayload customErrorResponsePayload;
        if(ex.getErrorMessages() != null){

            customErrorResponsePayload = new CustomErrorResponsePayload(ex.getErrorMessages(),
                    ex, request.getDescription(false), CustomExceptionUtils.getAllStackTraces(ex),
                    CustomExceptionUtils.getAllCauses(ex), null);

        }else{
            customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false),
                    ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex),
                    CustomExceptionUtils.getAllCauses(ex));
        }
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.NOT_FOUND);

    }
    


    @ExceptionHandler(SearchFilterException.class)
    public ResponseEntity<?> searchFilterException(SearchFilterException ex, WebRequest request) {

        //logger.error(ex.getMessage());
        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getCause().getMessage(), request.getDescription(false),
                ex.getMessage(), ex.getStackTrace()[0].toString());
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.BAD_REQUEST);
    }



    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<?> nullPointerException(NullPointerException ex, WebRequest request) {
        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false),
                GeneralErrorMessage.NULL_VALUE_FOUND.getUserMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.NOT_FOUND);
    }
    




    // 3. Request @Valid
    /* 1. Validating the request body (when not using @RequestParam): Error thrown by @Valid. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> methodArgumentNotValidException(MethodArgumentNotValidException ex, WebRequest request) {

        Map<String, String> userValidationMessages = CustomExceptionUtils.extractMethodArgumentNotValidErrors(ex);

        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false),
                null,
                userValidationMessages,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.UNPROCESSABLE_ENTITY);
    }
    //
    //The types of individual parameters in the request body (String, Date, Integer) are different, or there is a JSON format error.
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<?> httpMessageNotReadableExceptionHandler(HttpMessageNotReadableException ex, WebRequest request) {

        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false),
                "The received form does not match. Please contact the administrator with the following information. (Error details: " + ex.getMostSpecificCause().getMessage() + ")",
                null,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.BAD_REQUEST);
    }

    /* 2-1. In the case of @RequestParam: Validity check thrown by @Validated. */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<?> missingServletRequestParameterException(ConstraintViolationException ex, WebRequest request, HttpServletRequest h) {

        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.UNPROCESSABLE_ENTITY);
    }
    /* 2-2. In the case of @RequestParam: The error thrown when @RequestParam is completely missing in the Controller. */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<?> missingServletRequestParameterException(MissingServletRequestParameterException ex, WebRequest request, HttpServletRequest h) {

        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false),
                "Required parameter (" + ex.getParameterName() + ") is missing.", CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    /* 3. Other Custom Validation: For example, search in the source with @ValidPart.  */
    @ExceptionHandler(BindException.class)
    public ResponseEntity<?> bindExceptionHandler(BindException ex, WebRequest request) {

        Map<String, String> errorMessages = new HashMap<>();

        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            errorMessages.put(fieldError.getField(), fieldError.getDefaultMessage());
        }

        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false), null,
                errorMessages,
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.UNPROCESSABLE_ENTITY);
    }


    // 4. Custom Validation using DB(select)

    @ExceptionHandler(AlreadyExistsException.class)
    public ResponseEntity<?> alreadyExistsException(AlreadyExistsException ex, WebRequest request) {

        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<?> illegalStateException(IllegalStateException ex, WebRequest request) {

        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.BAD_REQUEST);
    }


    @ExceptionHandler(AlreadyInProgressException.class)
    public ResponseEntity<?> alreadyInProgressException(AlreadyInProgressException ex, WebRequest request) {

        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false),
                ex.getMessage(), CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.UNPROCESSABLE_ENTITY);
    }


    // config/resttemplate
    @ExceptionHandler(ResourceAccessException.class)
    public ResponseEntity<?> restTemplateAccessException(ResourceAccessException ex, WebRequest request) {

        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false),
                "We apologize for the inconvenience. The call to the 3rd Party API provider has failed. If the problem persists, please contact customer service.", CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.REQUEST_TIMEOUT);
    }


    // Unhandled
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> unhandledExceptionHandler(Exception ex, WebRequest request) {
        CustomErrorResponsePayload customErrorResponsePayload = new CustomErrorResponsePayload(ex.getMessage(), request.getDescription(false), GeneralErrorMessage.UNHANDLED_ERROR.getUserMessage(),
                CustomExceptionUtils.getAllStackTraces(ex), CustomExceptionUtils.getAllCauses(ex));
        return new ResponseEntity<>(customErrorResponsePayload, HttpStatus.INTERNAL_SERVER_ERROR);
    }



}
