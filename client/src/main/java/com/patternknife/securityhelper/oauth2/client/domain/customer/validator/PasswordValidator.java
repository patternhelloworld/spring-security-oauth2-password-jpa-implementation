package com.patternknife.securityhelper.oauth2.client.domain.customer.validator;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.stereotype.Component;

import java.text.MessageFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class PasswordValidator implements ConstraintValidator<Password, String> {

    private static final int MIN_SIZE = 9;
    private static final int MAX_SIZE = 20;
    private static final String regexPassword = "^(?=.*[A-Za-z])(?=.*[0-9])(?=.*[$@!%*#?&])[A-Za-z[0-9]$@!%*#?&]{" + MIN_SIZE
            + "," + MAX_SIZE + "}$";
    private static final String regexConsecutiveNumber = "([0-9])\\1";

    @Override
    public void initialize(Password constraintAnnotation) {
    }

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        boolean isValidPassword = password.matches(regexPassword) && !findConsecutiveNumber(password);
        if (!isValidPassword) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(
                    MessageFormat.format("Please enter a password that includes numbers, letters, and special characters of at least {0} characters and no more than {1} characters, and is not a sequence of consecutive numbers.", MIN_SIZE, MAX_SIZE))
                    .addConstraintViolation();
        }
        return isValidPassword;
    }

    private boolean findConsecutiveNumber(String password){
        Pattern pattern = Pattern.compile(regexConsecutiveNumber);
        Matcher matcher = pattern.matcher(password);
        return matcher.find();
    }
}