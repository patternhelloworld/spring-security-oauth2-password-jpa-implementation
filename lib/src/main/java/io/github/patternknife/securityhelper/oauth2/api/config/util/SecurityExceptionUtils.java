package io.github.patternknife.securityhelper.oauth2.api.config.util;

import org.slf4j.Logger;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.function.Supplier;

public class SecurityExceptionUtils {

    public static <T> T retryOnDuplicateException(Supplier<T> action, int maxRetries, Logger logger, String errorMessage) {
        int attempt = 0;
        while (attempt < maxRetries) {
            try {
                return action.get();
            } catch (DataIntegrityViolationException e) {
                logger.error(String.format("%s... Retrying up to %d times.... (Count: %d) - %s", errorMessage, maxRetries, attempt, e.getMessage()));
                attempt++;
                if (attempt == maxRetries) {
                    throw e;
                }
            }
        }
        return null;
    }
}
