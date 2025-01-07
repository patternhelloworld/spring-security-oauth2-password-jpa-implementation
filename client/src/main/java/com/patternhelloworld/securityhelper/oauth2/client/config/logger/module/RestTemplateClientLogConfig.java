package com.patternhelloworld.securityhelper.oauth2.client.config.logger.module;

import com.patternhelloworld.securityhelper.oauth2.client.config.logger.common.CommonLoggingRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.lang.NonNull;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;


public class RestTemplateClientLogConfig implements ClientHttpRequestInterceptor {

  private static final Logger logger = LoggerFactory.getLogger(RestTemplateClientLogConfig.class);

  @NonNull
  @Override
  public ClientHttpResponse intercept(@NonNull final HttpRequest request,
      @NonNull final byte[] body, final @NonNull ClientHttpRequestExecution execution)
      throws IOException {

    loggingRequest(request, body);

    ClientHttpResponse response = execution.execute(request, body);

    try {
      loggingResponse(response);
    }catch (Exception e){
        logger.error(e.getMessage());
    }


    return response;
  }

  private void loggingRequest(final HttpRequest request, byte[] body) {

    CommonLoggingRequest commonLoggingRequest = new CommonLoggingRequest();
    String loggedText = commonLoggingRequest.getText();

    loggedText += "\n======Request to Server====== (Thread ID : " + Thread.currentThread().getId() + ")\n";
    loggedText += "Headers: " + request.getHeaders() + "\n";
    loggedText += "Request Method: " + request.getMethod() + "\n";
    loggedText += "Request URI: " + request.getURI() + "\n";
    loggedText += "Request body: " +
            (body.length == 0 ? "No body value" : new String(body, StandardCharsets.UTF_8)) + "\n";
    loggedText += "======Request to Server======\n";

    logger.trace(loggedText);
  }

  private void loggingResponse(ClientHttpResponse response) throws IOException {

    CommonLoggingRequest commonLoggingRequest = new CommonLoggingRequest();
    String loggedText = commonLoggingRequest.getText();

    final String body = getBody(response);

    loggedText += "\n======Response from Server====== (Thread ID : " + Thread.currentThread().getId() + ")\n";
    loggedText += "Headers: " + response.getHeaders() + "\n";
    loggedText += "Response Status : " + response.getRawStatusCode() + "\n";
    loggedText += "Response body: " + body + "\n";
    loggedText += "======Response from Server======\n";

    logger.trace(loggedText);
  }


  private String getBody(@NonNull final ClientHttpResponse response) throws IOException {
    try (BufferedReader br = new BufferedReader(new InputStreamReader(response.getBody()))) {
      return br.readLine();
    }
  }


}
