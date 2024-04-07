package com.patternknife.securityhelper.oauth2.config.logger.module;

import com.patternknife.securityhelper.oauth2.config.logger.common.CommonLoggingRequest;
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
      // 이 구간에서 오류가 발생하면 서버로 부터 response 200 을 받고도 오류가 발생 함.
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
            (body.length == 0 ? "값이 없습니다." : new String(body, StandardCharsets.UTF_8)) + "\n";
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
