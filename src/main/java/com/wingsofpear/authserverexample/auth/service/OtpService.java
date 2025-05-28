package com.wingsofpear.authserverexample.auth.service;

public interface OtpService {
    boolean validateOtp(String email, String otp);

    String requestOtp(String email);

    void clearOtp(String email);
}
