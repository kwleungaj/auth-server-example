package com.wingsofpear.authserverexample.auth.service;

public interface OtpService {
    boolean validate(String email, String otp);
}
