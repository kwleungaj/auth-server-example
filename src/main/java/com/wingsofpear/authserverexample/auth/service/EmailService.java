package com.wingsofpear.authserverexample.auth.service;

public interface EmailService {
    void sendOtp(String to, String otp);
}
