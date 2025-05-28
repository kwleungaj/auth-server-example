package com.wingsofpear.authserverexample.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {
    private final int TTL_MINUTES;
    private final JavaMailSender mailSender;

    public EmailServiceImpl(JavaMailSender mailSender,
                            @Value("${app.auth.otp.ttl-minutes}") int ttlMinutes
    ) {
        this.mailSender = mailSender;
        this.TTL_MINUTES = ttlMinutes;
    }

    @Override
    public void sendOtp(String to, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Your OTP Code");
        message.setText("Your one-time password is: " + otp + "\nThis OTP will expire in " + TTL_MINUTES + " minutes.");
        mailSender.send(message);
    }
}
