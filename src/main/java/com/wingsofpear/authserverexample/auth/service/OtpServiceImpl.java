package com.wingsofpear.authserverexample.auth.service;

import org.springframework.stereotype.Service;

@Service
public class OtpServiceImpl implements OtpService {

    @Override
    public boolean validate(String email, String otp) {
        return true;
    }
}
