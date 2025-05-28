package com.wingsofpear.authserverexample.auth.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.time.Duration;

import static com.wingsofpear.authserverexample.common.util.OtpUtil.generateOtp;

@Service
public class OtpServiceImpl implements OtpService {
    private final RedisTemplate<String, String> redisTemplate;
    private final Duration OTP_VALIDITY = Duration.ofMinutes(5);

    public OtpServiceImpl(RedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public boolean validateOtp(String email, String otp) {
        String storedOtp = redisTemplate.opsForValue().get(email);
        return otp != null && otp.equals(storedOtp);
    }

    @Override
    public String requestOtp(String email) {
        Assert.hasText(email, "email cannot be empty");
        String otp = generateOtp(6);
        redisTemplate.opsForValue().set(email, otp, OTP_VALIDITY);
        return otp;
    }

    public void clearOtp(String email) {
        redisTemplate.delete(email);
    }
}
