package com.wingsofpear.authserverexample.auth.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.time.Duration;

import static com.wingsofpear.authserverexample.common.util.OtpUtil.generateOtp;

@Service
public class OtpServiceImpl implements OtpService {
    private final int CODE_LENGTH;
    private final Duration OTP_VALIDITY;
    private final RedisTemplate<String, String> redisTemplate;

    public OtpServiceImpl(RedisTemplate<String, String> redisTemplate,
                          @Value("${app.auth.otp.ttl-minutes}") int ttlMinutes,
                          @Value("${app.auth.otp.code-length}") int codeLength
    ) {
        this.redisTemplate = redisTemplate;
        this.CODE_LENGTH = codeLength;
        this.OTP_VALIDITY = Duration.ofMinutes(ttlMinutes);
    }

    @Override
    public boolean validateOtp(String email, String otp) {
        String storedOtp = redisTemplate.opsForValue().get(email);
        return otp != null && otp.equals(storedOtp);
    }

    @Override
    public String requestOtp(String email) {
        Assert.hasText(email, "email cannot be empty");
        String otp = generateOtp(CODE_LENGTH);
        redisTemplate.opsForValue().set(email, otp, OTP_VALIDITY);
        return otp;
    }

    public void clearOtp(String email) {
        redisTemplate.delete(email);
    }
}
