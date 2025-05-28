package com.wingsofpear.authserverexample.common.util;

import java.security.SecureRandom;

public class OtpUtil {
    public static String generateOtp(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < length; i++) {
            otp.append(random.nextInt(10));
        }
        return otp.toString();
    }
}
