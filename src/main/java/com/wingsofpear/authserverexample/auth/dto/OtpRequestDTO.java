package com.wingsofpear.authserverexample.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class OtpRequestDTO {
    @Email(message = "must be a well‑formed email address")
    @NotBlank(message = "email is required")
    private String email;
}
