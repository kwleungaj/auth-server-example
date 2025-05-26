package com.wingsofpear.authserverexample.auth.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.wingsofpear.authserverexample.auth.entity.User;
import lombok.Data;

import java.time.Instant;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class UserResponseDTO {
    private String email;
    private String firstName;
    private String lastName;
    private Instant lastLoginAt;

    public UserResponseDTO(User user) {
        this.email = user.getEmail();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.lastLoginAt = user.getLastLoginAt();
    };
}
