package com.wingsofpear.authserverexample.common.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ApiResponseDTO<T> {
    private T data;
    private String error;
    private String message;

    public static <T> ApiResponseDTO<T> success(T data) {
        return new ApiResponseDTO<>(data, null, "success");
    }
    public static <T> ApiResponseDTO<T> fail(String errorCode, String errorMessage) {
        return new ApiResponseDTO<>(null, errorCode, errorMessage);
    }
    public static <T> ApiResponseDTO<T> failWithSupplementData(T data, String errorCode, String errorMessage) {
        return new ApiResponseDTO<>(data, errorCode, errorMessage);
    }
}
