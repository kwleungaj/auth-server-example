package com.wingsofpear.authserverexample.config;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Jackson mix-in for CustomUserDetails to enable polymorphic type handling
 * and define how to instantiate it during deserialization.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY,
        getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class CustomUserDetailsMixin {

    /**
     * Constructor parameters map to JSON properties.
     * Jackson uses this to create a CustomUserDetails instance.
     */
    @JsonCreator
    public CustomUserDetailsMixin(
            @JsonProperty("id")       Long id,
            @JsonProperty("username") String username,
            @JsonProperty("password") String password
    ) {
        // no-op: mix-in only provides annotation metadata
    }
}
