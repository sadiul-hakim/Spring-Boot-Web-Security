package com.hakim.accessandrefreshtokensecurity.utility;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.Map;

public class ResponseUtility {
    public static void commitResponse(HttpServletResponse response, Map<String,String> map) throws IOException {

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), map);
    }
}
