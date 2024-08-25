package com.pbl.starauthserver.utils;

import java.text.Normalizer;
import java.util.regex.Pattern;

public class UsernameGenerator {
    private static final Pattern NON_ASCII_PATTERN = Pattern.compile("[^\\p{ASCII}]");

    public static String generateUniqueName(String name) {
        if (name == null || name.isEmpty()) {
            return "user" + generateUniqueCode();
        }

        String uniqueName = normalize(name).replace(" ", "");
        return (uniqueName + generateUniqueCode()).toLowerCase();
    }

    public static String normalize(String input) {
        String normalized = Normalizer.normalize(input, Normalizer.Form.NFD);
        return NON_ASCII_PATTERN.matcher(normalized).replaceAll("");
    }

    private static String generateUniqueCode() {
        String ALPHA_NUMERIC_STRING = "0123456789";
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 9; i++) {
            int index = (int)(ALPHA_NUMERIC_STRING.length() * Math.random());
            builder.append(ALPHA_NUMERIC_STRING.charAt(index));
        }
        return builder.toString();
    }
}
