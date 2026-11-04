package com.zerotrust.util;

import java.security.SecureRandom;

import com.zerotrust.exception.ApiException;

/**
 * Password strength rules: 8-128 characters with upper-case, lower-case,
 * digit and special character, and not containing the username.
 */
public final class PasswordPolicy {

    public static final String DESCRIPTION = "Password must be 8-128 characters and include upper-case, "
            + "lower-case, a digit and a special character, and must not contain the username.";

    private static final String UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private static final String LOWER = "abcdefghijkmnopqrstuvwxyz";
    private static final String DIGITS = "23456789";
    private static final String SPECIAL = "!@#$%^&*-_=+?";
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordPolicy() {
    }

    public static boolean isStrong(String password, String username) {
        if (password == null || password.length() < 8 || password.length() > 128) {
            return false;
        }
        if (username != null && !username.isBlank()
                && password.toLowerCase().contains(username.toLowerCase())) {
            return false;
        }
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean special = false;
        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                upper = true;
            } else if (Character.isLowerCase(c)) {
                lower = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            } else if (!Character.isWhitespace(c)) {
                special = true;
            }
        }
        return upper && lower && digit && special;
    }

    public static void validate(String password, String username) {
        if (!isStrong(password, username)) {
            throw ApiException.badRequest(DESCRIPTION);
        }
    }

    /** Generates a random password that satisfies the policy. */
    public static String generate(int length) {
        String all = UPPER + LOWER + DIGITS + SPECIAL;
        char[] chars = new char[Math.max(length, 12)];
        chars[0] = UPPER.charAt(RANDOM.nextInt(UPPER.length()));
        chars[1] = LOWER.charAt(RANDOM.nextInt(LOWER.length()));
        chars[2] = DIGITS.charAt(RANDOM.nextInt(DIGITS.length()));
        chars[3] = SPECIAL.charAt(RANDOM.nextInt(SPECIAL.length()));
        for (int i = 4; i < chars.length; i++) {
            chars[i] = all.charAt(RANDOM.nextInt(all.length()));
        }
        for (int i = chars.length - 1; i > 0; i--) {
            int j = RANDOM.nextInt(i + 1);
            char tmp = chars[i];
            chars[i] = chars[j];
            chars[j] = tmp;
        }
        return new String(chars);
    }
}
