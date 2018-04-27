package com.wireguard.config;

import android.text.TextUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The set of valid attributes for an interface or peer in a WireGuard configuration file.
 */

enum Attribute {
    ADDRESS("Address"),
    ALLOWED_IPS("AllowedIPs"),
    DNS("DNS"),
    ENDPOINT("Endpoint"),
    LISTEN_PORT("ListenPort"),
    MTU("MTU"),
    PERSISTENT_KEEPALIVE("PersistentKeepalive"),
    PRESHARED_KEY("PresharedKey"),
    PRIVATE_KEY("PrivateKey"),
    PUBLIC_KEY("PublicKey");

    private static final Map<String, Attribute> KEY_MAP;
    private static final Pattern SEPARATOR_PATTERN = Pattern.compile("\\s|=");

    static {
        KEY_MAP = new HashMap<>(Attribute.values().length);
        for (final Attribute key : Attribute.values()) {
            KEY_MAP.put(key.token, key);
        }
    }

    private final Pattern pattern;
    private final String token;

    Attribute(final String token) {
        pattern = Pattern.compile(token + "\\s*=\\s*(\\S.*)");
        this.token = token;
    }

    public static Attribute match(final CharSequence line) {
        return KEY_MAP.get(SEPARATOR_PATTERN.split(line)[0]);
    }

    public static <T> String listToString(final List<T> list) {
        return TextUtils.join(", ", list);
    }

    public static String[] stringToList(final String string) {
        if (string == null)
            return new String[0];
        return string.trim().split("\\s*,\\s*");
    }

    private static Method parseNumericAddressMethod;
    static {
        try {
            parseNumericAddressMethod = InetAddress.class.getMethod("parseNumericAddress", new Class[]{String.class});
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static InetAddress parseIPString(final String address) {
        if (address == null || address.isEmpty())
            throw new IllegalArgumentException("Empty address");
        try {
            return (InetAddress)parseNumericAddressMethod.invoke(null, new Object[]{address});
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof IllegalArgumentException)
                throw (IllegalArgumentException)e.getCause();
            else
                throw new IllegalArgumentException(e.getCause());
        }
    }

    public String composeWith(final Object value) {
        return String.format("%s = %s%n", token, value);
    }

    public String composeWith(final int value) {
        return String.format(Locale.getDefault(), "%s = %d%n", token, value);
    }

    public <T> String composeWith(final List<T> value) {
        return String.format("%s = %s%n", token, listToString(value));
    }

    public String parse(final CharSequence line) {
        final Matcher matcher = pattern.matcher(line);
        return matcher.matches() ? matcher.group(1) : null;
    }

    public String[] parseList(final CharSequence line) {
        final Matcher matcher = pattern.matcher(line);
        return matcher.matches() ? stringToList(matcher.group(1)) : null;
    }
}
