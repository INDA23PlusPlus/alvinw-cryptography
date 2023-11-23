package alvinw.cryptography.client;

import java.io.IOException;
import java.net.HttpURLConnection;

/**
 * An exception thrown when an HTTP request responds with an unexpected HTTP
 * status code.
 */
public class HttpResponseException extends IOException {
    public HttpResponseException(String message) {
        super(message);
    }

    public HttpResponseException(Throwable cause) {
        super(cause);
    }

    /**
     * Create an exception instance that formats the HTTP status code and response
     * message nicely.
     *
     * @param request The request.
     * @return The exception.
     */
    public static HttpResponseException of(HttpURLConnection request) {
        try {
            return new HttpResponseException("HTTP " + request.getResponseCode() + ": " + request.getResponseMessage());
        } catch (IOException e) {
            return new HttpResponseException(e);
        }
    }
}
