package alvinw.cryptography.client;

import java.io.IOException;
import java.net.HttpURLConnection;

public class HttpResponseException extends IOException {
    public HttpResponseException(String message) {
        super(message);
    }

    public HttpResponseException(Throwable cause) {
        super(cause);
    }

    public static HttpResponseException of(HttpURLConnection connection) {
        try {
            return new HttpResponseException("HTTP " + connection.getResponseCode() + ": " + connection.getResponseMessage());
        } catch (IOException e) {
            return new HttpResponseException(e);
        }
    }
}
