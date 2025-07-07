package util.websocket;

import core.shell.ShellEntity;

import java.util.List;
import java.util.Map;

public class WebSocketResponse {
    private final int responseCode;
    private final Map<String, List<String>> headers;
    private byte[] result;
    private ShellEntity shellEntity;

    public WebSocketResponse(ShellEntity shellEntity, int responseCode, Map<String, List<String>> headers, byte[] result) {
        this.shellEntity = shellEntity;
        this.responseCode = responseCode;
        this.headers = headers;
        this.result = Decrypte(result);
    }

    public int getResponseCode() {
        return responseCode;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    public byte[] getresult() {
        return result;
    }

    public byte[] Decrypte(byte[] Ciphertext) {
        try {
            byte[] decode = this.shellEntity.getCryptionModule().decode(Ciphertext);
            return decode;
        } catch (Exception e) {
            return new byte[0];
        }
    }
}
