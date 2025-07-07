package util.websocket;

import core.ApplicationContext;
import core.shell.ShellEntity;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

import util.Log;
import util.functions;

public class WebSocket {
    private static final HostnameVerifier hostnameVerifier = new TrustAnyHostnameVerifier();
    private final Proxy proxy;
    private final ShellEntity shellContext;
    private CookieManager cookieManager;
    private URI uri;
    public String requestMethod = "POST";
    private boolean connected = false;
    private Socket socket = null;
    private OutputStream outputStream = null;
    private InputStream inputStream = null;

    public WebSocket(ShellEntity shellContext) {
        this.shellContext = shellContext;
        this.proxy = ApplicationContext.getProxy(this.shellContext);
    }

    public boolean Handshake() {
        try {
            URI uri = new URI(shellContext.getUrl());
            Proxy proxy = this.proxy;
            BufferedReader reader = null;
            BufferedWriter writer = null;

            try {
                if (proxy == null) {
                    proxy = Proxy.NO_PROXY;
                }
                this.socket = new Socket(proxy);

                socket.connect(new InetSocketAddress(uri.getHost(), getPort(uri)), shellContext.getConnTimeout());
                socket.setSoTimeout(shellContext.getReadTimeout());

                this.inputStream = this.socket.getInputStream();
                this.outputStream = this.socket.getOutputStream();

                reader = new BufferedReader(new InputStreamReader(this.inputStream));
                writer = new BufferedWriter(new OutputStreamWriter(this.outputStream));

                String key = generateWebSocketKey(this.shellContext.getPassword()+this.shellContext.getSecretKeyX());
                writer.write("GET " + uri.getRawPath() + (uri.getQuery() != null ? "?" + uri.getQuery() : "") + " HTTP/1.1\r\n");
                writer.write("Host: " + uri.getHost() + ":" + getPort(uri) + "\r\n");
                writer.write("Upgrade: websocket\r\n");
                writer.write("Connection: Upgrade\r\n");
                writer.write("Sec-WebSocket-Key: " + key + "\r\n");
                writer.write("Sec-WebSocket-Version: 13\r\n");

                writer.write("\r\n");
                writer.flush();

                String statusLine = reader.readLine();
                if (statusLine == null || !statusLine.startsWith("HTTP/1.1 101")) {
                    throw new IOException("WebSocket handshake failed: " + statusLine);
                }

                Map<String, List<String>> responseHeaders = new HashMap<>();
                String line;
                while ((line = reader.readLine()) != null && !line.isEmpty()) {
                    int idx = line.indexOf(':');
                    if (idx > 0) {
                        String name = line.substring(0, idx).trim();
                        String value = line.substring(idx + 1).trim();
                        responseHeaders.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
                    }
                }

                this.connected = true;
                return true;
            } catch (Exception e) {
                Log.error("WebSocket handshake error: " + e.getMessage());
                disconnect();
                return false;
            } finally {
//                    if (reader != null) reader.close();
//                    if (writer != null) writer.close();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }


    public WebSocketResponse SendWebSocketConn(String urlString, String method, Map<String, String> header, byte[] requestData, int connTimeOut, int readTimeOut, Proxy proxy) throws Exception {
        if (!connected || this.socket == null || !this.socket.isConnected()) {
            throw new IllegalStateException("WebSocket not connected");
        }

        try {
            sendWebSocketFrame(requestData);
            byte[] response = readWebSocketFrame();
            return new WebSocketResponse(this.shellContext, 200, null, response);
        } catch (IOException e) {
            Log.error("WebSocket send error: " + e.getMessage());
            disconnect();
            return new WebSocketResponse(this.shellContext, 500, null, ("Error: " + e.getMessage()).getBytes());
        }
    }

    public WebSocketResponse sendWebSocketResponse(byte[] requestData) {
        Map<String, String> header = this.shellContext.getHeaders();
        int connTimeOut = this.shellContext.getConnTimeout();
        int readTimeOut = this.shellContext.getReadTimeout();

        requestData = this.shellContext.getCryptionModule().encode(requestData);
        String left = this.shellContext.getReqLeft();
        String right = this.shellContext.getReqRight();
        if (this.shellContext.isSendLRReqData()) {
            byte[] leftData = left.getBytes();
            byte[] rightData = right.getBytes();
            requestData = (byte[]) functions.concatArrays(functions.concatArrays(leftData, 0, (leftData.length > 0 ? leftData.length : 1) - 1, requestData, 0, requestData.length - 1), 0, leftData.length + requestData.length - 1, rightData, 0, (rightData.length > 0 ? rightData.length : 1) - 1);
        }
        try {
            return this.SendWebSocketConn(this.shellContext.getUrl(), this.requestMethod, header, requestData, connTimeOut, readTimeOut, this.proxy);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void sendWebSocketFrame(byte[] payload) throws IOException {
        byte[] frame = new byte[10 + payload.length];  // 最大头长度 10
        int offset = 0;

        if (this.shellContext.getCryption().contains("BASE64")) {
            frame[offset++] = (byte) 0x81;
        }
        if (this.shellContext.getCryption().contains("RAW")) {
            frame[offset++] = (byte) 0x82;
        }

        int length = payload.length;
        boolean mask = true;

        if (length <= 125) {
            frame[offset++] = (byte) ((mask ? 0x80 : 0) | length);
        } else if (length < 65536) {
            frame[offset++] = (byte) ((mask ? 0x80 : 0) | 126);
            frame[offset++] = (byte) (length >> 8);
            frame[offset++] = (byte) length;
        } else {
            frame[offset++] = (byte) ((mask ? 0x80 : 0) | 127);
            for (int i = 56; i >= 0; i -= 8) {
                frame[offset++] = (byte) (length >> i);
            }
        }

        byte[] maskKey = new byte[4];
        new SecureRandom().nextBytes(maskKey);
        System.arraycopy(maskKey, 0, frame, offset, 4);
        offset += 4;

        for (int i = 0; i < length; i++) {
            frame[offset + i] = (byte) (payload[i] ^ maskKey[i % 4]);
        }

        offset += length;

        outputStream.write(frame, 0, offset);
        outputStream.flush();
    }

//    private byte[] readWebSocketFrame() throws IOException {
//        byte[] buffer = new byte[65536];
//        int len = inputStream.read(buffer);
//        if (len < 2) return new byte[0];
//
//        boolean fin = (buffer[0] & 0x80) != 0;
//        int opcode = buffer[0] & 0x0F;
//        boolean mask = (buffer[1] & 0x80) != 0;
//        int payloadLength = buffer[1] & 0x7F;
//
//        int maskOffset = 2;
//
//        if (payloadLength == 126) {
//            maskOffset += 2;
//        } else if (payloadLength == 127) {
//            maskOffset += 8;
//        }
//
//        if (mask) {
//            maskOffset += 4;  // mask key
//        }
//
//        if (len < maskOffset) return new byte[0];
//
//        int dataStart = maskOffset;
//        int dataLength = len - dataStart;
//
//        byte[] data = new byte[dataLength];
//        System.arraycopy(buffer, dataStart, data, 0, dataLength);
//
//        if (mask) {
//            byte[] maskKey = new byte[4];
//            System.arraycopy(buffer, maskOffset - 4, maskKey, 0, 4);
//            for (int i = 0; i < data.length; i++) {
//                data[i] ^= maskKey[i % 4];
//            }
//        }
//
//        return data;
//    }

    private byte[] readWebSocketFrame() throws IOException {
        ByteArrayOutputStream frameBuffer = new ByteArrayOutputStream();
        byte[] buffer = new byte[65536];

        int totalRead = 0;
        while (frameBuffer.size() < 2 && totalRead != -1) {
            totalRead = inputStream.read(buffer);
            if (totalRead > 0) frameBuffer.write(buffer, 0, totalRead);
        }

        if (frameBuffer.size() < 2) return new byte[0];

        byte[] frameHeader = frameBuffer.toByteArray();
        boolean mask = (frameHeader[1] & 0x80) != 0;
        int payloadLength = frameHeader[1] & 0x7F;

        int lengthBytes = 0;
        if (payloadLength == 126) lengthBytes = 2;
        else if (payloadLength == 127) lengthBytes = 8;

        int maskKeyOffset = 2 + lengthBytes;
        int totalNeedRead = maskKeyOffset + (mask ? 4 : 0);

        while (frameBuffer.size() < totalNeedRead && totalRead != -1) {
            totalRead = inputStream.read(buffer);
            if (totalRead > 0) frameBuffer.write(buffer, 0, totalRead);
        }

        if (frameBuffer.size() < totalNeedRead) return new byte[0];

        if (payloadLength == 126) {
            payloadLength = ((frameHeader[2] & 0xFF) << 8) | (frameHeader[3] & 0xFF);
        } else if (payloadLength == 127) {
            payloadLength = ((frameHeader[6] & 0xFF) << 24)
                    | ((frameHeader[7] & 0xFF) << 16)
                    | ((frameHeader[8] & 0xFF) << 8)
                    | (frameHeader[9] & 0xFF);
        }

        int dataStart = maskKeyOffset + (mask ? 4 : 0);
        int dataLength = payloadLength;
        int totalDataRead = frameBuffer.size() - dataStart;

        while (totalDataRead < dataLength && totalRead != -1) {
            totalRead = inputStream.read(buffer);
            if (totalRead > 0) {
                frameBuffer.write(buffer, 0, totalRead);
                totalDataRead += totalRead;
            }
        }

        byte[] fullFrame = frameBuffer.toByteArray();
        byte[] data = new byte[dataLength];
        System.arraycopy(fullFrame, dataStart, data, 0, dataLength);

        if (mask) {
            byte[] maskKey = new byte[4];
            System.arraycopy(fullFrame, maskKeyOffset, maskKey, 0, 4);
            for (int i = 0; i < data.length; i++) {
                data[i] ^= maskKey[i % 4];
            }
        }

        return data;
    }

    private static void trustAllHttpsCertificates() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[1];
            miTM tm = new miTM();
            trustAllCerts[0] = tm;
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            SSLContext sc2 = SSLContext.getInstance("TLS");
            sc2.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc2.getSocketFactory());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public synchronized URI getUri() {
        if (this.uri == null) {
            try {
                this.uri = URI.create(this.shellContext.getUrl());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return this.uri;
    }

    private int getPort(URI uri) {
        int port = uri.getPort();
        if (port == -1) {
            if ("wss".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme())) {
                return 443;
            } else {
                return 80;
            }
        }
        return port;
    }

    public void disconnect() {
        connected = false;
        try {
            if (outputStream != null) outputStream.close();
            if (inputStream != null) inputStream.close();
            if (socket != null && !socket.isClosed()) socket.close();
        } catch (IOException e) {
            Log.error("WebSocket disconnect error: " + e.getMessage());
        }
    }

    private String generateWebSocketKey(String customKey) {
        byte[] nonce;

        if (customKey != null && !customKey.isEmpty()) {
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                nonce = md.digest(customKey.getBytes(StandardCharsets.UTF_8));
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("MD5 algorithm not found", e);
            }
        } else {
            nonce = new byte[16];
            new SecureRandom().nextBytes(nonce);
        }

        return Base64.getEncoder().withoutPadding().encodeToString(nonce);
    }



    public synchronized CookieManager getCookieManager() {
        if (this.cookieManager == null) {
            this.cookieManager = new CookieManager();
            try {
                String cookieStr = this.shellContext.getHeaders().get("Cookie");
                if (cookieStr == null) {
                    cookieStr = this.shellContext.getHeaders().get("cookie");
                }
                if (cookieStr != null) {
                    String[] cookies;
                    for (String cookieStr2 : cookies = cookieStr.split(";")) {
                        String[] cookieAtt = cookieStr2.split("=");
                        if (cookieAtt.length != 2) continue;
                        HttpCookie httpCookie = new HttpCookie(cookieAtt[0], cookieAtt[1]);
                        this.cookieManager.getCookieStore().add(this.getUri(), httpCookie);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return this.cookieManager;
    }

    static {
        WebSocket.trustAllHttpsCertificates();
    }

    public static class TrustAnyHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    private static class miTM extends X509ExtendedTrustManager implements TrustManager, X509TrustManager {
        private miTM() {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public boolean isServerTrusted(X509Certificate[] certs) {
            return true;
        }

        public boolean isClientTrusted(X509Certificate[] certs) {
            return true;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, Socket socket) throws CertificateException {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s, SSLEngine sslEngine) throws CertificateException {
        }
    }
}
