package io.dataease.commons.utils;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * 发送https请求 工具类
 * 注意:是Https请求,若是Http,请将 HttpsURLConnection ---> HttpURLConnection
 */
public class HttpUtil {


    public static Logger logger = Logger.getLogger(HttpUtil.class);


    /**
     * [强制]在实现的HostnameVerifier子类中，需要使用verify函数效验服务器主机名的合法性，否则会导致恶意程序利用中间人攻击绕过主机名效验。
     * 信任固定ip
     */
    static {
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                // ip address of the service URL(like.23.28.244.244)
                if (hostname.equals("127.0.0.1xx")) {
                    return true;
                }
                return false;
            }
        });
    }


    /**
     * 通过重写TrustManager的checkClientTrusted（检查客户端证书信任）和checkServerTrusted（检查服务端证书验证）。以及HostnameVerifier的verify（校验）方法即可取消对证书的所有验证。
     */

    static HostnameVerifier _hv = new HostnameVerifier() {
        @Override
        public boolean verify(String host, SSLSession sslSession) {
            logger.warn("Host===>" + host);
            logger.warn("sslSession.getPeerHost====>" + sslSession.getPeerHost());
            return true;
        }
    };

    static TrustManager[] _trustCerts = new TrustManager[]{
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            }
    };

    /**
     * 信任证书ssl
     */
    static {
        try {
            HttpsURLConnection.setDefaultHostnameVerifier(_hv);
            SSLContext ctxSSL = null;
            ctxSSL = SSLContext.getInstance("SSL");
            ctxSSL.init(null, _trustCerts, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(ctxSSL.getSocketFactory());
        } catch (Exception e) {
            logger.error("SSL context set fail: {}", e);
        }
    }

    /**
     * 发送 post 请求
     *
     * @param urlStr  目标地址
     * @param json    请求参数(json格式) 例如:{"one":"1"}
     * @return
     */
    public static String doPost(String urlStr, String json, HttpClientConfig config) {
        String result = null;
        logger.error("POST请求地址：------>" + urlStr);
        logger.error("POST请求参数：------>" + json);
        try {
            DataOutputStream out = null;
            BufferedReader reader = null;
            HttpsURLConnection connection = null;
            try {
                //获取目标地址
                URL url = new URL(urlStr);
                //创建连接
                connection = (HttpsURLConnection) url.openConnection();
                //设置向HttpURLConnection输出、输入（发送数据、接收数据），当请求为post时必须设置这两个参数
                connection.setDoOutput(true);
                connection.setDoInput(true);
                //设置请求方式
                connection.setRequestMethod("POST");
                //设置是否开启缓存，post请求时，缓存必须关掉
                connection.setUseCaches(false);
                //设置连接是否自动处理重定向（setFollowRedirects：所用http连接；setInstanceFollowRedirects：本次连接）
                connection.setInstanceFollowRedirects(true);
                //设置提交内容类型(设置请求头)
                connection.setRequestProperty("Content-Type", "application/json");
                Map<String, String> header = config.getHeader();
                for (String key : header.keySet()) {
                    connection.setRequestProperty(key, header.get(key));
                }
                //开始连接
                connection.connect();
                //发送请求
                out = new DataOutputStream(connection.getOutputStream());
                //提交参数
                if (StringUtils.isNotBlank(json)) {
                    out.write(json.getBytes(config.getCharset()));
                }
                out.flush();
                out.close();
                //读取响应
                reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), config.getCharset()));
                String lines;
                StringBuffer sb = new StringBuffer("");
                while ((lines = reader.readLine()) != null) {
                    lines = new String(lines.getBytes());
                    sb.append(lines);
                }
                result = sb.toString();
                logger.error("请求返回结果：" + result);
                reader.close();
                // 断开连接
                connection.disconnect();
            } catch (Exception e) {
                logger.error("发送post 请求失败--->", e);
            } finally {
                if (out != null) {
                    out.flush();
                    out.close();
                }
                if (reader != null) {
                    reader.close();
                }
                if (connection != null) {
                    connection.disconnect();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("发送post 请求失败--->", e);
        }
        return result;
    }


    /**
     * get 请求默认编码 UTF-8
     *
     * @param urlStr
     * @return
     */
    public static String doGet(String urlStr) {
        return doGet(urlStr, "UTF-8");
    }

    /**
     * 发送 get 请求
     *
     * @param urlStr
     * @param charset
     * @return
     */
    public static String doGet(String urlStr, String charset) {
        String result = null;
        logger.error("GET请求地址：------>" + urlStr);
        try {
            BufferedReader reader = null;
            HttpsURLConnection connection = null;
            try {
                //获取目标地址
                URL url = new URL(urlStr);
                //创建连接
                connection = (HttpsURLConnection) url.openConnection();
                //设置请求方式
                connection.setRequestMethod("GET");
                //开始连接
                connection.connect();
                //读取响应
                reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), charset));
                String lines;
                StringBuffer sb = new StringBuffer("");
                while ((lines = reader.readLine()) != null) {
                    lines = new String(lines.getBytes());
                    sb.append(lines);
                }
                result = sb.toString();
                logger.error("请求返回结果：" + result);
                reader.close();
                // 断开连接
                connection.disconnect();
            } catch (Exception e) {
                logger.error("发送get 请求失败--->", e);
            } finally {
                if (reader != null) {
                    reader.close();
                }
                if (connection != null) {
                    connection.disconnect();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("发送get 请求失败--->", e);
        }
        return result;
    }

}
