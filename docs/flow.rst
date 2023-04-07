签名
=================

假定待签名数据头为::

    "request_id": "2XiTgZ2oVrBgGqKQ1ruCKh",
    "access_key": "2y7cg8kmoGDrDBXJLaizoD",
    "nonce": 1464594744

签名过程用Java代码描述如下::

        import cn.hutool.core.util.HexUtil;
        import cn.hutool.core.util.IdUtil;
        import cn.hutool.crypto.BCUtil;
        import cn.hutool.crypto.SecureUtil;
        import cn.hutool.crypto.asymmetric.SM2;
        import org.bouncycastle.crypto.engines.SM2Engine;
        import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

        import java.nio.charset.StandardCharsets;
        import java.security.KeyPair;
        import java.util.Base64;

        public class SignatureUtil {
            //签名
            public static String sign(byte[] data, String privateKey) {
                SM2 sm2 = new SM2(privateKey,null);
                sm2.setMode(SM2Engine.Mode.C1C2C3);
                sm2.usePlainEncoding();
                //签名使用Base64编码后得到的值即为请求头中signature字段的值
                return Base64.getEncoder().encodeToString(sm2.sign(data));
            }
            //验签
            public static boolean verify(byte[] data, String publicKey, String sign) {
                SM2 sm2 = new SM2(null, publicKey);
                sm2.setMode(SM2Engine.Mode.C1C2C3);
                sm2.usePlainEncoding();
                return sm2.verify(data,Base64.getDecoder().decode(sign));
            }
            //测试用例
            public static void main(String[] args) {
                KeyPair keyPair = SecureUtil.generateKeyPair("SM2");
                String publicKey = HexUtil.encodeHexStr(((BCECPublicKey)keyPair.getPublic()).getQ().getEncoded(false));
                //RSA私钥文件路径
                String privateKey = HexUtil.encodeHexStr(BCUtil.encodeECPrivateKey(keyPair.getPrivate()));
                System.out.println(publicKey);
                System.out.println(privateKey);
                long requestId = IdUtil.getSnowflakeNextId();//2XiTgZ2oVrBgGqKQ1ruCKh
                String accessKey = "2y7cg8kmoGDrDBXJLaizoD";
                long nonce = System.currentTimeMillis()/1000;//1464594744
                String data = requestId + accessKey + nonce;
                //签名
                String sign = sign(data.getBytes(StandardCharsets.UTF_8),privateKey);
                System.out.println(sign);
                //验签
                boolean verify = verify(data.getBytes(StandardCharsets.UTF_8),publicKey,sign);
                System.out.println(verify);
            }
        }

.. note:: 签名所用的方法是SM2，签名数据字符串转换成bytes时要用UTF-8编码格式









