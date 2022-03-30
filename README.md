### Compatible kotlin code (Java)
```
fun encryptAES256(secret: String, salt: String, text: String): String? {
    try {
        val iv = ByteArray(16) { i -> 0 }
        val ivSpec = IvParameterSpec(iv)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keySpec = PBEKeySpec(
            secret.toCharArray(),
            salt.toByteArray(),
            65536, 256
        )
        val tmp = factory.generateSecret(keySpec)
        val secretKey = SecretKeySpec(tmp.encoded, "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
        return Base64.encodeToString(cipher.doFinal(text.toByteArray(StandardCharsets.UTF_8)), Base64.DEFAULT)
    } catch (e: java.lang.Exception) {
        Logger.e("e: ${e.message}")
        return null
    }
}

fun decryptAES256(secret: String, salt: String, encryptedText: String): String? {
    try {
        val iv = ByteArray(16) { i -> 0 }
        val ivSpec = IvParameterSpec(iv)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keySpec = PBEKeySpec(
            secret.toCharArray(),
            salt.toByteArray(),
            65536, 256
        )
        val tmp = factory.generateSecret(keySpec)
        val secretKey = SecretKeySpec(tmp.encoded, "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        return String(cipher.doFinal(Base64.decode(encryptedText, Base64.DEFAULT)))
    } catch (e: java.lang.Exception) {
        return null
    }
}
```