# TempGBox Mobile API Documentation

Complete API reference for the TempGBox Mobile Android application.

## 🔗 Base URL

- **Production**: `https://api.tempgbox.net`
- **Development**: `http://localhost:8000`

## 🔐 Authentication

The mobile app uses JWT tokens with device binding for secure API communication.

### Token Generation

```kotlin
// Generate secure token with device binding
suspend fun generateSecureToken(deviceId: String, domain: String): String {
    val browserHash = generateBrowserSecurityHash()
    val timestamp = System.currentTimeMillis()
    val nonce = generateNonce()
    
    val payload = TokenPayload(
        device_id = deviceId,
        domain = domain,
        browser_hash = browserHash,
        timestamp = timestamp,
        nonce = nonce,
        origin = "android://tempgbox",
        user_agent = "TempGBox-Mobile/${BuildConfig.VERSION_NAME}",
        tab_data = TabData(
            tabSwitchCount = 0,
            hasTabChanged = false,
            timeSinceLastActivity = 0
        )
    )
    
    return apiService.generateToken(payload).token
}
```

### Device Fingerprinting

```kotlin
fun generateDeviceFingerprint(): String {
    val components = listOf(
        Build.MODEL,
        Build.MANUFACTURER,
        Build.VERSION.RELEASE,
        Build.VERSION.SDK_INT.toString(),
        getScreenResolution(),
        getDeviceId()
    )
    
    return components.joinToString("|").hashCode().toString()
}

private fun getScreenResolution(): String {
    val displayMetrics = Resources.getSystem().displayMetrics
    return "${displayMetrics.widthPixels}x${displayMetrics.heightPixels}"
}

private fun getDeviceId(): String {
    return Settings.Secure.getString(
        context.contentResolver,
        Settings.Secure.ANDROID_ID
    )
}
```

## 📧 Email API Endpoints

### Generate Email

Create a new temporary email address.

```kotlin
// Generate email with secure token
suspend fun generateEmail(domains: List<String>): EmailResponse {
    val deviceId = generateDeviceFingerprint()
    val secureToken = generateSecureToken(deviceId, domains.joinToString(","))
    
    return apiService.generateEmail(
        token = secureToken,
        deviceId = deviceId,
        domains = domains
    )
}

// Response
data class EmailResponse(
    val email: String,
    val status: String,
    val service: String,
    val domain_type: String,
    val domain_info: DomainInfo
)

data class DomainInfo(
    val name: String,
    val suffix: String,
    val description: String,
    val reliability: String
)
```

### Generate Custom Email

Create email with custom username.

```kotlin
// Generate custom email
suspend fun generateCustomEmail(username: String, domain: String): EmailResponse {
    val deviceId = generateDeviceFingerprint()
    val secureToken = generateSecureToken(deviceId, domain)
    
    return apiService.generateCustomEmail(
        token = secureToken,
        deviceId = deviceId,
        username = username,
        domain = domain
    )
}
```

### Get Email Messages

Retrieve messages for a specific email address.

```kotlin
// Get messages
suspend fun getEmailMessages(emailAddress: String): List<EmailMessage> {
    val deviceId = generateDeviceFingerprint()
    val secureToken = generateSecureToken(deviceId, "gmail")
    
    return apiService.getEmailMessages(
        token = secureToken,
        emailAddress = emailAddress
    )
}

// Response
data class EmailMessage(
    val messageID: String?,
    val messageId: String?,
    val message_id: String?,
    val from: String,
    val subject: String,
    val time: String,
    val content: String? = null
) {
    val id: String
        get() = messageID ?: messageId ?: message_id ?: ""
}
```

## 📚 Email History API

### Get Email History

Retrieve email history for a device.

```kotlin
// Get device email history
suspend fun getEmailHistory(includeExpired: Boolean = false): EmailHistoryResponse {
    val deviceId = generateDeviceFingerprint()
    val secureToken = generateSecureToken(deviceId, "gmail")
    
    return apiService.getEmailHistory(
        token = secureToken,
        deviceId = deviceId,
        includeExpired = includeExpired
    )
}

// Response
data class EmailHistoryResponse(
    val device_id: String,
    val emails: List<EmailHistoryItem>,
    val total_count: Int
)

data class EmailHistoryItem(
    val email: String,
    val created_at: String,
    val expires_at: String,
    val status: String,
    val message_count: Int
)
```

### Add Email to History

Add an email to device history.

```kotlin
// Add email to history
suspend fun addEmailToHistory(email: String): ApiResponse {
    val deviceId = generateDeviceFingerprint()
    val secureToken = generateSecureToken(deviceId, "gmail")
    
    return apiService.addEmailToHistory(
        token = secureToken,
        deviceId = deviceId,
        email = email
    )
}
```

### Remove Email from History

Remove an email from device history.

```kotlin
// Remove email from history
suspend fun removeEmailFromHistory(email: String): ApiResponse {
    val deviceId = generateDeviceFingerprint()
    val secureToken = generateSecureToken(deviceId, "gmail")
    
    return apiService.removeEmailFromHistory(
        token = secureToken,
        deviceId = deviceId,
        email = email
    )
}
```

## 🔧 API Service Implementation

### Retrofit Service

```kotlin
interface TempGBoxApiService {
    @GET("email")
    suspend fun generateEmail(
        @Query("token") token: String,
        @Query("device_id") deviceId: String,
        @Query("domain") domain: String
    ): EmailResponse
    
    @POST("email/token")
    suspend fun generateToken(
        @Body payload: TokenPayload
    ): TokenResponse
    
    @GET("email/{emailAddress}/messages")
    suspend fun getEmailMessages(
        @Path("emailAddress") emailAddress: String,
        @Query("token") token: String
    ): List<EmailMessage>
    
    @GET("email/history")
    suspend fun getEmailHistory(
        @Query("device_id") deviceId: String,
        @Query("include_expired") includeExpired: Boolean,
        @Query("token") token: String
    ): EmailHistoryResponse
    
    @POST("email/history")
    suspend fun addEmailToHistory(
        @Body request: AddEmailRequest
    ): ApiResponse
    
    @DELETE("email/history")
    suspend fun removeEmailFromHistory(
        @Body request: RemoveEmailRequest
    ): ApiResponse
}
```

### API Client Setup

```kotlin
class ApiClient {
    private val httpClient = OkHttpClient.Builder()
        .addInterceptor(AuthInterceptor())
        .addInterceptor(SecurityInterceptor())
        .addInterceptor(LoggingInterceptor())
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()
    
    private val retrofit = Retrofit.Builder()
        .baseUrl(BuildConfig.API_BASE_URL)
        .client(httpClient)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
    
    val apiService: TempGBoxApiService = retrofit.create(TempGBoxApiService::class.java)
    
    private class AuthInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request().newBuilder()
                .addHeader("X-Session-ID", getSessionId())
                .addHeader("X-Browser-Hash", getBrowserHash())
                .addHeader("X-Origin", "android://tempgbox")
                .addHeader("X-Timestamp", System.currentTimeMillis().toString())
                .addHeader("X-Nonce", generateNonce())
                .addHeader("X-User-Agent", "TempGBox-Mobile/${BuildConfig.VERSION_NAME}")
                .build()
            
            return chain.proceed(request)
        }
    }
    
    private class SecurityInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request()
            
            // Add certificate pinning for production
            if (BuildConfig.DEBUG.not()) {
                val certificatePinner = CertificatePinner.Builder()
                    .add("api.tempgbox.net", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                    .build()
                
                val newRequest = request.newBuilder()
                    .build()
                
                return chain.proceed(newRequest)
            }
            
            return chain.proceed(request)
        }
    }
    
    private class LoggingInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request()
            
            if (BuildConfig.DEBUG) {
                Log.d("API", "Request: ${request.url}")
            }
            
            val response = chain.proceed(request)
            
            if (BuildConfig.DEBUG) {
                Log.d("API", "Response: ${response.code}")
            }
            
            return response
        }
    }
}
```

## 🎯 AdMob Integration

### Banner Ads

```kotlin
@Composable
fun AdMobBanner(
    modifier: Modifier = Modifier,
    adUnitId: String = BuildConfig.ADMOB_BANNER_ID
) {
    AndroidView(
        modifier = modifier.fillMaxWidth(),
        factory = { context ->
            AdView(context).apply {
                setAdSize(AdSize.BANNER)
                this.adUnitId = adUnitId
                loadAd(AdRequest.Builder().build())
            }
        }
    )
}
```

### Interstitial Ads

```kotlin
class AdManager(private val context: Context) {
    private var interstitialAd: InterstitialAd? = null
    private val frequencyManager = AdFrequencyManager()
    
    fun loadInterstitialAd() {
        if (!frequencyManager.canShowAd("interstitial")) {
            return
        }
        
        interstitialAd = InterstitialAd(context).apply {
            adUnitId = BuildConfig.ADMOB_INTERSTITIAL_ID
            adListener = object : AdListener() {
                override fun onAdLoaded() {
                    Log.d("AdMob", "Interstitial ad loaded")
                }
                
                override fun onAdFailedToLoad(errorCode: Int) {
                    Log.e("AdMob", "Interstitial ad failed to load: $errorCode")
                }
                
                override fun onAdClosed() {
                    loadInterstitialAd() // Load next ad
                }
            }
            loadAd(AdRequest.Builder().build())
        }
    }
    
    fun showInterstitialAd() {
        interstitialAd?.let { ad ->
            if (ad.isLoaded && frequencyManager.canShowAd("interstitial")) {
                ad.show()
                frequencyManager.recordAdShown("interstitial")
            }
        }
    }
}
```

### Frequency Capping

```kotlin
class AdFrequencyManager {
    private val adShownTimes = mutableMapOf<String, Long>()
    private val frequencyCapMinutes = 5
    
    fun canShowAd(adType: String): Boolean {
        val lastShown = adShownTimes[adType] ?: 0
        val currentTime = System.currentTimeMillis()
        
        return (currentTime - lastShown) > (frequencyCapMinutes * 60 * 1000)
    }
    
    fun recordAdShown(adType: String) {
        adShownTimes[adType] = System.currentTimeMillis()
    }
}
```

## 🔒 Security Implementation

### Network Security

```kotlin
// Network security configuration
class NetworkSecurityConfig {
    companion object {
        fun createNetworkSecurityConfig(): NetworkSecurityConfig {
            return NetworkSecurityConfig.Builder()
                .addDomain("api.tempgbox.net")
                .addDomain("tempgbox.net")
                .setCleartextTrafficPermitted(false)
                .build()
        }
    }
}
```

### Certificate Pinning

```kotlin
class CertificatePinningManager {
    fun createCertificatePinner(): CertificatePinner {
        return CertificatePinner.Builder()
            .add("api.tempgbox.net", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.tempgbox.net", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build()
    }
}
```

### Data Encryption

```kotlin
class DataEncryption {
    private val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    private val keyStore = KeyStore.getInstance("AndroidKeyStore")
    
    init {
        keyStore.load(null)
    }
    
    fun encryptData(data: String): String {
        val cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_GCM + "/" + KeyProperties.ENCRYPTION_PADDING_NOPADDING)
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }
    
    fun decryptData(encryptedData: String): String {
        val cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_GCM + "/" + KeyProperties.ENCRYPTION_PADDING_NOPADDING)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey())
        
        val encryptedBytes = Base64.decode(encryptedData, Base64.DEFAULT)
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes)
    }
    
    private fun getSecretKey(): SecretKey {
        return keyStore.getKey("TempGBoxKey", null) as SecretKey
    }
}
```

## 📊 Performance Optimization

### Caching Strategy

```kotlin
class CacheManager {
    private val memoryCache = LruCache<String, Any>(50)
    private val diskCache = DiskLruCache.open(cacheDir, 1, 1, 10 * 1024 * 1024)
    
    fun get(key: String): Any? {
        return memoryCache.get(key) ?: diskCache.get(key)
    }
    
    fun put(key: String, value: Any) {
        memoryCache.put(key, value)
        diskCache.put(key, value)
    }
    
    fun clear() {
        memoryCache.evictAll()
        diskCache.delete()
    }
}
```

### Image Loading

```kotlin
@Composable
fun SenderAvatar(
    sender: String,
    modifier: Modifier = Modifier
) {
    AsyncImage(
        model = ImageRequest.Builder(LocalContext.current)
            .data(generateAvatarUrl(sender))
            .crossfade(true)
            .memoryCacheKey("avatar_$sender")
            .diskCacheKey("avatar_$sender")
            .build(),
        contentDescription = "Sender avatar",
        modifier = modifier
            .size(40.dp)
            .clip(CircleShape),
        contentScale = ContentScale.Crop,
        loading = {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(Color.Gray),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = Color.White
                )
            }
        },
        error = {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(Color.Gray),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = sender.firstOrNull()?.uppercase() ?: "?",
                    color = Color.White,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    )
}
```

### Memory Management

```kotlin
class EmailManager {
    private val listeners = mutableSetOf<WeakReference<EmailListener>>()
    private val emailCache = LruCache<String, EmailMessage>(100)
    
    fun addListener(listener: EmailListener) {
        listeners.add(WeakReference(listener))
    }
    
    fun removeListener(listener: EmailListener) {
        listeners.removeAll { it.get() == listener }
    }
    
    fun getEmailMessage(id: String): EmailMessage? {
        return emailCache.get(id)
    }
    
    fun cacheEmailMessage(message: EmailMessage) {
        emailCache.put(message.id, message)
    }
    
    fun clearCache() {
        emailCache.evictAll()
    }
}
```

## 🔧 Error Handling

### API Error Handling

```kotlin
class ApiErrorHandler {
    fun handleError(throwable: Throwable): String {
        return when (throwable) {
            is HttpException -> {
                when (throwable.code()) {
                    400 -> "Bad request. Please check your input."
                    401 -> "Unauthorized. Please refresh the app."
                    403 -> "Forbidden. Your session has expired."
                    404 -> "Not found. The requested resource doesn't exist."
                    429 -> "Too many requests. Please wait a moment."
                    500 -> "Server error. Please try again later."
                    else -> "Network error. Please check your connection."
                }
            }
            is SocketTimeoutException -> "Request timeout. Please check your connection."
            is UnknownHostException -> "No internet connection. Please check your network."
            is IOException -> "Network error. Please try again."
            else -> "An unexpected error occurred. Please try again."
        }
    }
}
```

### Retry Logic

```kotlin
class RetryInterceptor : Interceptor {
    private val maxRetries = 3
    private val retryDelay = 1000L
    
    override fun intercept(chain: Interceptor.Chain): Response {
        var request = chain.request()
        var response: Response? = null
        var exception: Exception? = null
        
        for (i in 0..maxRetries) {
            try {
                response = chain.proceed(request)
                if (response.isSuccessful) {
                    return response
                }
            } catch (e: Exception) {
                exception = e
                if (i < maxRetries) {
                    Thread.sleep(retryDelay * (i + 1))
                }
            }
        }
        
        throw exception ?: Exception("Max retries exceeded")
    }
}
```

## 📱 Offline Support

### Offline Data Storage

```kotlin
class OfflineDataManager {
    private val database = Room.databaseBuilder(
        context,
        TempGBoxDatabase::class.java,
        "tempgbox_database"
    ).build()
    
    suspend fun saveEmailMessage(message: EmailMessage) {
        database.emailMessageDao().insert(message)
    }
    
    suspend fun getEmailMessages(emailAddress: String): List<EmailMessage> {
        return database.emailMessageDao().getMessagesByEmail(emailAddress)
    }
    
    suspend fun saveEmailHistory(history: EmailHistoryItem) {
        database.emailHistoryDao().insert(history)
    }
    
    suspend fun getEmailHistory(): List<EmailHistoryItem> {
        return database.emailHistoryDao().getAll()
    }
}
```

### Network State Monitoring

```kotlin
class NetworkStateManager {
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    
    fun isNetworkAvailable(): Boolean {
        val network = connectivityManager.activeNetwork
        val capabilities = connectivityManager.getNetworkCapabilities(network)
        return capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
    }
    
    fun observeNetworkState(): Flow<Boolean> {
        return callbackFlow {
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    trySend(true)
                }
                
                override fun onLost(network: Network) {
                    trySend(false)
                }
            }
            
            connectivityManager.registerDefaultNetworkCallback(callback)
            
            awaitClose {
                connectivityManager.unregisterNetworkCallback(callback)
            }
        }
    }
}
```

## 📞 Support

- **Documentation**: [Mobile Docs](https://github.com/thevpankaj/tempgbox-mobile)
- **Issues**: [GitHub Issues](https://github.com/thevpankaj/tempgbox-mobile/issues)
- **Email**: support@tempgbox.net

---

**TempGBox Mobile API Documentation** - Complete mobile API reference
