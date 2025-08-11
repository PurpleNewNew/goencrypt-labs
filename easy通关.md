# Encrypt Labs 通关攻略 (简单模式-Burp+Python联动篇)

本攻略将以教程的形式，一步步带你分析`encrypt-labs`靶场（简单模式）的加密逻辑，并最终结合Burp Suite和Python脚本完成密码爆破。每个关卡都将遵循“分析->定位->逆向->编写->爆破”的完整流程。

## 核心思想

我们将不再编写独立的爆破程序，而是创建一系列小型的Python“加密器”脚本。Burp Intruder负责提供密码字典并发起攻击，但在发送每个请求之前，它会调用我们的Python脚本来对当前密码进行实时加密，并将加密结果作为最终的Payload发送。

## 准备工作

1.  **Python环境**: 确保你的Python环境可用，并安装了`requests` 和 `pycryptodome`库。
    ```bash
    pip install pycryptodome requests
    ```
2.  **脚本存放**: 将下面每个关卡的Python脚本分别保存到本地，例如保存在 `C:\encrypt-labs-scripts\` 目录下。
3.  **Burp Suite**: 熟练掌握Intruder模块的基本用法。

---

### 第1关：AES固定Key

*   **第一步：抓包分析**
    1.  在浏览器中输入任意密码并点击登录，用Burp Suite拦截请求。
    2.  观察请求包：请求路径为 `/encrypt/aes`，方法为 `POST`，请求体为`x-www-form-urlencoded`格式，包含一个参数 `encryptedData`，其值是一段看起来像Base64的字符串。

*   **第二步：前端代码定位**
    1.  查看`easy.html`的源码，发现登录按钮关联的挑战关卡都定义在一个`<ul>`列表中。
    2.  第一个关卡“AES固定Key”的链接`<a>`标签中，有一个`data-func="sendDataAes"`的属性。这告诉我们，点击此关卡时，会调用`easy.js`文件中的`sendDataAes`函数。

*   **第三步：JS逆向与逻辑分析**
    1.  打开`static/js/easy.js`文件，找到`sendDataAes`函数。
    2.  分析代码逻辑：
        *   将用户名和密码打包成一个JSON对象：`{username: "...", password: "..."}`。
        *   定义了常量`key`和`iv`，值都是`1234567890123456`。
        *   调用`CryptoJS.AES.encrypt`函数进行加密。从参数可以看出，加密模式是`CBC`，填充方式是`Pkcs7`。
        *   将加密后的结果转换成字符串，这就是最终的密文。

*   **第四步：编写联动加密脚本**
    根据分析，我们编写一个Python脚本，它接收一个密码作为命令行参数，模拟上述加密过程，并打印出最终的Base64密文。

    **脚本 (`encrypt_level_1.py`)**: 
    ```python
    # C:\encrypt-labs-scripts\encrypt_level_1.py
    import sys, json
    from base64 import b64encode
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    def encrypt_data(password):
        data = {"username": "admin", "password": password}
        json_data = json.dumps(data).encode('utf-8')
        key = b'1234567890123456'
        iv = b'1234567890123456'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(pad(json_data, AES.block_size))
        return b64encode(encrypted_bytes).decode('utf-8')

    if __name__ == "__main__":
        if len(sys.argv) > 1:
            print(encrypt_data(sys.argv[1]))
    ```

*   **第五步：配置Burp Intruder并爆破**
    1.  将抓到的请求包发送到 **Intruder** (Ctrl+I)。
    2.  在 **Positions** 标签页，点击 **Clear §**，然后仅选中`encryptedData`参数的值，点击 **Add §**。
    3.  切换到 **Payloads** 标签页。
    4.  **Payload Sets**: **Payload type**选择 `Simple list`，在下面的文本框中加载你的密码字典。
    5.  **Payload Processing**: 点击 **Add**，**Rule type**选择 `Invoke shell`。
    6.  在 **Define command** 中配置调用脚本的命令（请根据你的实际路径修改）：
        ```cmd
        C:\Python39\python.exe C:\encrypt-labs-scripts\encrypt_level_1.py
        ```
    7.  确保 **Input for command** 选项是 `Payload`。
    8.  点击 **Start attack**。通过观察响应长度或内容，筛选出成功的请求，即可找到正确密码。

---

### 第2关：AES随机Key

*   **第一步：抓包分析**
    1.  在Burp中观察发现，点击登录前，浏览器会先向`/encrypt/get-public-key`发起一个GET请求。
    2.  登录请求本身被发送到`/encrypt/aes_random_key`，请求体是JSON格式，包含`encryptedData`和`encryptedKey`两个参数。

*   **第二步：前端代码定位**
    1.  在`easy.html`中找到对应关卡的`data-func="sendDataRandomAes"`。

*   **第三步：JS逆向与逻辑分析**
    1.  在`easy.js`中找到`sendDataRandomAes`函数。
    2.  逻辑如下：
        *   先`fetch`服务器的`/get-public-key`接口，得到一个RSA公钥。
        *   使用`CryptoJS.lib.WordArray.random(16)`生成一个16字节（128位）的随机AES密钥，并且IV与Key相同。
        *   使用这个随机密钥加密数据（AES-CBC-PKCS7）。
        *   使用第一步获取的RSA公钥，加密这个随机的AES密钥（注意，JS代码在RSA加密前，还对AES密钥的字符串形式做了一次Base64编码）。
        *   最后将加密后的数据和加密后的密钥一并发送。

*   **第四步：编写联动加密脚本**
    脚本需要模拟上述完整流程，接收密码，返回用`|`分隔的两个加密值。

    **脚本 (`encrypt_level_2.py`)**: 
    ```python
    # C:\encrypt-labs-scripts\encrypt_level_2.py
    import sys, requests, json
    from base64 import b64encode
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import pad
    from Crypto.Random import get_random_bytes

    def encrypt_data(password):
        try:
            pub_key_pem = requests.get("http://localhost:8080/encrypt/get-public-key").json()['publicKey']
            rsa_key = RSA.import_key(pub_key_pem)
        except Exception:
            return "ERROR|ERROR"
        data = {"username": "admin", "password": password}
        json_data = json.dumps(data).encode('utf-8')
        aes_key = get_random_bytes(16)
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=aes_key)
        encrypted_data = b64encode(aes_cipher.encrypt(pad(json_data, AES.block_size))).decode('utf-8')
        rsa_cipher = PKCS1_v1_5.new(rsa_key)
        encrypted_key = b64encode(rsa_cipher.encrypt(b64encode(aes_key))).decode('utf-8')
        return f"{encrypted_data}|{encrypted_key}"

    if __name__ == "__main__":
        if len(sys.argv) > 1:
            print(encrypt_data(sys.argv[1]))
    ```

*   **第五步：配置Burp Intruder并爆破**
    1.  抓取向 `/encrypt/aes_random_key` 的请求，发送到Intruder。
    2.  **Attack type**: `Pitchfork`。
    3.  在**Positions**中，清除默认标记，分别选中JSON体中`encryptedData`和`encryptedKey`的值，添加`§`标记。
    4.  在**Payloads**中，**Payload Set 1** (`encryptedData`) 和 **Payload Set 2** (`encryptedKey`) 都使用相同的配置：
        *   **Payload type**: `Simple list`，加载密码字典。
        *   **Payload Processing**: 添加 `Invoke shell` 规则，命令为 `C:\Python39\python.exe C:\encrypt-labs-scripts\encrypt_level_2.py`。
    5.  在**Payload Set 1**的Payload Processing中**再添加**一个规则 `Extract by separator`，分隔符为 `|`，提取第 `1` 部分。
    6.  在**Payload Set 2**的Payload Processing中**再添加**一个规则 `Extract by separator`，分隔符为 `|`，提取第 `2` 部分。
    7.  开始攻击。

---

### 第3关：AES服务端获取Key

*   **第一步：抓包分析**
    1.  点击登录前，浏览器向`/encrypt/aesserver`发起GET请求，服务器返回一个含`key`和`iv`的JSON。
    2.  登录请求与第1关格式相同，但加密内容显然是用了上一步获取的密钥。

*   **第二步：前端代码定位**
    1.  `easy.html`中找到`data-func="fetchAndSendDataAes"`。

*   **第三步：JS逆向与逻辑分析**
    1.  `fetchAndSendDataAes`函数中，先`fetch`密钥，然后用获取到的`key`和`iv`加密数据，流程清晰。

*   **第四步：编写联动加密脚本**
    脚本需要先请求密钥接口，然后再执行加密。

    **脚本 (`encrypt_level_3.py`)**: 
    ```python
    # C:\encrypt-labs-scripts\encrypt_level_3.py
    import sys, requests, json
    from base64 import b64encode
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    def encrypt_data(password):
        try:
            key_iv = requests.get("http://localhost:8080/encrypt/aesserver").json()
            key = key_iv['key'].encode('utf-8')
            iv = key_iv['iv'].encode('utf-8')
        except Exception:
            return "ERROR"
        data = {"username": "admin", "password": password}
        json_data = json.dumps(data).encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_bytes = cipher.encrypt(pad(json_data, AES.block_size))
        return b64encode(encrypted_bytes).decode('utf-8')

    if __name__ == "__main__":
        if len(sys.argv) > 1:
            print(encrypt_data(sys.argv[1]))
    ```

*   **第五步：配置Burp Intruder并爆破**
    1.  与第1关设置完全相同，请求路径为`/encrypt/aes`，调用的脚本换成`encrypt_level_3.py`。

---

### 第4关：Rsa加密

*   **第一步：抓包分析**
    1.  请求路径为 `/encrypt/rsa`，`x-www-form-urlencoded`格式，参数名为`data`。

*   **第二步：前端代码定位**
    1.  `easy.html`中找到`data-func="sendEncryptedDataRSA"`。

*   **第三步：JS逆向与逻辑分析**
    1.  `sendEncryptedDataRSA`函数中，硬编码了一个RSA公钥。
    2.  将登录数据的JSON字符串直接用此公钥加密，结果进行Base64编码。

*   **第四步：编写联动加密脚本**

    **脚本 (`encrypt_level_4.py`)**: 
    ```python
    # C:\encrypt-labs-scripts\encrypt_level_4.py
    import sys, json
    from base64 import b64encode
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5

    PUBLIC_KEY_PEM = '''
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRvA7giwinEkaTYllDYCkzujvi
    NH+up0XAKXQot8RixKGpB7nr8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlM
    DSj92Mr3xSaJcshZU8kfj325L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3Cb
    ocDbsNeCwNpRxwjIdQIDAQAB
    -----END PUBLIC KEY-----
    '''
    RSA_KEY = RSA.import_key(PUBLIC_KEY_PEM)

    def encrypt_data(password):
        data = {"username": "admin", "password": password}
        json_data = json.dumps(data).encode('utf-8')
        cipher = PKCS1_v1_5.new(RSA_KEY)
        return b64encode(cipher.encrypt(json_data)).decode('utf-8')

    if __name__ == "__main__":
        if len(sys.argv) > 1:
            print(encrypt_data(sys.argv[1]))
    ```

*   **第五步：配置Burp Intruder并爆破**
    1.  与第1关类似，请求路径为`/encrypt/rsa`，参数名为`data`，调用的脚本为`encrypt_level_4.py`。

---

### 第5关：AES+Rsa加密

*   **分析**: 此关卡是第2关的变种，逻辑完全一样，只是RSA公钥是硬编码在JS里的，而非从服务器获取。
*   **脚本 (`encrypt_level_5.py`)**: 与第2关脚本相比，只是把获取公钥的`requests`调用，换成第4关那样的硬编码公钥即可。
*   **Burp设置**: 与第2关完全相同，请求路径为`/encrypt/aesrsa`，调用的脚本为`encrypt_level_5.py`。

---

### 第6关：Des规律Key

*   **分析**: DES加密，其Key和IV是根据用户名动态生成的。JS代码中`encryptAndSendDataDES`函数清晰地展示了规则：Key是用户名前8位（不足用`6`补齐），IV是`9999`+用户名前4位（不足用`9`补齐）。只对密码加密，结果转为Hex。
*   **脚本 (`encrypt_level_6.py`)**: 
    ```python
    # C:\encrypt-labs-scripts\encrypt_level_6.py
    import sys
    from Crypto.Cipher import DES
    from Crypto.Util.Padding import pad

    def encrypt_data(password):
        username = "admin"
        password_bytes = password.encode('utf-8')
        key_str = (username[:8] + '6' * 8)[:8]
        iv_str = ('9999' + (username[:4] + '9' * 4)[:4])
        key = key_str.encode('utf-8')
        iv = iv_str.encode('utf-8')
        cipher = DES.new(key, DES.MODE_CBC, iv)
        encrypted_password_hex = cipher.encrypt(pad(password_bytes, DES.block_size)).hex()
        return encrypted_password_hex

    if __name__ == "__main__":
        if len(sys.argv) > 1:
            print(encrypt_data(sys.argv[1]))
    ```
*   **Burp设置**: 抓取`/encrypt/des`请求，在Intruder中仅标记JSON体里`password`的值，然后通过`Invoke shell`调用`encrypt_level_6.py`。

---

### 第7关：明文加签

*   **分析**: 数据明文传输，但附加了一个HMAC签名。`sendDataWithNonce`函数显示，`signature`是对`username + password + nonce + timestamp`的HMAC-SHA256签名，密钥硬编码为`be56e057f20f883e`。
*   **脚本 (`encrypt_level_7.py`)**: 脚本需返回用`|`分隔的4个动态值：password, nonce, timestamp, signature。
    ```python
    # C:\encrypt-labs-scripts\encrypt_level_7.py
    import sys, time, hmac, hashlib, random, string

    def generate_signature(password):
        username = "admin"
        nonce = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        timestamp = str(int(time.time()))
        secret_key = b"be56e057f20f883e"
        data_to_sign = f"{username}{password}{nonce}{timestamp}".encode('utf-8')
        signature = hmac.new(secret_key, data_to_sign, hashlib.sha256).hexdigest()
        return f"{password}|{nonce}|{timestamp}|{signature}"

    if __name__ == "__main__":
        if len(sys.argv) > 1:
            print(generate_signature(sys.argv[1]))
    ```
*   **Burp设置**: 使用`Pitchfork`模式，标记`password`, `nonce`, `timestamp`, `signature`四个值，为它们配置同一个`Invoke shell`，并分别用`Extract by separator`提取第1, 2, 3, 4部分。

---

### 第8关：加签key在服务器端

*   **分析**: 与第7关逻辑相同，但HMAC密钥是从`/encrypt/signdataserver`接口获取的。
*   **脚本 (`encrypt_level_8.py`)**: 脚本中增加一步`requests.get`来获取密钥。
    ```python
    # C:\encrypt-labs-scripts\encrypt_level_8.py
    import sys, time, hmac, hashlib, random, string, requests

    def generate_signature(password):
        try:
            secret_key = requests.get("http://localhost:8080/encrypt/signdataserver").json()['secretKey'].encode('utf-8')
        except Exception:
            return "ERROR|ERROR|ERROR|ERROR"
        username = "admin"
        nonce = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
        timestamp = str(int(time.time()))
        data_to_sign = f"{username}{password}{nonce}{timestamp}".encode('utf-8')
        signature = hmac.new(secret_key, data_to_sign, hashlib.sha256).hexdigest()
        return f"{password}|{nonce}|{timestamp}|{signature}"

    if __name__ == "__main__":
        if len(sys.argv) > 1:
            print(generate_signature(sys.argv[1]))
    ```
*   **Burp设置**: 与第7关完全相同，只是调用的脚本换成`encrypt_level_8.py`。

---

### 第9关：禁止重放

*   **分析**: `generateRequestData`函数显示，请求中`random`字段的值是**当前毫秒级时间戳**经由一个硬编码的RSA公钥加密的结果。服务器以此来校验请求的时效性和唯一性。
*   **脚本 (`encrypt_level_9.py`)**: 脚本不接收参数，每次运行都只生成一个加密后的当前时间戳。
    ```python
    # C:\encrypt-labs-scripts\encrypt_level_9.py
    import sys, time
    from base64 import b64encode
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_v1_5

    PUBLIC_KEY_PEM = '''
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRvA7giwinEkaTYllDYCkzujvi
    NH+up0XAKXQot8RixKGpB7nr8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlM
    DSj92Mr3xSaJcshZU8kfj325L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3Cb
    ocDbsNeCwNpRxwjIdQIDAQAB
    -----END PUBLIC KEY-----
    '''
    RSA_KEY = RSA.import_key(PUBLIC_KEY_PEM)

    def encrypt_timestamp():
        timestamp_ms = str(int(time.time() * 1000)).encode('utf-8')
        cipher = PKCS1_v1_5.new(RSA_KEY)
        return b64encode(cipher.encrypt(timestamp_ms)).decode('utf-8')

    if __name__ == "__main__":
        print(encrypt_timestamp())
    ```
*   **Burp设置**: 使用`Pitchfork`模式，标记`password`和`random`的值。**Payload Set 1** (`password`)使用密码字典。**Payload Set 2** (`random`)使用`Null payloads`类型，生成数量与密码字典相同，并通过`Invoke shell`调用`encrypt_level_9.py`来为每次请求生成动态的加密时间戳。