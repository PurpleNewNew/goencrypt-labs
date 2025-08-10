document.addEventListener('DOMContentLoaded', function() {
    const menu = document.getElementById('challenge-menu');
    const loginButton = document.getElementById('login-button');

    // Set the first item as active by default
    let activeChallenge = menu.querySelector('a.active');

    menu.addEventListener('click', function(e) {
        e.preventDefault();
        if (e.target.tagName === 'A') {
            if (activeChallenge) {
                activeChallenge.classList.remove('active');
            }
            activeChallenge = e.target;
            activeChallenge.classList.add('active');
        }
    });

    loginButton.addEventListener('click', function() {
        if (activeChallenge) {
            const functionName = activeChallenge.dataset.func;
            const url = activeChallenge.dataset.url;
            if (window[functionName]) {
                window[functionName](url);
            } else {
                console.error('Function ' + functionName + ' not found.');
            }
        } else {
            alert('请先在左侧选择一个挑战关卡');
        }
    });
});

function sendDataAes(url) {
	const formData = {
		username: document.getElementById("username")
			.value,
		password: document.getElementById("password")
			.value
	};
	const jsonData = JSON.stringify(formData);

	const key = CryptoJS.enc.Utf8.parse("1234567890123456");
	const iv = CryptoJS.enc.Utf8.parse("1234567890123456");

	const encrypted = CryptoJS.AES.encrypt(jsonData, key, {
			iv: iv,
			mode: CryptoJS.mode.CBC,
			padding: CryptoJS.pad.Pkcs7
		})
		.toString();
    const params = `encryptedData=${encodeURIComponent(encrypted)}`;

	fetch(url.replace('.php', ''), {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
			},
			body: params
		})
		.then(response => response.json())
		.then(data => {
			if (data.success) {
				window.location.href = "success.html";
			} else {
				alert("用户名或密码错误");
			}
		})
		.catch(error => {
			console.error("请求错误:", error);
		});
}

function sendEncryptedDataRSA(url) {
	const publicKey = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRvA7giwinEkaTYllDYCkzujvi
NH+up0XAKXQot8RixKGpB7nr8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlM
DSj92Mr3xSaJcshZU8kfj325L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3Cb
ocDbsNeCwNpRxwjIdQIDAQAB
-----END PUBLIC KEY-----
  `;
	const username = document.getElementById("username").value;
	const password = document.getElementById("password").value;

	const dataPacket = {
		username: username,
		password: password
	};

	const dataString = JSON.stringify(dataPacket);

	const encryptor = new JSEncrypt();
	encryptor.setPublicKey(publicKey);

	const encryptedData = encryptor.encrypt(dataString);

	if (!encryptedData) {
		alert("加密失败，请检查公钥是否正确");
		return;
	}

	const formData = new URLSearchParams();
	formData.append('data', encryptedData);

	fetch(url.replace('.php', ''), {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded"
		},
		body: formData.toString()
	})
	.then(response => response.json())
	.then(data => {
		if (data.success) {
			window.location.href = "success.html";
		} else {
			alert(data.error || "用户名或密码错误");
		}
	})
	.catch(error => console.error("请求错误:", error));
}

function sendDataAesRsa(url) {
	const formData = {
		username: document.getElementById("username")
			.value,
		password: document.getElementById("password")
			.value
	};
	const jsonData = JSON.stringify(formData);

	const key = CryptoJS.lib.WordArray.random(16);
	const iv = key; // Use key as IV to match backend logic

	const encryptedData = CryptoJS.AES.encrypt(jsonData, key, {
			iv: iv,
			mode: CryptoJS.mode.CBC,
			padding: CryptoJS.pad.Pkcs7
		})
		.toString();

	const rsa = new JSEncrypt();
	rsa.setPublicKey(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRvA7giwinEkaTYllDYCkzujvi
NH+up0XAKXQot8RixKGpB7nr8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlM
DSj92Mr3xSaJcshZU8kfj325L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3Cb
ocDbsNeCwNpRxwjIdQIDAQAB
-----END PUBLIC KEY-----`);

	const encryptedKey = rsa.encrypt(key.toString(CryptoJS.enc.Base64));

	fetch(url.replace('.php', ''), {
			method: "POST",
			headers: {
				"Content-Type": "application/json"
			},
			body: JSON.stringify({
				encryptedData: encryptedData,
				encryptedKey: encryptedKey
			})
		})
		.then(response => response.json())
		.then(data => {
			if (data.success) {
				window.location.href = "success.html";
			} else {
				alert("用户名或密码错误");
			}
		})
		.catch(error => console.error("请求错误:", error));
}

async function fetchAndSendDataAes(url) {
	let aesKey, aesIv;

	try {
		const response = await fetch("/encrypt/aesserver");
		const data = await response.json();
		// FIX: Use correct JSON keys ('key', 'iv') and parse method (Utf8)
		aesKey = CryptoJS.enc.Utf8.parse(data.key);
		aesIv = CryptoJS.enc.Utf8.parse(data.iv);
	} catch (error) {
		console.error("获取 AES 密钥失败:", error);
		alert("无法获取 AES 密钥，请刷新页面重试");
		return;
	}

	const formData = {
		username: document.getElementById("username")
			.value,
		password: document.getElementById("password")
			.value
	};
	const jsonData = JSON.stringify(formData);

	const encryptedData = CryptoJS.AES.encrypt(jsonData, aesKey, {
			iv: aesIv,
			mode: CryptoJS.mode.CBC,
			padding: CryptoJS.pad.Pkcs7
		})
		.toString();

    const params = `encryptedData=${encodeURIComponent(encryptedData)}`;

	fetch(url.replace('.php', ''), {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
			},
			body: params
		})
		.then(response => response.json())
		.then(data => {
			if (data.success) {
				window.location.href = "success.html";
			} else {
				alert("用户名或密码错误");
			}
		})
		.catch(error => {
			console.error("请求错误:", error);
		});
}

function encryptAndSendDataDES(url) {
	const username = document.getElementById("username")
		.value;
	const password = document.getElementById("password")
		.value;

	const key = CryptoJS.enc.Utf8.parse(username.slice(0, 8)
		.padEnd(8, '6'));

	const iv = CryptoJS.enc.Utf8.parse('9999' + username.slice(0, 4)
		.padEnd(4, '9'));

	const encryptedPassword = CryptoJS.DES.encrypt(password, key, {
		iv: iv,
		mode: CryptoJS.mode.CBC,
		padding: CryptoJS.pad.Pkcs7
	});

	const encryptedHex = encryptedPassword.ciphertext.toString(CryptoJS.enc.Hex);

	fetch(url.replace('.php', ''), {
			method: "POST",
			headers: {
				"Content-Type": "application/json"
			},
			body: JSON.stringify({
				username: username,
				password: encryptedHex
			})
		})
		.then(response => response.json())
		.then(data => {
			if (data.success) {
				window.location.href = "success.html";
			} else {
				alert("用户名或密码错误");
			}
		})
		.catch(error => console.error("请求错误:", error));
}

function sendDataWithNonce(url) {
	const username = document.getElementById("username")
		.value;
	const password = document.getElementById("password")
		.value;

	const nonce = Math.random()
		.toString(36)
		.substring(2);
	const timestamp = Math.floor(Date.now() / 1000);

	const secretKey = "be56e057f20f883e";

	const dataToSign = username + password + nonce + timestamp;
	const signature = CryptoJS.HmacSHA256(dataToSign, secretKey)
		.toString(CryptoJS.enc.Hex);

	fetch(url.replace('.php', ''), {
			method: "POST",
			headers: {
				"Content-Type": "application/json"
			},
			body: JSON.stringify({
				username: username,
				password: password,
				nonce: nonce,
				timestamp: timestamp,
				signature: signature
			})
		})
		.then(response => response.json())
		.then(data => {
			if (data.success) {
				window.location.href = "success.html";
			} else {
				alert(data.error || "用户名或密码错误");
			}
		})
		.catch(error => console.error("请求错误:", error));
}

async function sendDataWithNonceServer(url) {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    const timestamp = Math.floor(Date.now() / 1000); // 当前时间戳

    try {
        const signResponse = await fetch("/encrypt/signdataserver", {
            method: "GET",
            headers: {
                "Content-Type": "application/json",
            },
        });
        if (!signResponse.ok) {
            console.error("获取签名失败:", signResponse.statusText);
            alert("获取签名失败，请稍后重试。");
            return;
        }

        const { secretKey } = await signResponse.json();

        if (!secretKey) {
            alert("签名获取失败，服务器未返回签名。");
            return;
        }

		// FIX: Define nonce before using it
		const nonce = Math.random().toString(36).substring(2);
        const dataToSign = username + password + nonce + timestamp;
	    const signature = CryptoJS.HmacSHA256(dataToSign, secretKey)
		    .toString(CryptoJS.enc.Hex);

        const submitResponse = await fetch(url.replace('.php', ''), {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                username: username,
                password: password,
                nonce: nonce,
                timestamp: timestamp,
                signature: signature,
            }),
        });

        if (!submitResponse.ok) {
            console.error("数据提交失败:", submitResponse.statusText);
            alert("提交数据失败，请稍后重试。");
            return;
        }

        const data = await submitResponse.json();

        if (data.success) {
            window.location.href = "success.html";
        } else {
            alert(data.error || "用户名或密码错误");
        }
    } catch (error) {
        console.error("请求错误:", error);
        alert("发生错误，请稍后重试。");
    }

}

function generateRequestData() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const timestamp = Date.now();

    const publicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRvA7giwinEkaTYllDYCkzujvi
NH+up0XAKXQot8RixKGpB7nr8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlM
DSj92Mr3xSaJcshZU8kfj325L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3Cb
ocDbsNeCwNpRxwjIdQIDAQAB
-----END PUBLIC KEY-----`;

    function rsaEncrypt(data, publicKey) {
        const jsEncrypt = new JSEncrypt(); 
        jsEncrypt.setPublicKey(publicKey);
        const encrypted = jsEncrypt.encrypt(data.toString());
        if (!encrypted) {
            throw new Error("RSA encryption failed.");
        }
        return encrypted;
    }

    // Encrypt the timestamp
    let encryptedTimestamp;
    try {
        encryptedTimestamp = rsaEncrypt(timestamp, publicKey);
    } catch (error) {
        console.error("Encryption error:", error);
        return null;
    }

    const dataToSend = {
        username: username,
        password: password,
        random: encryptedTimestamp // Replace timestamp with encrypted version
    };

    return dataToSend;
}


function sendLoginRequest(url) {
	const dataToSend = generateRequestData();

	fetch(url.replace('.php', ''), {
			method: "POST",
			headers: {
				"Content-Type": "application/json; charset=utf-8"
			},
			body: JSON.stringify(dataToSend)
		})
		.then(response => response.json())
		.then(data => {
			if (data.success) {
				window.location.href = "success.html";
			} else {
				alert(data.error || "用户名或密码错误");
			}
		})
		.catch(error => console.error("请求错误:", error));
}

async function sendDataRandomAes(url) {
	// 1. Fetch the public key from the server
	let publicKey;
	try {
		const response = await fetch('/encrypt/get-public-key');
		const data = await response.json();
		if (!data.publicKey) {
			alert('Failed to retrieve public key.');
			return;
		}
		publicKey = data.publicKey;
	} catch (error) {
		console.error('Error fetching public key:', error);
		alert('Could not fetch public key from server.');
		return;
	}

	const formData = {
		username: document.getElementById("username").value,
		password: document.getElementById("password").value
	};
	const jsonData = JSON.stringify(formData);

	// 2. Generate random AES key and IV
	const key = CryptoJS.lib.WordArray.random(16);
	const iv = key; // Using key as IV for simplicity

	// 3. Encrypt data with the random AES key
	const encryptedData = CryptoJS.AES.encrypt(jsonData, key, {
		iv: iv,
		mode: CryptoJS.mode.CBC,
		padding: CryptoJS.pad.Pkcs7
	}).toString();

	// 4. Encrypt the random AES key with the fetched RSA public key
	const rsa = new JSEncrypt();
	rsa.setPublicKey(publicKey);

	const encryptedKey = rsa.encrypt(key.toString(CryptoJS.enc.Base64));

	if (!encryptedKey) {
		alert("RSA encryption of the key failed.");
		return;
	}

	// 5. Send encrypted data and encrypted key to server
	fetch(url, {
		method: "POST",
		headers: {
			"Content-Type": "application/json"
		},
		body: JSON.stringify({
			encryptedData: encryptedData,
			encryptedKey: encryptedKey
		})
	})
	.then(response => response.json())
	.then(data => {
		if (data.success) {
			window.location.href = "success.html";
		} else {
			alert(data.error || "用户名或密码错误");
		}
	})
	.catch(error => console.error("请求错误:", error));
}
