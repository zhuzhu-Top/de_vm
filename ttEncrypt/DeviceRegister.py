import secrets
import uuid
import time
import json
import hashlib
import gzip
import requests # pip install requests
import ttEncryptorUtil


# 注: 协议来自Tiktok


def UUID():
    return str(uuid.uuid4())


def md5(message):
    md5_hash = hashlib.md5()
    md5_hash.update(message)
    return md5_hash.hexdigest()


def get_timestamp_in_millisecond():
    return int(time.time() * 1000)


def get_timestamp_in_second():
    return int(time.time())


def generate_android_id():
    return secrets.token_bytes(8).hex()


def http_post(url, headers, payload):    
    response = requests.request("POST", url, headers=headers, data=payload)    
    return response.text


def gzip_compress(buff):
    return gzip.compress(buff)


def get_post_data(android_id, cdid, google_aid, clientudid):    
    openudid = android_id
    postDataObj = {
        "magic_tag": "ss_app_log",
        "header": {
            "display_name": "TikTok",
            "update_version_code": 2023205030,
            "manifest_version_code": 2023205030,
            "app_version_minor": "",
            "aid": 1233,
            "channel": "googleplay",
            "package": "com.zhiliaoapp.musically",
            "app_version": "32.5.3",
            "version_code": 320503,
            "sdk_version": "3.9.17-bugfix.9",
            "sdk_target_version": 29,
            "git_hash": "3e93151",
            "os": "Android",
            "os_version": "11",
            "os_api": 30,
            "device_model": "Pixel 2",
            "device_brand": "google",
            "device_manufacturer": "Google",
            "cpu_abi": "arm64-v8a",
            "release_build": "e7cd5de_20231207",
            "density_dpi": 420,
            "display_density": "mdpi",
            "resolution": "1794x1080",
            "language": "en",
            "timezone": -5,
            "access": "wifi",
            "not_request_sender": 1,
            "rom": "6934943",
            "rom_version": "RP1A.201005.004.A1",
            "cdid": cdid,
            "sig_hash": "194326e82c84a639a52e5c023116f12a", # md5(packageInfo.signatures[0]) 
            "gaid_limited": 0,
            "google_aid": google_aid,
            "openudid": openudid,
            "clientudid": clientudid,
            "tz_name": "America\\/New_York",
            "tz_offset": -18000,
            "req_id": UUID(),
            "device_platform": "android",
            "custom": {
                "is_kids_mode": 0,
                "filter_warn": 0,
                "web_ua": "Mozilla\\/5.0 (Linux; Android 11; Pixel 2 Build\\/RP1A.201005.004.A1; wv) AppleWebKit\\/537.36 (KHTML, like Gecko) Version\\/4.0 Chrome\\/116.0.0.0 Mobile Safari\\/537.36",
                "user_period": 0,
                "screen_height_dp": 683,
                "user_mode": -1,
                "apk_last_update_time": 1702363135217,
                "screen_width_dp": 411
            },
            "apk_first_install_time": 1697783355395,
            "is_system_app": 0,
            "sdk_flavor": "global",
            "guest_mode": 0
        },
        "_gen_time": get_timestamp_in_millisecond()
    }
    
    return gzip_compress(json.dumps(postDataObj).encode(encoding='utf-8'))


def get_headers(md5Hash):
    headers = {
            'log-encode-type': 'gzip',
            'x-tt-request-tag': 't=0;n=1',
            'sdk-version': '2',
            'X-SS-REQ-TICKET': f'{get_timestamp_in_millisecond()}',
            'passport-sdk-version': '19',
            'x-tt-dm-status': 'login=0;ct=1;rt=4',
            'x-vc-bdturing-sdk-version': '2.3.4.i18n',
            'Content-Type': 'application/octet-stream;tt-data=a',
            'X-SS-STUB': md5Hash,
            'Host': 'log-va.tiktokv.com'
        }
    return headers


def get_device_register_url(openudid, cdid):
    url = 'https://log-va.tiktokv.com/service/2/device_register/?' + \
            "tt_data=a" + \
            "ac=wifi" + \
            "channel=googleplay" + \
            "aid=1233" + \
            "app_name=musical_ly" + \
            "version_code=320503" + \
            "version_name=32.5.3" + \
            "device_platform=android" + \
            "os=android" + \
            "ab_version=32.5.3" + \
            "ssmix=a" + \
            "device_type=Pixel+2" + \
            "device_brand=google" + \
            "language=en" + \
            "os_api=30" + \
            "os_version=11" + \
            f"openudid={openudid}" + \
            "manifest_version_code=2023205030" + \
            "resolution=1080*1794" + \
            "dpi=420" + \
            "update_version_code=2023205030" + \
            f"_rticket={get_timestamp_in_millisecond()}" + \
            "is_pad=0" + \
            "current_region=TW" + \
            "app_type=normal" + \
            "timezone_name=America%2FNew_York" + \
            "residence=TW" + \
            "app_language=en" + \
            "ac2=wifi5g" + \
            "uoo=0" + \
            "op_region=TW" + \
            "timezone_offset=-18000" + \
            "build_number=32.5.3" + \
            "host_abi=arm64-v8a" + \
            "locale=en" + \
            f"ts={get_timestamp_in_second()}" + \
            f"cdid={cdid}"
    return url


def device_register():    
    android_id = generate_android_id()
    cdid = UUID()
    google_aid = UUID()
    clientudid = UUID()
    gzip_post_data = get_post_data(android_id, cdid, google_aid, clientudid)
    ttencrypt_post_data = ttEncryptorUtil.ttEncrypt(gzip_post_data)
    headers = get_headers(md5(ttencrypt_post_data))
    url = get_device_register_url(android_id, cdid)
    response = http_post(url, headers, ttencrypt_post_data)
    print(f"设备注册结果:\n{response}")

if __name__ == "__main__":
    device_register()