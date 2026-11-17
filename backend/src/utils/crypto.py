"""静态加密与密钥环。

密钥材料只保存在独立的 keyring 目录（独立挂载卷），数据库与业务产物中
只出现密钥 ID，绝不保存密钥本身。信封格式：

    enc::v1::<key_id>::base64(nonce(12) || ciphertext || tag)

算法为 AES-256-GCM（认证加密），AAD 绑定字段/对象标签，密文被篡改或
密钥缺失时抛出明确异常，调用方必须拒绝输出而不是返回半份结果。
"""
import os
import json
import base64
import fcntl
import secrets
import time
from contextlib import contextmanager

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.config.settings import KEYRING_DIR

ENVELOPE_PREFIX = 'enc::v1::'
KEY_ID_PREFIX = 'k'
_ALGO = 'AES-256-GCM'
_NONCE_BYTES = 12
_KEY_BYTES = 32


class KeyMissingError(Exception):
    """解密所需密钥在密钥环中不存在。"""


class CiphertextInvalidError(Exception):
    """密文损坏、版本不符或认证标签校验失败。"""


class KeyUseError(Exception):
    """密钥状态不允许当前操作（例如已停用密钥被用于加密）。"""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def _b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode('ascii'), validate=True)
    except Exception as exc:
        raise CiphertextInvalidError('密文编码损坏，已拒绝读取') from exc


class Keyring:
    """文件密钥环：manifest 记录状态，key-<id>.key 保存原始密钥。

    backend 与 worker 两个进程通过 fcntl 锁串行化所有写操作；读操作也
    持共享流程锁，保证不会读到轮换中间态。
    """

    def __init__(self, directory: str):
        self.directory = directory
        self._lock_path = os.path.join(directory, 'keyring.lock')
        self._manifest_path = os.path.join(directory, 'manifest.json')

    @contextmanager
    def _locked(self):
        os.makedirs(self.directory, exist_ok=True)
        with open(self._lock_path, 'a+') as lock_f:
            fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)

    def _read_manifest(self) -> dict:
        try:
            with open(self._manifest_path, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
        except FileNotFoundError as exc:
            raise KeyMissingError('密钥环尚未初始化') from exc
        except json.JSONDecodeError as exc:
            raise KeyMissingError('密钥环清单损坏，无法读取密钥') from exc
        if not manifest.get('keys') or not manifest.get('current'):
            raise KeyMissingError('密钥环清单不完整')
        return manifest

    def _write_manifest(self, manifest: dict):
        tmp = self._manifest_path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._manifest_path)

    def _key_path(self, key_id: str) -> str:
        return os.path.join(self.directory, f'key-{key_id}.key')

    def _load_key(self, key_id: str) -> bytes:
        path = self._key_path(key_id)
        try:
            with open(path, 'rb') as f:
                raw = base64.b64decode(f.read(), validate=True)
        except FileNotFoundError as exc:
            raise KeyMissingError(f'密钥 {key_id} 已缺失，无法解密该内容') from exc
        except Exception as exc:
            raise CiphertextInvalidError(f'密钥 {key_id} 材料损坏') from exc
        if len(raw) != _KEY_BYTES:
            raise CiphertextInvalidError(f'密钥 {key_id} 长度不合法')
        return raw

    def ensure_initialized(self) -> str:
        """首次启动时生成初始密钥；可用 ENCRYPTION_KEYS 环境变量注入。"""
        with self._locked():
            if os.path.exists(self._manifest_path):
                return self._read_manifest()['current']
            seeded = [k.strip() for k in os.getenv('ENCRYPTION_KEYS', '').split(',') if k.strip()]
            keys = []
            for index, material in enumerate(seeded, start=1):
                try:
                    raw = base64.b64decode(material, validate=True)
                except Exception as exc:
                    raise KeyUseError('ENCRYPTION_KEYS 必须是逗号分隔的 base64 密钥') from exc
                if len(raw) != _KEY_BYTES:
                    raise KeyUseError(f'第 {index} 个注入密钥不是 {_KEY_BYTES} 字节')
                key_id = f'{KEY_ID_PREFIX}{index:04d}'
                self._persist_key(key_id, raw)
                keys.append(self._key_meta(key_id, 'active'))
            if not keys:
                raw = AESGCM.generate_key(bit_length=256)
                key_id = f'{KEY_ID_PREFIX}0001'
                self._persist_key(key_id, raw)
                keys.append(self._key_meta(key_id, 'active'))
            current = keys[-1]['id']
            self._write_manifest({'version': 1, 'algo': _ALGO, 'current': current, 'keys': keys})
            try:
                os.chmod(self._manifest_path, 0o600)
            except OSError:
                pass
            return current

    def _persist_key(self, key_id: str, raw: bytes):
        path = self._key_path(key_id)
        if os.path.exists(path):
            raise KeyUseError(f'密钥 {key_id} 已存在，拒绝覆盖')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, base64.b64encode(raw))
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _key_meta(key_id: str, state: str) -> dict:
        return {'id': key_id, 'state': state, 'algorithm': _ALGO, 'created_at': time.time()}

    def current_key_id(self) -> str:
        with self._locked():
            return self._read_manifest()['current']

    def status(self) -> dict:
        """供页面展示：只含密钥 ID 与状态，绝不含密钥材料。"""
        with self._locked():
            manifest = self._read_manifest()
            return {
                'algo': manifest.get('algo', _ALGO),
                'current': manifest['current'],
                'keys': [{'id': k['id'], 'state': k['state'], 'created_at': k.get('created_at')}
                         for k in manifest['keys']],
            }

    def rotate(self) -> tuple[str, str]:
        """生成新密钥并切换当前密钥；旧密钥保留可解密但不再用于加密。"""
        with self._locked():
            manifest = self._read_manifest()
            seq = len(manifest['keys']) + 1
            key_id = f'{KEY_ID_PREFIX}{seq:04d}'
            raw = AESGCM.generate_key(bit_length=256)
            self._persist_key(key_id, raw)
            for meta in manifest['keys']:
                if meta['id'] == manifest['current']:
                    meta['state'] = 'prior'
            manifest['keys'].append(self._key_meta(key_id, 'active'))
            manifest['current'] = key_id
            self._write_manifest(manifest)
            previous = next(k['id'] for k in manifest['keys'] if k['state'] == 'prior')
            return previous, key_id

    def retire(self, key_id: str):
        """全部内容迁移完成后停用旧密钥（材料保留，仅应急解密）。"""
        with self._locked():
            manifest = self._read_manifest()
            if key_id == manifest['current']:
                raise KeyUseError('当前在用密钥不能停用')
            for meta in manifest['keys']:
                if meta['id'] == key_id and meta['state'] != 'retired':
                    meta['state'] = 'retired'
            self._write_manifest(manifest)

    def encrypt(self, plaintext: bytes, label: str, key_id: str | None = None) -> str:
        with self._locked():
            manifest = self._read_manifest()
            key_id = key_id or manifest['current']
            entry = next((k for k in manifest['keys'] if k['id'] == key_id), None)
            if entry is None:
                raise KeyMissingError(f'密钥 {key_id} 不存在，拒绝加密')
            if entry['state'] == 'retired':
                raise KeyUseError(f'密钥 {key_id} 已停用，不能用于新写入')
            raw = self._load_key(key_id)
        nonce = secrets.token_bytes(_NONCE_BYTES)
        ciphertext = AESGCM(raw).encrypt(nonce, plaintext, label.encode('utf-8'))
        return ENVELOPE_PREFIX + key_id + '::' + _b64e(nonce + ciphertext)

    def decrypt(self, envelope: str, label: str) -> bytes:
        if not isinstance(envelope, str) or not envelope.startswith(ENVELOPE_PREFIX):
            raise CiphertextInvalidError('不是合法的加密信封，已拒绝读取')
        parts = envelope.split('::', 3)
        if len(parts) != 4 or not parts[2]:
            raise CiphertextInvalidError('加密信封结构损坏，已拒绝读取')
        version, key_id, payload = parts[1], parts[2], parts[3]
        if version != 'v1':
            raise CiphertextInvalidError(f'不支持的密文版本 {version}，已拒绝读取')
        blob = _b64d(payload)
        if len(blob) <= _NONCE_BYTES + 16:
            raise CiphertextInvalidError('密文长度异常，已拒绝读取')
        nonce, ciphertext = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
        with self._locked():
            manifest = self._read_manifest()
            entry = next((k for k in manifest['keys'] if k['id'] == key_id), None)
            if entry is None:
                raise KeyMissingError(f'密钥 {key_id} 不存在，无法解密该内容')
            raw = self._load_key(key_id)
        try:
            return AESGCM(raw).decrypt(nonce, ciphertext, label.encode('utf-8'))
        except Exception as exc:
            raise CiphertextInvalidError('密文认证失败（内容可能被篡改或密钥不匹配），已拒绝读取') from exc

    def is_envelope(self, value) -> bool:
        return isinstance(value, str) and value.startswith(ENVELOPE_PREFIX)

    def envelope_key_id(self, envelope: str) -> str | None:
        if not self.is_envelope(envelope):
            return None
        parts = envelope.split('::', 3)
        return parts[2] if len(parts) == 4 else None


keyring = Keyring(KEYRING_DIR)


def current_key_id() -> str:
    """模型列默认值用：惰性保证密钥环已初始化，再返回当前密钥 ID。"""
    keyring.ensure_initialized()
    return keyring.current_key_id()


def encrypt_json(value, label: str) -> str:
    plaintext = json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
    return keyring.encrypt(plaintext, label)


def decrypt_json(envelope: str, label: str):
    return json.loads(keyring.decrypt(envelope, label).decode('utf-8'))


def encrypt_bytes(raw: bytes, label: str) -> str:
    return keyring.encrypt(raw, label)


def decrypt_bytes(envelope: str, label: str) -> bytes:
    return keyring.decrypt(envelope, label)
