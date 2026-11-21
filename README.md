# Glue

import bz2
import contextlib
import gc
import hashlib
import http.client
import hmac
import io
import json
import os
import resource
import sys
import time
import types
import urllib.parse
import warnings
import zlib

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from boto3.s3.transfer import TransferConfig
from s3transfer.manager import TransferManager
from cryptography import utils as _crypto_utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.utils import CryptographyDeprecationWarning
from awsglue.utils import getResolvedOptions

try:
    from urllib3.exceptions import HTTPError as _Urllib3HTTPError
except ImportError:
    _Urllib3HTTPError = ()  # type: ignore[assignment]

# ==============================================================================
# Compatibilidade do pgpy==0.6.0 no AWS Glue 6 (Python 3.13 + cryptography >= 43)
# ==============================================================================
warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)

try:
    import imghdr  # noqa: F401
except ModuleNotFoundError:
    _imghdr_stub = types.ModuleType('imghdr')
    _imghdr_stub.what = lambda file, h=None: None
    sys.modules['imghdr'] = _imghdr_stub

if not hasattr(_crypto_utils, 'int_from_bytes'):
    _crypto_utils.int_from_bytes = (
        lambda data, byteorder='big', signed=False: int.from_bytes(
            data, byteorder=byteorder, signed=signed
        )
    )

if not hasattr(_crypto_utils, 'int_to_bytes'):
    def _compat_int_to_bytes(integer: int, length: int | None = None) -> bytes:
        if length is None:
            length = max(1, (integer.bit_length() + 7) // 8)
        return integer.to_bytes(length, 'big')

    _crypto_utils.int_to_bytes = _compat_int_to_bytes

try:
    from cryptography.hazmat.decrepit.ciphers import algorithms as _decrepit_algos
    for _algo_name in ('CAST5', 'Blowfish', 'IDEA', 'SEED', 'ARC4', 'TripleDES'):
        if not hasattr(algorithms, _algo_name) and hasattr(_decrepit_algos, _algo_name):
            setattr(algorithms, _algo_name, getattr(_decrepit_algos, _algo_name))
except ImportError:
    pass

try:
    from cryptography.hazmat.decrepit import hashes as _decrepit_hashes
    if not hasattr(hashes, 'RIPEMD160') and hasattr(_decrepit_hashes, 'RIPEMD160'):
        setattr(hashes, 'RIPEMD160', getattr(_decrepit_hashes, 'RIPEMD160'))
except ImportError:
    pass

import pgpy  # noqa: E402
from pgpy.constants import KeyFlags  # noqa: E402

# ==============================================================================
# Configurações Globais e Limites de Memória
# ==============================================================================
CHUNK_SIZE = 1024 * 1024  # 1 MB fixo por bloco de leitura/descompressão
MULTIPART_CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB por parte S3 (suporta até 640 GB por arquivo)
RECEIVED_PREFIX = 'Pismo/Files/Received/'
DECRYPTED_PREFIX = 'Pismo/Files/Decrypted/'
KNOWN_DATA_EXTENSIONS = ('.txt', '.csv', '.json', '.xml', '.tsv', '.dat', '.parquet')

# 10 tentativas em modo 'standard' suportam ~2,5 minutos de oscilação de rede/S3/KMS
BOTO_CONFIG = Config(
    connect_timeout=30,
    read_timeout=300,
    max_pool_connections=16,
    tcp_keepalive=True,
    retries={'max_attempts': 10, 'mode': 'standard'}
)


def get_optional_arg(name: str) -> str | None:
    """Lê parâmetro opcional de sys.argv sem falhar se vier vazio, 'None' ou ausente."""
    prefix = f"--{name}"
    val = None
    for i, arg in enumerate(sys.argv):
        if arg.startswith(f"{prefix}="):
            val = arg.split("=", 1)[1].strip()
        elif arg == prefix and i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("--"):
            val = sys.argv[i + 1].strip()
    if not val or val.lower() in ('none', 'null'):
        return None
    return val


args = getResolvedOptions(sys.argv, [
    'BUCKET_NAME',
    'SECRET_NAME'
])
OPTIONAL_INPUT_KEY = get_optional_arg('INPUT_KEY')

s3_client = boto3.client('s3', config=BOTO_CONFIG)
secrets_client = boto3.client('secretsmanager', config=BOTO_CONFIG)

# Verifica se a versão do botocore/s3transfer no Glue 6 mapeia IfNoneMatch sem enviá-lo no CreateMultipartUpload
_put_members = s3_client.meta.service_model.operation_model('PutObject').input_shape.members
_cmp_members = s3_client.meta.service_model.operation_model('CompleteMultipartUpload').input_shape.members
_cmu_members = s3_client.meta.service_model.operation_model('CreateMultipartUpload').input_shape.members
SUPPORTS_CONDITIONAL_WRITE = (
    'IfNoneMatch' in getattr(TransferManager, 'ALLOWED_UPLOAD_ARGS', ())
    and 'IfNoneMatch' in _put_members
    and 'IfNoneMatch' in _cmp_members
    and 'IfNoneMatch' not in _cmu_members
)


def get_ram_metrics_str() -> str:
    """Retorna RAM atual (VmRSS) e pico histórico (ru_maxrss) do processo Python em MB."""
    peak_mb = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 2)
    current_mb = peak_mb
    try:
        with open('/proc/self/status', 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    current_mb = round(int(line.split()[1]) / 1024, 2)
                    break
    except OSError:
        pass
    return f"Atual: {current_mb} MB | Pico: {peak_mb} MB"


def object_exists(bucket: str, key: str) -> bool:
    """Verifica se o objeto já existe no S3 sem baixar seu conteúdo."""
    try:
        s3_client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as exc:
        code = str(exc.response.get('Error', {}).get('Code', ''))
        status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode', 0)
        if code in ('404', 'NoSuchKey', 'NotFound') or status == 404:
            return False
        raise


def resolve_input_s3_key(raw_key: str, bucket: str) -> str:
    """
    Normaliza URI s3://bucket/... e resolve chaves URL-encoded vindas de eventos S3
    sem corromper chaves que possuam '%' literal no nome.
    """
    s3_uri_prefix = f"s3://{bucket}/"
    if raw_key.startswith(s3_uri_prefix):
        raw_key = raw_key[len(s3_uri_prefix):]
    clean_key = raw_key.lstrip('/')

    if '%' in clean_key or '+' in clean_key:
        if not object_exists(bucket, clean_key):
            decoded_key = urllib.parse.unquote_plus(clean_key)
            if decoded_key != clean_key and object_exists(bucket, decoded_key):
                return decoded_key
    return clean_key


def build_decrypted_key(input_key: str) -> str:
    """Converte 'Pismo/Files/Received/[sub/]nome.gpg' em 'Pismo/Files/Decrypted/[sub/]nome.txt'."""
    if input_key.startswith(RECEIVED_PREFIX):
        rel_path = input_key[len(RECEIVED_PREFIX):]
    else:
        rel_path = os.path.basename(input_key)

    if rel_path.lower().endswith('.gpg'):
        rel_path = rel_path[:-4]
    if not rel_path.lower().endswith(KNOWN_DATA_EXTENSIONS):
        rel_path = f"{rel_path}.txt"
    return f"{DECRYPTED_PREFIX}{rel_path}"


def list_pending_gpg_keys(bucket: str) -> list[str]:
    """Lista arquivos .gpg em Pismo/Files/Received/ ainda não gravados em Pismo/Files/Decrypted/."""
    paginator = s3_client.get_paginator('list_objects_v2')

    existing_decrypted = set()
    for page in paginator.paginate(Bucket=bucket, Prefix=DECRYPTED_PREFIX):
        for obj in page.get('Contents', []):
            existing_decrypted.add(obj['Key'])

    pending = []
    for page in paginator.paginate(Bucket=bucket, Prefix=RECEIVED_PREFIX):
        for obj in page.get('Contents', []):
            key = obj['Key']
            if not key.lower().endswith('.gpg'):
                continue
            if obj['Size'] <= 0:
                print(f"[AVISO] Ignorando arquivo .gpg vazio (0 bytes): {key}")
                continue
            if build_decrypted_key(key) not in existing_decrypted:
                pending.append(key)
    return pending


class ResumableS3Stream:
    """
    Wrapper zero-buffer sobre StreamingBody do S3 com retomada automática via Range + IfMatch (ETag)
    em caso de perda de conectividade, reset de socket ou ReadTimeout no meio de arquivos multi-GB.
    """
    _TRANSIENT_CLIENT_CODES = {
        'RequestTimeout', 'InternalError', 'SlowDown', 'ServiceUnavailable', '500', '502', '503', '504'
    }
    _NETWORK_ERRORS = (BotoCoreError, OSError, http.client.HTTPException, _Urllib3HTTPError)

    def __init__(self, client, bucket: str, key: str, max_retries: int = 8):
        self._client = client
        self._bucket = bucket
        self._key = key
        self._max_retries = max_retries
        self._pos = 0
        self._etag = None
        self._content_length = None
        self._body = None
        self._open_with_retry(initial=True)

    @property
    def content_length(self) -> int | None:
        return self._content_length

    def _is_retryable_client_error(self, exc: ClientError) -> bool:
        code = str(exc.response.get('Error', {}).get('Code', ''))
        status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode', 0)
        if code in ('PreconditionFailed', '412'):
            raise RuntimeError(
                f"Arquivo de origem {self._key} foi alterado no S3 durante a leitura (ETag divergente)."
            ) from exc
        return code in self._TRANSIENT_CLIENT_CODES or status in (408, 429, 500, 502, 503, 504)

    def _open_with_retry(self, initial: bool = False) -> None:
        self.close()
        for attempt in range(self._max_retries + 1):
            try:
                kwargs = {'Bucket': self._bucket, 'Key': self._key}
                if not initial and self._pos > 0:
                    kwargs['Range'] = f'bytes={self._pos}-'
                if not initial and self._etag:
                    kwargs['IfMatch'] = self._etag

                resp = self._client.get_object(**kwargs)
                if initial:
                    self._etag = resp.get('ETag')
                    self._content_length = resp.get('ContentLength')
                self._body = resp['Body']
                return
            except ClientError as exc:
                if not self._is_retryable_client_error(exc) or attempt >= self._max_retries:
                    raise
                wait_sec = min(2 ** attempt, 30)
                print(
                    f"[S3 OPEN RETRY {attempt + 1}/{self._max_retries}] "
                    f"{self._key} no byte {self._pos} ({exc}) aguardando {wait_sec}s..."
                )
                time.sleep(wait_sec)
            except self._NETWORK_ERRORS as exc:
                if attempt >= self._max_retries:
                    raise
                wait_sec = min(2 ** attempt, 30)
                print(
                    f"[S3 OPEN RETRY {attempt + 1}/{self._max_retries}] "
                    f"{self._key} no byte {self._pos} ({type(exc).__name__}: {exc}) aguardando {wait_sec}s..."
                )
                time.sleep(wait_sec)

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b''
        if self._content_length is not None and self._pos >= self._content_length:
            return b''

        amt = None if (size is None or size < 0) else size
        needs_reopen = False

        for attempt in range(self._max_retries + 1):
            try:
                if needs_reopen:
                    self._open_with_retry(initial=False)
                    needs_reopen = False

                data = self._body.read(amt)
                if data:
                    self._pos += len(data)
                    return data

                if self._content_length is not None and self._pos < self._content_length:
                    raise IOError(
                        f"Conexão S3 encerrada prematuramente em {self._pos}/{self._content_length} bytes."
                    )
                return b''

            except ClientError as exc:
                if not self._is_retryable_client_error(exc) or attempt >= self._max_retries:
                    raise
                wait_sec = min(2 ** attempt, 30)
                print(
                    f"[S3 DOWNLOAD RETRY {attempt + 1}/{self._max_retries}] "
                    f"{self._key} no byte {self._pos} ({exc}) aguardando {wait_sec}s..."
                )
                time.sleep(wait_sec)
                needs_reopen = True

            except self._NETWORK_ERRORS as exc:
                if attempt >= self._max_retries:
                    raise
                wait_sec = min(2 ** attempt, 30)
                print(
                    f"[S3 DOWNLOAD RETRY {attempt + 1}/{self._max_retries}] "
                    f"{self._key} no byte {self._pos} ({type(exc).__name__}: {exc}) aguardando {wait_sec}s..."
                )
                time.sleep(wait_sec)
                needs_reopen = True

        return b''

    def close(self) -> None:
        if self._body is not None:
            try:
                self._body.close()
            except Exception:
                pass
            self._body = None


class GeneratorStream(io.RawIOBase):
    """Conecta o gerador de chunks em streaming direto ao upload_fileobj do Boto3 com RAM limitada."""
    def __init__(self, byte_generator, track_progress: bool = False):
        self._gen = byte_generator
        self._buf = bytearray()
        self._eof = False
        self._track_progress = track_progress
        self.bytes_streamed = 0
        self._next_log_mark = 500 * 1024 * 1024  # Loga progresso a cada 500 MB

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b''

        if size is None or size < 0:
            while not self._eof:
                try:
                    self._buf.extend(next(self._gen))
                except StopIteration:
                    self._eof = True
            out = bytes(self._buf)
            self._buf = bytearray()
        else:
            while len(self._buf) < size and not self._eof:
                try:
                    self._buf.extend(next(self._gen))
                except StopIteration:
                    self._eof = True
            out = bytes(self._buf[:size])
            del self._buf[:size]
            if not self._buf and self._eof:
                self._buf = bytearray()

        if self._track_progress and out:
            self.bytes_streamed += len(out)
            if self.bytes_streamed >= self._next_log_mark:
                gb = self.bytes_streamed / (1024 ** 3)
                print(f"[STREAM] Gravados: {gb:.2f} GB | RAM ({get_ram_metrics_str()})")
                self._next_log_mark += 500 * 1024 * 1024

        return out


def read_exact(stream, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def read_exact_or_raise(stream, n: int, context: str = "stream OpenPGP") -> bytes:
    data = read_exact(stream, n)
    if len(data) < n:
        raise ValueError(
            f"Fim inesperado em {context}: esperados {n} bytes, obtidos {len(data)} (arquivo truncado)."
        )
    return data


def read_packet_header(stream) -> tuple[int, bool, int, bytes]:
    """
    Lê o cabeçalho completo de um pacote OpenPGP (RFC 4880 Section 4.2).
    Retorna: (tag, is_partial, body_len, raw_header_bytes)
    """
    first = read_exact(stream, 1)
    if not first:
        return -1, False, 0, b''

    b0 = first[0]
    if not (b0 & 0x80):
        raise ValueError("Arquivo não está no formato binário OpenPGP (.gpg).")

    # New Format Packet (RFC 4880 Section 4.2.2)
    if b0 & 0x40:
        tag = b0 & 0x3F
        l0_bytes = read_exact_or_raise(stream, 1, "cabeçalho New Format")
        l0 = l0_bytes[0]

        if l0 < 192:
            return tag, False, l0, first + l0_bytes
        elif 192 <= l0 <= 223:
            l1_bytes = read_exact_or_raise(stream, 1, "comprimento de 2 bytes New Format")
            body_len = ((l0 - 192) << 8) + l1_bytes[0] + 192
            return tag, False, body_len, first + l0_bytes + l1_bytes
        elif l0 == 255:
            l_bytes = read_exact_or_raise(stream, 4, "comprimento de 5 bytes New Format")
            body_len = int.from_bytes(l_bytes, 'big')
            return tag, False, body_len, first + l0_bytes + l_bytes
        else:
            # Partial Body Length (224 <= l0 <= 254)
            body_len = 1 << (l0 & 0x1F)
            return tag, True, body_len, first + l0_bytes

    # Old Format Packet (RFC 4880 Section 4.2.1)
    tag = (b0 >> 2) & 0x0F
    len_type = b0 & 0x03
    if len_type == 0:
        lb = read_exact_or_raise(stream, 1, "cabeçalho Old Format (1 byte)")
        return tag, False, lb[0], first + lb
    elif len_type == 1:
        lb = read_exact_or_raise(stream, 2, "cabeçalho Old Format (2 bytes)")
        return tag, False, int.from_bytes(lb, 'big'), first + lb
    elif len_type == 2:
        lb = read_exact_or_raise(stream, 4, "cabeçalho Old Format (4 bytes)")
        return tag, False, int.from_bytes(lb, 'big'), first + lb
    return tag, False, -1, first


def iter_packet_body(stream, is_partial: bool, body_len: int):
    """Itera sobre o corpo de um pacote OpenPGP em blocos fixos de no máximo CHUNK_SIZE."""
    if not is_partial:
        if body_len < 0:
            while True:
                data = stream.read(CHUNK_SIZE)
                if not data:
                    break
                yield data
        else:
            rem = body_len
            while rem > 0:
                data = read_exact_or_raise(stream, min(CHUNK_SIZE, rem), "corpo de pacote OpenPGP")
                rem -= len(data)
                yield data
        return

    rem = body_len
    while True:
        while rem > 0:
            data = read_exact_or_raise(stream, min(CHUNK_SIZE, rem), "bloco partial-length")
            rem -= len(data)
            yield data

        l0 = read_exact_or_raise(stream, 1, "próximo cabeçalho partial-length")[0]
        if l0 < 192:
            rem = l0
            while rem > 0:
                data = read_exact_or_raise(stream, min(CHUNK_SIZE, rem), "último bloco partial-length (1 byte)")
                rem -= len(data)
                yield data
            break
        elif 192 <= l0 <= 223:
            l1 = read_exact_or_raise(stream, 1, "último bloco partial-length (2 bytes)")[0]
            rem = ((l0 - 192) << 8) + l1 + 192
            while rem > 0:
                data = read_exact_or_raise(stream, min(CHUNK_SIZE, rem), "último bloco partial-length (2 bytes)")
                rem -= len(data)
                yield data
            break
        elif l0 == 255:
            rem = int.from_bytes(
                read_exact_or_raise(stream, 4, "último bloco partial-length (5 bytes)"),
                'big'
            )
            while rem > 0:
                data = read_exact_or_raise(stream, min(CHUNK_SIZE, rem), "último bloco partial-length (5 bytes)")
                rem -= len(data)
                yield data
            break
        else:
            rem = 1 << (l0 & 0x1F)


def stream_decompress_bounded(decompressor, data: bytes):
    """Descomprime em fatias limitadas a CHUNK_SIZE para impedir picos de memória e perda de tail."""
    if decompressor is None:
        if data:
            yield data
        return

    if isinstance(decompressor, bz2.BZ2Decompressor):
        out = decompressor.decompress(data, max_length=CHUNK_SIZE)
        if out:
            yield out
        while not decompressor.needs_input and not decompressor.eof:
            out = decompressor.decompress(b'', max_length=CHUNK_SIZE)
            if out:
                yield out
            else:
                break
    else:
        out = decompressor.decompress(data, max_length=CHUNK_SIZE)
        if out:
            yield out
        while decompressor.unconsumed_tail:
            prev_tail_len = len(decompressor.unconsumed_tail)
            out = decompressor.decompress(
                decompressor.unconsumed_tail,
                max_length=CHUNK_SIZE
            )
            if out:
                yield out
            elif len(decompressor.unconsumed_tail) >= prev_tail_len:
                break


def unwrap_inner_openpgp(seipd_stream: GeneratorStream):
    stream = seipd_stream
    tag, is_partial, body_len, _ = read_packet_header(stream)

    if tag == 8:
        body_iter = iter_packet_body(stream, is_partial, body_len)
        first_chunk = next((c for c in body_iter if c), b'')
        if not first_chunk:
            raise ValueError("Pacote comprimido (Tag 8) vazio ou truncado.")

        comp_algo = first_chunk[0]
        initial_data = first_chunk[1:]

        if comp_algo == 0:
            decompressor = None
        elif comp_algo == 1:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        elif comp_algo == 2:
            decompressor = zlib.decompressobj(zlib.MAX_WBITS)
        elif comp_algo == 3:
            decompressor = bz2.BZ2Decompressor()
        else:
            raise ValueError(f"Algoritmo de compressão OpenPGP não suportado: {comp_algo}")

        def decompressed_gen():
            if initial_data:
                yield from stream_decompress_bounded(decompressor, initial_data)
            for c in body_iter:
                if c:
                    yield from stream_decompress_bounded(decompressor, c)

            # ZLIB (algo 2) e BZIP2 (algo 3) possuem trailer explícito;
            # ZIP/Deflate raw (algo 1) pode terminar com Z_SYNC_FLUSH sem BFINAL=1.
            if comp_algo in (2, 3) and decompressor is not None and not decompressor.eof:
                raise ValueError(f"Stream comprimido (algo {comp_algo}) truncado antes do fim.")

            if decompressor and hasattr(decompressor, 'flush'):
                tail = decompressor.flush()
                for offset in range(0, len(tail), CHUNK_SIZE):
                    yield tail[offset:offset + CHUNK_SIZE]

        stream = GeneratorStream(decompressed_gen())
        tag, is_partial, body_len, _ = read_packet_header(stream)

    # Ignora Signature (Tag 2), One-Pass Signature (Tag 4) e Marker Packet (Tag 10) em arquivos assinados
    while tag in (2, 4, 10):
        for _ in iter_packet_body(stream, is_partial, body_len):
            pass
        tag, is_partial, body_len, _ = read_packet_header(stream)

    if tag != 11:
        raise ValueError(f"Pacote interno inesperado (Tag {tag}). Esperado Literal Data (Tag 11).")

    lit_iter = iter_packet_body(stream, is_partial, body_len)
    buf = bytearray()
    header_parsed = False

    for chunk in lit_iter:
        if not header_parsed:
            buf.extend(chunk)
            if len(buf) >= 2:
                header_size = 2 + buf[1] + 4
                if len(buf) >= header_size:
                    header_parsed = True
                    if len(buf) > header_size:
                        yield bytes(buf[header_size:])
                    buf = bytearray()
        elif chunk:
            yield chunk

    if not header_parsed:
        raise ValueError("Cabeçalho Literal Data (Tag 11) incompleto ou truncado.")

    # Drena pacotes finais (ex.: Tag 2 Signature) e o stream SEIPD externo,
    # garantindo que decrypted_seipd_stream() sempre conclua e valide o SHA-1 MDC.
    while stream.read(CHUNK_SIZE):
        pass
    if seipd_stream is not stream:
        while seipd_stream.read(CHUNK_SIZE):
            pass


def load_private_key(secret_name: str, max_retries: int = 6) -> tuple[pgpy.PGPKey, str]:
    """Lê a chave privada do Secrets Manager (descriptografada via KMS) com retry resiliente."""
    retryable_codes = {
        'ThrottlingException', 'InternalServiceError', 'RequestTimeout',
        'ServiceUnavailable', 'KMSInvalidStateException'
    }
    network_errors = (BotoCoreError, OSError, http.client.HTTPException, _Urllib3HTTPError)
    secret_resp = None

    for attempt in range(max_retries + 1):
        try:
            secret_resp = secrets_client.get_secret_value(SecretId=secret_name)
            break
        except ClientError as exc:
            code = str(exc.response.get('Error', {}).get('Code', ''))
            status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode', 0)
            if (code in retryable_codes or status in (429, 500, 502, 503, 504)) and attempt < max_retries:
                wait_sec = min(2 ** attempt, 16)
                print(
                    f"[SECRET/KMS RETRY {attempt + 1}/{max_retries}] "
                    f"Falha ao obter/descriptografar secret ({code}) em {wait_sec}s..."
                )
                time.sleep(wait_sec)
                continue
            raise
        except network_errors as exc:
            if attempt >= max_retries:
                raise
            wait_sec = min(2 ** attempt, 16)
            print(
                f"[SECRET/KMS RETRY {attempt + 1}/{max_retries}] "
                f"Erro de rede ao acessar secret ({type(exc).__name__}) em {wait_sec}s..."
            )
            time.sleep(wait_sec)

    if 'SecretString' in secret_resp and secret_resp['SecretString'] is not None:
        secret_str = secret_resp['SecretString'].strip()
    elif 'SecretBinary' in secret_resp and secret_resp['SecretBinary'] is not None:
        raw_bin = secret_resp['SecretBinary']
        secret_str = (raw_bin.decode('utf-8') if isinstance(raw_bin, (bytes, bytearray)) else str(raw_bin)).strip()
    else:
        raise ValueError("Secret não contém SecretString nem SecretBinary.")

    if secret_str.startswith('{'):
        secret_dict = json.loads(secret_str)
        raw_key = secret_dict['private_key'].replace('\\n', '\n').strip()
        passphrase = secret_dict.get('passphrase') or ''
    else:
        raw_key = secret_str.replace('\\n', '\n').strip()
        passphrase = ''

    priv_key, _ = pgpy.PGPKey.from_blob(raw_key)
    return priv_key, passphrase


def get_ordered_decryption_keys(priv_key: pgpy.PGPKey) -> list[pgpy.PGPKey]:
    """Prioriza subchaves/chaves com flag de criptografia antes de chaves apenas de assinatura."""
    all_keys = [priv_key] + list(priv_key.subkeys.values())
    enc_flags = {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}
    preferred = []
    fallback = []
    for k in all_keys:
        try:
            if set(getattr(k, 'key_flags', ())) & enc_flags:
                preferred.append(k)
            else:
                fallback.append(k)
        except Exception:
            fallback.append(k)
    return preferred + fallback


def stream_decrypt_file(
    priv_key: pgpy.PGPKey,
    passphrase: str,
    bucket: str,
    input_key: str,
    output_key: str
) -> None:
    print(f"[INÍCIO] s3://{bucket}/{input_key} -> s3://{bucket}/{output_key}")
    s3_body = ResumableS3Stream(s3_client, bucket, input_key)
    session_key = None
    cipher_algo = None
    candidate_keys = get_ordered_decryption_keys(priv_key)

    try:
        if s3_body.content_length == 0:
            print(f"[AVISO] Ignorando arquivo .gpg vazio (0 bytes): s3://{bucket}/{input_key}")
            return

        while True:
            tag, is_partial, body_len, raw_hdr = read_packet_header(s3_body)
            if tag == -1:
                raise ValueError("Fim inesperado do arquivo antes dos dados criptografados.")

            if tag == 1 and session_key is None:
                if is_partial or body_len < 0 or body_len > 65536:
                    raise ValueError(
                        f"Cabeçalho PKESK (Tag 1) inválido ou tamanho excessivo: {body_len} bytes."
                    )

                pkesk_bytes = bytearray(raw_hdr)
                for part in iter_packet_body(s3_body, is_partial, body_len):
                    pkesk_bytes.extend(part)

                try:
                    pkesk_pkt = pgpy.packet.Packet(pkesk_bytes)
                except Exception:
                    continue

                for key in candidate_keys:
                    try:
                        unlock_ctx = (
                            key.unlock(passphrase)
                            if getattr(key, 'is_protected', False)
                            else contextlib.nullcontext()
                        )
                        with unlock_ctx:
                            cipher_algo, session_key = pkesk_pkt.decrypt(key._key)
                            break
                    except Exception:
                        continue

            elif tag == 18:
                if not session_key:
                    raise ValueError("Nenhuma chave privada compatível encontrada.")
                break
            elif tag in (9, 20):
                raise ValueError(f"Formato de criptografia OpenPGP não suportado (Tag {tag}).")
            else:
                for _ in iter_packet_body(s3_body, is_partial, body_len):
                    pass

        if int(cipher_algo) not in (7, 8, 9):
            raise ValueError(f"Algoritmo simétrico não suportado: {cipher_algo}")

        cipher = Cipher(algorithms.AES(bytes(session_key)), modes.CFB(b'\x00' * 16))
        decryptor = cipher.decryptor()

        def decrypted_seipd_stream():
            body_iter = iter_packet_body(s3_body, is_partial, body_len)
            first_chunk = next((c for c in body_iter if c), b'')
            if not first_chunk:
                raise ValueError("Pacote SEIPD (Tag 18) vazio ou truncado.")
            if first_chunk[0] != 1:
                raise ValueError(f"Versão SEIPD não suportada: {first_chunk[0]}")

            prefix_buf = bytearray()
            tail_buf = bytearray()
            prefix_checked = False
            mdc_hasher = hashlib.sha1()

            def process_cipher_bytes(c_bytes: bytes):
                nonlocal prefix_checked
                plain = decryptor.update(c_bytes)
                if not plain:
                    return

                if not prefix_checked:
                    prefix_buf.extend(plain)
                    if len(prefix_buf) < 18:
                        return
                    if prefix_buf[14:16] != prefix_buf[16:18]:
                        raise ValueError("Chave privada ou senha incorreta.")
                    prefix_checked = True
                    mdc_hasher.update(prefix_buf[:18])
                    tail_buf.extend(prefix_buf[18:])
                    prefix_buf.clear()
                else:
                    tail_buf.extend(plain)

                if len(tail_buf) > 22:
                    emit_len = len(tail_buf) - 22
                    out = bytes(tail_buf[:emit_len])
                    del tail_buf[:emit_len]
                    mdc_hasher.update(out)
                    yield out

            yield from process_cipher_bytes(first_chunk[1:])
            for enc_chunk in body_iter:
                if enc_chunk:
                    yield from process_cipher_bytes(enc_chunk)

            final_plain = decryptor.finalize()
            if final_plain:
                tail_buf.extend(final_plain)
                if len(tail_buf) > 22:
                    emit_len = len(tail_buf) - 22
                    out = bytes(tail_buf[:emit_len])
                    del tail_buf[:emit_len]
                    mdc_hasher.update(out)
                    yield out

            if len(tail_buf) != 22 or tail_buf[:2] != b'\xd3\x14':
                raise ValueError("Pacote MDC ausente ou arquivo GPG truncado.")

            mdc_hasher.update(tail_buf[:2])
            expected_sha1 = bytes(tail_buf[2:22])
            if not hmac.compare_digest(mdc_hasher.digest(), expected_sha1):
                raise ValueError("Falha de integridade (SHA-1 MDC divergente): arquivo corrompido.")

        seipd_stream = GeneratorStream(decrypted_seipd_stream())
        output_stream = GeneratorStream(
            unwrap_inner_openpgp(seipd_stream),
            track_progress=True
        )
        transfer_config = TransferConfig(
            multipart_chunksize=MULTIPART_CHUNK_SIZE,
            max_concurrency=3,
            max_io_queue=3
        )
        extra_args = {'IfNoneMatch': '*'} if SUPPORTS_CONDITIONAL_WRITE else {}

        try:
            s3_client.upload_fileobj(
                Fileobj=output_stream,
                Bucket=bucket,
                Key=output_key,
                ExtraArgs=extra_args,
                Config=transfer_config
            )
        except ClientError as exc:
            code = str(exc.response.get('Error', {}).get('Code', ''))
            status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode', 0)
            if code in ('PreconditionFailed', 'ConditionalRequestConflict', '412', '409') or status in (409, 412):
                print(
                    f"[IGNORADO] Upload concorrente detectado — destino já gravado por outro worker: "
                    f"s3://{bucket}/{output_key}"
                )
                return
            raise

        total_gb = output_stream.bytes_streamed / (1024 ** 3)
        print(f"[CONCLUÍDO] {output_key} ({total_gb:.2f} GB) | RAM ({get_ram_metrics_str()})")
    finally:
        s3_body.close()


if __name__ == '__main__':
    bucket_name = args['BUCKET_NAME']
    priv_key, passphrase = load_private_key(args['SECRET_NAME'])

    # Modo 1: Arquivo específico passado via SQS/Lambda (--INPUT_KEY)
    if OPTIONAL_INPUT_KEY and not OPTIONAL_INPUT_KEY.endswith('*.gpg'):
        src_key = resolve_input_s3_key(OPTIONAL_INPUT_KEY, bucket_name)
        dst_key = build_decrypted_key(src_key)
        if object_exists(bucket_name, dst_key):
            print(f"[IGNORADO] Destino já existe (sem sobrescrita): s3://{bucket_name}/{dst_key}")
        else:
            stream_decrypt_file(priv_key, passphrase, bucket_name, src_key, dst_key)
    # Modo 2: Varredura da pasta Pismo/Files/Received/*.gpg
    else:
        target_keys = list_pending_gpg_keys(bucket_name)
        print(f"[BATCH] Arquivos .gpg pendentes encontrados: {len(target_keys)}")

        failed_files = []
        for src_key in target_keys:
            dst_key = build_decrypted_key(src_key)
            try:
                stream_decrypt_file(priv_key, passphrase, bucket_name, src_key, dst_key)
            except Exception as exc:
                print(f"[ERRO] Falha ao processar {src_key}: {exc}")
                failed_files.append((src_key, str(exc)))
            finally:
                gc.collect()

        if failed_files:
            summary = "; ".join(f"{k} ({err})" for k, err in failed_files)
            raise RuntimeError(f"Batch concluído com {len(failed_files)} falha(s): {summary}")
