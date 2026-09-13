"""StegoVault core: LSB steganography for images, audio and video.

Carriers: any image PIL can open, any audio (other than integer-WAV is
transcoded through the bundled ffmpeg) and any video OpenCV can decode
(outputs are always lossless PNG/BMP, WAV or AVI).
Payloads: UTF-8 text or arbitrary files (images, audio, video, ...).
Every payload is wrapped in a robust length-tagged container so extraction
always knows exactly how many bits to read (fixes the fragile delimiter
approach that caused the old "no payload found" bug):

    header = b'STE1' + flags(1) + blob_size(4, big-endian)
    blob   = AES-256-GCM( inner ) when encrypted, else the plain inner
    inner  = kind(1) + name_len(2) + name + data_len(4) + data
"""

import os
import subprocess
import tempfile
import struct
import hashlib

import cv2
import numpy as np
from PIL import Image
from scipy.io import wavfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AVI_FCC = b'DIB '

MAGIC = b'STE1'
KIND_TEXT = 0
KIND_FILE = 1


class StegoError(Exception):
    pass


class NoPayloadFound(StegoError):
    pass


class CapacityError(StegoError):
    pass


class WrongPassword(StegoError):
    pass


class CorruptedPayload(StegoError):
    pass


def _derived_key(password):
    return hashlib.sha256(password.encode('utf-8')).digest()


def _encrypt(data, password):
    nonce = os.urandom(12)
    ciphertext = AESGCM(_derived_key(password)).encrypt(nonce, data, None)
    return nonce + ciphertext


def _decrypt(blob, password):
    try:
        return AESGCM(_derived_key(password)).decrypt(blob[:12], blob[12:], None)
    except Exception as exc:
        raise WrongPassword('Wrong password. The payload could not be decrypted.') from exc


def _pack_inner(kind, name, data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    name_bytes = name.encode('utf-8')[:0xFFFF]
    header = bytes([kind]) + struct.pack('>H', len(name_bytes)) + name_bytes
    return header + struct.pack('>I', len(data)) + data


def _unpack_inner(inner):
    if len(inner) < 7:
        raise CorruptedPayload('The hidden payload is too short to be valid.')
    kind = inner[0]
    if kind not in (KIND_TEXT, KIND_FILE):
        raise CorruptedPayload('The hidden payload header is invalid.')
    name_len = struct.unpack('>H', inner[1:3])[0]
    if len(inner) < 3 + name_len + 4:
        raise CorruptedPayload('The hidden payload is truncated.')
    name = inner[3:3 + name_len].decode('utf-8', errors='replace')
    offset = 7 + name_len
    data_len = struct.unpack('>I', inner[3 + name_len:offset])[0]
    if len(inner) < offset + data_len:
        raise CorruptedPayload('The hidden payload is truncated.')
    return kind, name, inner[offset:offset + data_len]


def build_payload(kind, name, data, password):
    inner = _pack_inner(kind, name, data)
    if password:
        blob = _encrypt(inner, password)
        flags = 1
    else:
        blob = inner
        flags = 0
    return MAGIC + bytes([flags]) + struct.pack('>I', len(blob)) + blob


def unpack_payload(raw, password):
    if raw[:4] != MAGIC:
        raise NoPayloadFound('No hidden payload found in this file.')
    flags = raw[4]
    blob_size = struct.unpack('>I', raw[5:9])[0]
    blob = raw[9:9 + blob_size]
    if len(blob) < blob_size:
        raise CorruptedPayload('The hidden payload is incomplete or damaged.')
    if flags & 1:
        if not password:
            raise WrongPassword('This payload is encrypted. Enter the password that was used to hide it.')
        inner = _decrypt(blob, password)
    else:
        inner = blob
    return _unpack_inner(inner)


def _embed_bits_into(flat, payload):
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    if bits.size > flat.size:
        raise CapacityError(
            'The hidden payload is too large for this carrier. '
            'Use a bigger cover file or a smaller payload.')
    np.bitwise_and(flat[:bits.size], 0xFE, out=flat[:bits.size], casting='unsafe')
    flat[:bits.size] |= bits
    return len(payload)


def _read_bytes(flat, offset_bits, count_bytes):
    end = offset_bits + count_bytes * 8
    if end > flat.size:
        raise NoPayloadFound('No hidden payload found in this file.')
    slice_bits = (flat[offset_bits:end] & 1).astype(np.uint8)
    return np.packbits(slice_bits).tobytes()


def _read_payload(flat):
    header = _read_bytes(flat, 0, 9)
    if header[:4] != MAGIC:
        raise NoPayloadFound('No hidden payload found in this file.')
    blob_size = struct.unpack('>I', header[5:9])[0]
    blob = _read_bytes(flat, 72, blob_size)
    return header + blob


def _load_image_cover(path):
    try:
        return np.array(Image.open(path).convert('RGB'))
    except Exception:
        raise StegoError('Could not decode this file as an image. '
                         'Use a PNG, JPEG, GIF, WebP, TIFF or BMP cover.')


def image_capacity_bytes(path):
    image = _load_image_cover(path)
    return int(image.size) // 8


def embed_image(cover_path, kind, name, data, password, out_path):
    image = _load_image_cover(cover_path)
    flat = image.reshape(-1)
    payload = build_payload(kind, name, data, password)
    _embed_bits_into(flat, payload)
    extension = os.path.splitext(out_path)[1].lower()
    fmt = 'BMP' if extension == '.bmp' else 'PNG'
    Image.fromarray(image).save(out_path, fmt)


def extract_image(path, password):
    image = np.array(Image.open(path).convert('RGB'))
    raw = _read_payload(image.reshape(-1))
    return unpack_payload(raw, password)


def audio_capacity_bytes(path):
    sample_rate, samples, temp_path = _load_audio_cover(path)
    capacity = int(samples.size) // 8
    _cleanup_temp(temp_path)
    return capacity


def _ffmpeg_binary():
    try:
        import imageio_ffmpeg
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        return None


def _cleanup_temp(path):
    if path:
        try:
            os.remove(path)
        except OSError:
            pass


def _transcode_to_wav(cover_path):
    ffmpeg = _ffmpeg_binary()
    if not ffmpeg:
        raise StegoError('This cover format needs transcoding first. '
                         'Run "pip install imageio-ffmpeg" once to enable MP3/FLAC/OGG/M4A covers, '
                         'or use a WAV cover.')
    fd, temp_path = tempfile.mkstemp(suffix='.wav')
    os.close(fd)
    try:
        result = subprocess.run(
            [ffmpeg, '-y', '-hide_banner', '-i', cover_path,
             '-vn', '-acodec', 'pcm_s16le', temp_path],
            capture_output=True)
        if result.returncode != 0 or not os.path.exists(temp_path):
            raise StegoError('Could not decode this file as audio. '
                             'Use a WAV, MP3, FLAC, OGG or M4A cover.')
        sample_rate, samples = wavfile.read(temp_path)
    except StegoError:
        _cleanup_temp(temp_path)
        raise
    except Exception:
        _cleanup_temp(temp_path)
        raise StegoError('Could not decode this file as audio. '
                         'Use a WAV, MP3, FLAC, OGG or M4A cover.')
    return sample_rate, samples, temp_path


def _load_audio_cover(cover_path):
    try:
        sample_rate, samples = wavfile.read(cover_path)
        if np.issubdtype(samples.dtype, np.integer):
            return sample_rate, samples, None
    except Exception:
        pass
    return _transcode_to_wav(cover_path)


def embed_audio(cover_path, kind, name, data, password, out_path):
    sample_rate, samples, temp_path = _load_audio_cover(cover_path)
    try:
        original_shape = samples.shape
        flat = samples.astype(np.int32).reshape(-1)
        payload = build_payload(kind, name, data, password)
        _embed_bits_into(flat, payload)
        result = flat.reshape(original_shape).astype(samples.dtype)
        wavfile.write(out_path, sample_rate, result)
    finally:
        _cleanup_temp(temp_path)


def extract_audio(path, password):
    _, samples = wavfile.read(path)
    raw = _read_payload(samples.astype(np.int32).reshape(-1))
    return unpack_payload(raw, password)


def _frame_to_dib(frame):
    height, width = frame.shape[:2]
    row_bytes = (width * 3 + 3) & ~3
    dib = np.zeros((height * row_bytes,), dtype=np.uint8)
    for y in range(height):
        row = frame[height - 1 - y].reshape(-1)
        start = y * row_bytes
        dib[start:start + width * 3] = row
    return dib


def _fit_dimension(frame, max_dimension):
    height, width = frame.shape[:2]
    largest = max(width, height)
    if largest <= max_dimension:
        return frame
    scale = max_dimension / largest
    new_width = int(width * scale) & ~1
    new_height = int(height * scale) & ~1
    return cv2.resize(frame, (new_width, new_height), interpolation=cv2.INTER_AREA)


def _synthetic_frame(width, height, index, total):
    t = index / max(1, total)
    x = np.linspace(0.0, 255.0, width, dtype=np.float32)
    y = np.linspace(0.0, 255.0, height, dtype=np.float32)
    grid_x, grid_y = np.meshgrid(x, y)
    frame = np.empty((height, width, 3), dtype=np.uint8)
    frame[..., 0] = ((grid_x + 255 * t) % 256).astype(np.uint8)
    frame[..., 1] = ((grid_y + 255 * t) % 256).astype(np.uint8)
    frame[..., 2] = (((grid_x + grid_y) * 0.5 + 255 * t) % 256).astype(np.uint8)
    return frame


def _chunk(fcc, data):
    out = bytearray(fcc + struct.pack('<I', len(data)))
    out += data
    if len(data) & 1:
        out += b'\x00'
    return out


def _list(ftype, content):
    return bytearray(b'LIST' + struct.pack('<I', len(content) + 4) + ftype) + content


def _write_avi(path, frame_dibs, width, height, fps):
    if not frame_dibs:
        raise StegoError('No frames were produced for the output video.')
    frame_size = len(frame_dibs[0])
    frame_count = len(frame_dibs)
    fps_int = max(1, int(round(fps or 24)))
    usec_per_frame = int(round(1000000.0 / fps_int))

    avih = _chunk(b'avih', struct.pack('<IIIIIIIIII', usec_per_frame,
                                       0, 0, 0x10,
                                       frame_count, 0, 1, frame_size, width, height)
                  + struct.pack('<IIII', 0, 0, 0, 0))

    strh = _chunk(b'strh', b'vids' + AVI_FCC
                  + struct.pack('<HH', 0, 0)
                  + struct.pack('<II', 0, 1)
                  + struct.pack('<II', fps_int, 0)
                  + struct.pack('<II', frame_count, frame_size)
                  + struct.pack('<I', 0xFFFFFFFF)
                  + struct.pack('<I', 0)
                  + struct.pack('<IIII', 0, 0, 0, 0))

    strf = _chunk(b'strf', struct.pack('<IiiHHIIIIII', 40, width, height,
                                       1, 24, 0, frame_size, 2835, 2835, 0, 0))

    hdrl = _list(b'hdrl', avih + _list(b'strl', strh + strf))

    movi_content = bytearray()
    index_entries = bytearray()
    offset = 4
    for dib in frame_dibs:
        index_entries += b'00dc' + struct.pack('<I', 0x10) + struct.pack('<I', offset) + struct.pack('<I', frame_size)
        movi_content += b'00dc' + struct.pack('<I', frame_size) + bytes(dib)
        offset += 8 + frame_size

    movi = _list(b'movi', movi_content)
    idx1 = _chunk(b'idx1', index_entries)

    body = hdrl + movi + idx1
    with open(path, 'wb') as handle:
        handle.write(b'RIFF' + struct.pack('<I', len(body) + 4) + b'AVI ' + body)


def _parse_avi_frames(data):
    if data[:4] != b'RIFF' or data[8:12] != b'AVI ':
        return []
    pos = 12
    end = len(data)
    while pos + 8 <= end:
        fcc = data[pos:pos + 4]
        size = struct.unpack('<I', data[pos + 4:pos + 8])[0]
        if fcc == b'LIST':
            if data[pos + 8:pos + 12] == b'movi':
                frames = []
                pointer = pos + 12
                limit = pos + 8 + size
                while pointer + 8 <= limit:
                    chunk_fcc = data[pointer:pointer + 4]
                    chunk_size = struct.unpack('<I', data[pointer + 4:pointer + 8])[0]
                    if chunk_fcc == b'00dc':
                        frames.append(data[pointer + 8:pointer + 8 + chunk_size])
                    pointer += 8 + chunk_size + (chunk_size & 1)
                return frames
            pos += 8 + size + (size & 1)
        else:
            pos += 8 + size + (size & 1)
    return []


def video_capacity_bytes(path):
    with open(path, 'rb') as handle:
        data = handle.read()
    frames = _parse_avi_frames(data)
    return sum(len(frame) for frame in frames) // 8


def _file_skip(total):
    return min(4096, max(16, total // 8))


def file_capacity_bytes(path):
    total = os.path.getsize(path)
    return (total - _file_skip(total)) // 8


def embed_file(cover_path, kind, name, data, password, out_path):
    with open(cover_path, 'rb') as handle:
        blob = bytearray(handle.read())
    skip = _file_skip(len(blob))
    flat = np.frombuffer(blob, dtype=np.uint8)
    payload = build_payload(kind, name, data, password)
    _embed_bits_into(flat[skip:], payload)
    with open(out_path, 'wb') as handle:
        handle.write(bytes(blob))


def extract_file(path, password):
    with open(path, 'rb') as handle:
        data = handle.read()
    skip = _file_skip(len(data))
    flat = np.frombuffer(bytearray(data), dtype=np.uint8)
    raw = _read_payload(flat[skip:])
    return unpack_payload(raw, password)


def embed_video(cover_path, kind, name, data, password, out_path,
                generate=False, max_dimension=960, max_frames=900):
    payload = build_payload(kind, name, data, password)
    bits_needed = len(payload) * 8
    frame_dibs = []
    width = height = 0
    fps = 24

    if cover_path:
        cap = cv2.VideoCapture(cover_path)
        if not cap.isOpened():
            raise StegoError('The cover video could not be decoded. Upload a readable video file.')
        source_fps = cap.get(cv2.CAP_PROP_FPS)
        if source_fps and source_fps > 1:
            fps = source_fps
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            frame = _fit_dimension(frame, max_dimension)
            if not frame_dibs:
                height, width = frame.shape[0], frame.shape[1]
            frame_dibs.append(_frame_to_dib(frame))
            if len(frame_dibs) >= max_frames:
                break
        cap.release()
        if not frame_dibs:
            raise StegoError('The cover video contains no readable frames.')
    else:
        if not generate:
            raise StegoError('Choose "Automatic video" or upload a cover video.')
        width, height = 640, 360
        row_bytes = (width * 3 + 3) & ~3
        frames_needed = max(1, -(-bits_needed // (row_bytes * height)))
        frame_dibs = [_frame_to_dib(_synthetic_frame(width, height, i, frames_needed))
                      for i in range(frames_needed)]

    capacity_bits = sum(len(dib) for dib in frame_dibs) * 8
    if bits_needed > capacity_bits:
        raise CapacityError(
            'The hidden payload is too large: it needs {} bits but the video '
            'only offers {} bits of capacity. Use a longer video or a smaller payload.'.format(
                bits_needed, capacity_bits))

    buffer = bytearray().join(bytes(dib) for dib in frame_dibs)
    flat = np.frombuffer(buffer, dtype=np.uint8)
    _embed_bits_into(flat, payload)
    frame_size = len(frame_dibs[0])
    for i, dib in enumerate(frame_dibs):
        frame_dibs[i] = bytes(flat[i * frame_size:(i + 1) * frame_size])

    _write_avi(out_path, frame_dibs, width, height, fps)


def extract_video(path, password):
    with open(path, 'rb') as handle:
        data = handle.read()
    frames = _parse_avi_frames(data)
    if not frames:
        raise NoPayloadFound('This file is not a StegoVault video (no video frames found).')
    flat = np.frombuffer(b''.join(frames), dtype=np.uint8)
    raw = _read_payload(flat)
    return unpack_payload(raw, password)