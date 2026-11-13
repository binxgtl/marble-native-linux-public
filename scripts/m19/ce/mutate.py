#!/usr/bin/env python3
"""Mutants of the R7 CE core: every one must fail test.py. Defence-in-depth checks that a later check always
catches as well (link refusals before O_NOFOLLOW opens, bounds a corrupted length fails anyway) are not listed."""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
UNLOCK = HERE.parent / 'unlock'
MUTANTS = (
    ('ce.c', '(S.spblob[0] != 2 && S.spblob[0] != 3) || S.spblob[1] != 0)', '0)'),
    ('ce.c', 'M19_CE_FAKE_UID_BASE + env->user', 'env->user'),
    ('ce.c', '"user-gk-authentication"', '"user-gk-authenticatio"'),
    ('ce.c', '"secdiscardable-transform"', '"secdiscardable-transfor"'),
    ('ce.c', '"application-id"', '"application-i"'),
    ('ce.c', 'LABEL_FBE[] = "fbe-key"', 'LABEL_FBE[] = "fbe-ke"'),
    ('ce.c', '"android-synthetic-password-personalization-context"', '"android-synthetic-password-personalization"'),
    ('ce.c', '"Android key wrapping key generation SHA512"', '"Android key wrapping key generation SHA51"'),
    ('ce.c', '"synthetic_password_"', '"synthetic_password"'),
    ('ce.c', "while (digits[0] == '0' && digits[1])", 'while (0)'),
    ('ce.c', 'memcpy(S.protector, S.token, sizeof(S.token));', ''),
    ('ce.c', 'put32(message + used, (uint32_t)(context_size * 8));', 'put32(message + used, (uint32_t)context_size);'),
    ('ce.c', 'put32(message + used + 4, 256);', 'put32(message + used + 4, 128);'),
    ('ce.c', 'put32(message, 1);', 'put32(message, 0);'),
    ('ce.c', 'if (S.spblob[0] == 3) {', 'if (S.spblob[0] == 2) {'),
    ('ce.c', 'secret_size = 32;', 'secret_size = 64;'),
    ('ce.c', "return !error && seen == 2 && !other ? M19_CE_OK : M19_CE_CE_LAYOUT;", 'return M19_CE_OK;'),
    ('ce.c', "version_size != 1 ||\n        version[0] != '1' ||", ''),
    ('ce.c', '||\n        encrypted_size <= M19_CE_GCM_NONCE + M19_CE_GCM_TAG)', ')'),
    ('ce.c', 'if (env->gatekeeper->connect(env->gatekeeper_context, &report->detail))', 'if (0)'),
    ('ce.c', 'env->storage->connect(env->storage_context, &report->detail) != M19_KS_OK ||\n        ', ''),
    ('ce.c', 'result == M19_GK_REJECTED ? M19_CE_GK_REJECTED : ', ''),
    ('ce.c', 'result == M19_GK_RETRY ? M19_CE_GK_RETRY : ', ''),
    ('ce.c', 'report->gk_timeout_ms = timeout;', ''),
    ('ce.c', 'if (size != M19_CE_AUTH_TOKEN_BYTES || data[0] != 0)', 'if (size != M19_CE_AUTH_TOKEN_BYTES)'),
    ('ce.c', 'token->authenticator_type = (int32_t)get32(data + 25);', 'token->authenticator_type = (int32_t)get32(data + 24);'),
    ('ce.c', 'token->timestamp_ms = (int64_t)get64(data + 29);', 'token->timestamp_ms = (int64_t)get64le(data + 29);'),
    ('ce.c', 'token->challenge = (int64_t)get64le(data + 1);', 'token->challenge = (int64_t)get64(data + 1);'),
    ('ce.c', 'memcpy(token->mac, data + 37, sizeof(token->mac));', 'memcpy(token->mac, data + 36, sizeof(token->mac));'),
    ('ce.c', 'if (size < M19_CE_PIN_MIN || size > M19_CE_PIN_MAX)', 'if (size > M19_CE_PIN_MAX)'),
    ('ce.c', 'if (size < M19_CE_PIN_MIN || size > M19_CE_PIN_MAX)', 'if (size < M19_CE_PIN_MIN)'),
    ('ce.c', "if (pin[i] < '0' || pin[i] > '9')", 'if (0)'),
    ('ce.c', '|| found++) {', '|| (found = 1, 0)) {'),
    ('ce.c', "(name[i] >= 'a' && name[i] <= 'f')", "(name[i] >= 'a' && name[i] <= 'f') || (name[i] >= 'A' && name[i] <= 'F')"),
    ('ce.c', ' && present(spblob_dir, id, ".secdis")', ''),
    ('ce.c', 'if (!pwd->log_n || pwd->log_n > 15 || pwd->log_r > 4 || pwd->log_p > 2)', 'if (pwd->log_n > 15 || pwd->log_r > 4 || pwd->log_p > 2)'),
    ('ce.c', 'if (!pwd->log_n || pwd->log_n > 15 || pwd->log_r > 4 || pwd->log_p > 2)', 'if (!pwd->log_n || pwd->log_r > 4 || pwd->log_p > 2)'),
    ('ce.c', 'pwd->salt = data + 11;', 'pwd->salt = data + 12;'),
    ('ce.c', 'pwd->handle = data + 15 + salt;', 'pwd->handle = data + 11 + salt;'),
    ('ce.c', 'secdis_size != M19_CE_SECDIS_BYTES)', '0)'),
    ('ce.c', 'm19_wipe(&S, sizeof(S));\n    m19_wipe(alias, sizeof(alias));', 'm19_wipe(alias, sizeof(alias));'),
    ('ce.c', 'm19_wipe(&S, sizeof(S));\n    return status;\n}\n\nenum m19_ce_status m19_ce_copy_db', 'return status;\n}\n\nenum m19_ce_status m19_ce_copy_db'),
    ('ce.c', 'if ((result != M19_KS_OK && result != M19_KS_UPGRADE) || !plain_size', 'if (result != M19_KS_OK || !plain_size'),
    ('ce.c', '*upgraded = result == M19_KS_UPGRADE;', '*upgraded = 0;'),
    ('ce.c', '*upgraded = -1; /* UNKNOWN until a successful decrypt response, as in R1. */', ''),
    ('ce.c', 'if (fs->add_key(fs_context, S.ephemeral, ephemeral_size, detail))', 'if (0)'),
    ('ce.c', 'O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW', 'O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW'),
    ('ce.c', 'O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW', 'O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC'),
    ('ce.c', 'st.st_size <= 0 ||', ''),
    ('crypto.c', 'lib.ctrl(ctx, CTRL_GCM_SET_TAG, M19_CE_GCM_TAG, tag) == 1 && lib.final(ctx, output + produced, &tail) == 1',
     '(lib.final(ctx, output + produced, &tail), 1)'),
    ('crypto.c', 'tag[i] = sealed[body + i];', 'tag[i] = sealed[i];'),
    ('crypto.c', 'lib.init(ctx, NULL, NULL, key, nonce) == 1', 'lib.init(ctx, NULL, NULL, nonce, key) == 1'),
    ('crypto.c', 'lib.scrypt((const char *)password, password_size, salt, salt_size, n, r, p,',
     'lib.scrypt((const char *)password, password_size, salt, salt_size, n, p, r,'),
    ('fscrypt.c', 'memcpy(arg + 0x4c, &flags, 4);', ''),
    ('fscrypt.c', 'memcpy(arg + 0x28, &size, 4);', 'memcpy(arg + 0x2c, &size, 4);'),
    ('fscrypt.c', 'uint32_t type = KEY_SPEC_TYPE_IDENTIFIER,', 'uint32_t type = 1,'),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--libcrypto', default='libcrypto.so.3')
    arguments = parser.parse_args()
    survivors = []
    for number, (name, old, new) in enumerate(MUTANTS):
        source = (HERE / name).read_text(encoding='utf-8')
        if old not in source:
            sys.exit(f'mutant {number} does not apply to {name}: {old!r}')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'ce').mkdir()
            shutil.copytree(UNLOCK, root / 'unlock', ignore=shutil.ignore_patterns('__pycache__'))
            for path in HERE.iterdir():
                if path.suffix in ('.c', '.h', '.py'):
                    shutil.copy(path, root / 'ce')
            (root / 'ce' / name).write_text(source.replace(old, new, 1), encoding='utf-8')
            build = subprocess.run(['gcc', '-std=c11', '-O1', '-w', '-DM19_CE_TEST', 'ce/ce.c', 'ce/crypto.c', 'ce/fscrypt.c', 'ce/test-ce.c',
                                    'unlock/core.c', 'unlock/hash.c', '-ldl', '-o', 'test-ce'], cwd=root, capture_output=True, timeout=120)
            if build.returncode:
                sys.exit(f'mutant {number} does not compile: {build.stderr.decode()[-400:]}')
            result = subprocess.run([sys.executable, 'ce/test.py', '--binary', str(root / 'test-ce'), '--libcrypto', arguments.libcrypto],
                                    cwd=root, capture_output=True, timeout=600)
        if not result.returncode:
            survivors.append(number)
            print(f'SURVIVED {number}: {name}: {old[:70]!r}')
    print(f'R7 CE mutants killed: {len(MUTANTS) - len(survivors)} of {len(MUTANTS)}')
    sys.exit(1 if survivors else 0)


if __name__ == '__main__':
    main()
