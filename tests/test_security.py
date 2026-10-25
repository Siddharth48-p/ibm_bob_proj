import unittest

from api.security import password_hash, password_verify, token_hash, verify_signature


class SecurityUnitTests(unittest.TestCase):
    def test_password_hash_is_salted_and_verified(self):
        first = password_hash("Correct horse battery 123!")
        second = password_hash("Correct horse battery 123!")
        self.assertNotEqual(first, second)
        self.assertTrue(password_verify("Correct horse battery 123!", first))
        self.assertFalse(password_verify("wrong password", first))

    def test_session_token_hash_is_keyed(self):
        self.assertNotEqual(token_hash("session", "key-one"), token_hash("session", "key-two"))

    def test_webhook_signature_requires_exact_body_and_secret(self):
        import hashlib, hmac
        body = b'{"event":"test"}'
        secret = "test-only-webhook-secret"
        signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        self.assertTrue(verify_signature(body, signature, secret))
        self.assertFalse(verify_signature(body+b" ", signature, secret))
        self.assertFalse(verify_signature(body, signature, "wrong"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
