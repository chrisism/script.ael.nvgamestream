import unittest, os
import unittest.mock

from tests.fakes import FakeFile

from akl.utils import io
import resources.lib.crypto as target

class Test_cryptography_test(unittest.TestCase):
    
    ROOT_DIR = ''
    TEST_DIR = ''
    TEST_ASSETS_DIR = ''
    TEST_OUTPUT_DIR = ''

    @classmethod
    def setUpClass(cls):
        cls.TEST_DIR = os.path.dirname(os.path.abspath(__file__))
        cls.ROOT_DIR = os.path.abspath(os.path.join(cls.TEST_DIR, os.pardir))
        cls.TEST_ASSETS_DIR = os.path.abspath(os.path.join(cls.TEST_DIR,'assets/'))
        cls.TEST_OUTPUT_DIR = os.path.abspath(os.path.join(cls.TEST_DIR,'output/'))
        if not os.path.exists(cls.TEST_OUTPUT_DIR): os.makedirs(cls.TEST_OUTPUT_DIR)
        
    def test_get_public_key_from_certificate(self):
        
        # arrange
        test_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = FakeFile(test_dir + '/nv_client_test.crt')
        key_path = FakeFile(test_dir + '/nv_client_test.key')

        # act
        target.create_self_signed_cert("NVIDIA GameStream Client", cert_path, key_path)
        certificate_data = cert_path.getFakeContent().encode('ascii')
        actual = target.get_certificate_public_key(certificate_data)

        # assert
        self.assertIsNotNone(actual)

    def test_get_signature_key_from_certificate(self):
        
        # arrange
        test_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = FakeFile(test_dir + '/nv_client_test.crt')
        key_path = FakeFile(test_dir + '/nv_client_test.key')

        # act
        target.create_self_signed_cert("NVIDIA GameStream Client", cert_path, key_path)
        certificate_data = cert_path.getFakeContent().encode('ascii')
        actual = target.get_certificate_signature(certificate_data)

        # assert
        self.assertIsNotNone(actual)

    def test_decrypt_cert(self):

        # arrange
        test_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = FakeFile(test_dir + '/nv_client_test.crt')
        key_path = FakeFile(test_dir + '/nv_client_test.key')

        # act
        target.create_self_signed_cert("NVIDIA GameStream Client", cert_path, key_path)
        certificate_data = cert_path.getFakeContent().encode('ascii')
        certificate_key = key_path.getFakeContent().encode('ascii')

        data = target.get_certificate_public_key(certificate_data)
        target.AESCipher

        # arrange


    def test_create_certificates(self):
        # arrange
        output_dir = io.FileName(self.TEST_OUTPUT_DIR, isdir=True)
        cert_name = "NVIDIA GameStream Client"
        cert_file_path = output_dir.pjoin('nvidia_01.crt')
        key_file_path = output_dir.pjoin('nvidia_02.key')
        
        # act

        target.create_self_signed_cert(cert_name, cert_file_path, key_file_path)
        # assert
        assert cert_file_path.exists()
        assert key_file_path.exists()

    def test_hashing_a_value(self):

        # arrange
        target_hash = target.HashAlgorithm(256)

        inputHex = "3e72d22e02dbb0596637d9a02b93156b5e094f0998a28a85acede2c4669ac632bcc47b32f78a1c04ec54ab4632fcb82e043b7f6563ef4182efc8dd973e36079d423d7bc14474908b12f09652bb5641a8a0842161b15fb1f8dd79f2ab3a1f2d99ed8f73a3abb0862aa97bd7bd149deca32f87ada1b46df9f840deb8a76bf76d6aa549f93312043617efdc843f3e16416bf7756f79a6a50c9f5e42424f1014058da6b4f045c426a682cd81921a2ac8d02a0b93031f3bfa05e50b79987f99b68bb3f4d23cc591df7c427b80e1f9ed4a45fcb4b1bc4c866c232d98a6cd5744676ad6ba239026dafd85ff6ce59c7065fa0ebd2e214068b6a7c8d4d2f909067a6ca929f810d5ffdfeade2c3900e62fd47c73c650ca25d03b4ac53368875b9a1bfb50cc"
        expected = "b38b92ee89db21842c6173cffc27d4a58c7a58ce965b7155a5caba711ccba86a"
        input = bytearray.fromhex(inputHex)

        # act
        actual = target_hash.hashToHex(input)
        print(actual)
        actual_str = actual.decode('utf-8`')

        # assert
        self.assertEqual(expected, actual_str)
        
    @unittest.skip('PEM conversion testing with an original key')
    def test_converting_pkcs8_to_pem(self):
        import ssl
         # arrange
        test_file = os.path.join(self.TEST_ASSETS_DIR, 'certs/nvidia.key')
          
        file_contents = ''
        with open(test_file, 'r') as f:
            file_contents = f.read()

        #print file_contents
        print('----------------------------')
        #print(binascii.hexlify(file_contents))
        print('----------------------------')
        #print(binascii.hexlify(ssl.DER_cert_to_PEM_cert(file_contents)))
        print('----------------------------')
        #hex = b64encode(binascii.hexlify(file_contents))
        #print(hex)
        print( '----------------------------')
        #encoded = b64encode(file_contents)
        #print(encoded)

if __name__ == '__main__':
    unittest.main()
