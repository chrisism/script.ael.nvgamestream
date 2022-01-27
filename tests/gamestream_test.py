import unittest, os
import unittest.mock
from unittest.mock import MagicMock, patch

import logging
import os, binascii

#from fakes import FakeProgressDialog, random_string

logging.basicConfig(format = '%(asctime)s %(module)s %(levelname)s: %(message)s',
                datefmt = '%m/%d/%Y %I:%M:%S %p', level = logging.DEBUG)
logger = logging.getLogger(__name__)

from resources.lib.gamestream import GameStreamServer

from akl.utils import io

class Test_gamestream(unittest.TestCase):

    ROOT_DIR = ''
    TEST_DIR = ''
    TEST_ASSETS_DIR = ''

    @classmethod
    def setUpClass(cls):
        cls.TEST_DIR = os.path.dirname(os.path.abspath(__file__))
        cls.ROOT_DIR = os.path.abspath(os.path.join(cls.TEST_DIR, os.pardir))
        cls.TEST_ASSETS_DIR = os.path.abspath(os.path.join(cls.TEST_DIR,'assets/'))

    def read_file(self, path, encoding=None):
        with open(path, 'r', encoding=encoding) as f:
            return f.read()
        
    @patch('resources.lib.gamestream.net.get_URL_using_handler')
    def test_connecting_to_a_gamestream_server(self, http_mock: MagicMock):
        
        # arrange
        http_mock.return_value = self.read_file(self.TEST_ASSETS_DIR + "/gamestreamserver_response.xml", encoding='utf-16')
        server = GameStreamServer('192.168.0.555', io.FileName(self.TEST_ASSETS_DIR), debug_mode=True)
        
        # act
        actual = server.connect()

        # assert
        self.assertTrue(actual)


    @patch('resources.lib.gamestream.net.get_URL_using_handler')
    def test_get_the_version_of_the_gamestream_server(self, http_mock: MagicMock):
         
        # arrange
        http_mock.return_value = self.read_file(self.TEST_ASSETS_DIR + "/gamestreamserver_response.xml", encoding='utf-16')
        server = GameStreamServer('192.168.0.555', io.FileName(self.TEST_ASSETS_DIR), debug_mode=True)
        expected = '7.1.402.0'
        expectedMajor = 7

        # act
        server.connect()
        actual = server.get_server_version()

        # assert
        self.assertEqual(expected, actual.getFullString())
        self.assertEqual(expectedMajor, actual.getMajor()) 
      
    @patch('resources.lib.gamestream.net.get_URL_using_handler')
    def test_getting_apps_from_gamestream_server_gives_correct_amount(self, http_mock: MagicMock):

        # arrange        
        http_mock.return_value = self.read_file(self.TEST_ASSETS_DIR + "/gamestreamserver_apps.xml")
        server = GameStreamServer('192.168.0.555', io.FileName(self.TEST_ASSETS_DIR))

        expected = 18

        # act
        actual = server.getApps()

        for app in actual:
            print('----------')
            for key in app:
                print('{} = {}'.format(key, app[key]))

        # arranges
        self.assertEqual(expected, len(actual))
        
    @unittest.skip('only testable with actual server for now')
    @patch('resources.lib.gamestream.getCertificateBytes')
    @patch('resources.lib.gamestream.getCertificateKeyBytes')
    @patch('resources.lib.gamestream.crypto.randomBytes')
    def test_pair_with_gamestream_server(self, random_mock:MagicMock, certificateKeyBytesMock:MagicMock, certificateBytesMock:MagicMock):
        
        # arrange
        addon_dir = io.FileName(self.TEST_ASSETS_DIR)
        certificateBytesMock.return_value    = self.read_file(self.TEST_ASSETS_DIR + "/nvidia.crt")
        certificateKeyBytesMock.return_value = self.read_file(self.TEST_ASSETS_DIR + "/nvidia.key")
        random_mock.return_value = binascii.unhexlify("50ca25d03b4ac53368875b9a1bfb50cc")

        server = GameStreamServer('mediaserver', addon_dir, debug_mode = True)
        
        # act
        server.connect()
        pincode = server.generatePincode()
        paired = server.pairServer(pincode)

        # assert
        self.assertTrue(paired)
        
   # @patch('resources.gamestream.net_get_URL_using_handler')
    @unittest.skip('only testable with actual server for now')
    def test_getting_apps_from_gamestream_server(self):#, http_mock):

        # arrange        
       # http_mock.return_value = self.read_file(self.TEST_ASSETS_DIR + "\\gamestreamserver_apps.xml")
        server = GameStreamServer('192.168.0.5', io.FileName(self.TEST_ASSETS_DIR), debug_mode=True)

        expected = 18

        # act
        actual = server.getApps()

        for app in actual:
            print('----------')
            for key in app:
                print('{} = {}'.format(key, app[key]))

        # arranges
        self.assertEqual(expected, len(actual))
        

if __name__ == '__main__':
    unittest.main()
