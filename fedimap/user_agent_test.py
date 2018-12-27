import unittest

from fedimap.user_agent import InstanceUserAgent, classify_user_agent


class TestAccessLog(unittest.TestCase):
    def test_mastodon(self):
        expected = InstanceUserAgent(
            pattern_name='mastodon',
            server='Mastodon',
            version='2.6.5',
            url='https://example.org/',
            http_client='http.rb',
            http_client_version='3.3.0'
        )
        iua = classify_user_agent('http.rb/3.3.0 (Mastodon/2.6.5; +https://example.org/)')
        self.assertEqual(iua, expected)

    def test_mastodon_probably(self):
        iua = classify_user_agent('http.rb/3.3.0')
        self.assertEqual(iua.server, 'Mastodon')
        self.assertEqual(iua.pattern_name, 'mastodon_probably')

    def test_pleroma_mediaproxy(self):
        expected = InstanceUserAgent(
            pattern_name='pleroma_mediaproxy',
            server='Pleroma',
            version='MediaProxy',
            url='https://example.org',
            email='admin@example.org',
        )
        iua = classify_user_agent('Pleroma/MediaProxy; https://example.org <admin@example.org>')
        self.assertEqual(iua, expected)

    def test_pleroma_probably(self):
        iua = classify_user_agent('hackney/1.13.0')
        self.assertEqual(iua.server, 'Pleroma')
        self.assertEqual(iua.pattern_name, 'pleroma_probably')

    def test_frendica(self):
        iua = classify_user_agent("Friendica 'The Tazmans Flax-lily' 2018.12-rc-1291; "
                                  "https://example.org")
        self.assertEqual(iua.server, 'Friendica')
        self.assertEqual(iua.url, 'https://example.org')

    def test_gnu_social_with_url(self):
        iua = classify_user_agent('GNU social/1.2.1-beta1 (https://example.org)')
        self.assertEqual(iua.server, 'GNU social')
        self.assertEqual(iua.url, 'https://example.org')

    def test_gnu_social_no_url(self):
        iua = classify_user_agent('GNU social/1.2.1-beta1 (Not decided yet)')
        self.assertEqual(iua.server, 'GNU social')
        self.assertIsNone(iua.url)

    def test_misskey(self):
        iua = classify_user_agent('Misskey/10.66.2 (https://example.org)')
        self.assertEqual(iua.server, 'Misskey')
        self.assertEqual(iua.url, 'https://example.org')
