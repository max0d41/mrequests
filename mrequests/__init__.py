import re
import time
import logging
import requests

from bs4 import BeautifulSoup
from functools import partial
from urlparse import urlparse, urljoin

try:
    import cchardet as chardet
except ImportError:
    import chardet

try:
    import botfv8
except ImportError:
    botfv8 = None

logger = logging.getLogger(__name__)


def _decode(text):
    try:
        text = text.decode('UTF-8')
    except (UnicodeDecodeError, UnicodeEncodeError):
        try:
            encoding = chardet.detect(text)['encoding']
            text = text.decode(encoding)
        except (UnicodeDecodeError, UnicodeEncodeError):
            try:
                text = text.encode('UTF-8')
                text = unicode(text, 'ascii', 'ignore')
            except (UnicodeDecodeError, UnicodeEncodeError):
                text = unicode(text, 'ascii', 'ignore')
    return text


class Response(requests.Response):
    def soup(self, parser='html.parser'):
        return BeautifulSoup(self.content, parser)

    def _prepare_kwargs(self, kwargs):
        if kwargs.get('headers', None) is None:
            kwargs['headers'] = dict()
        if 'referer' not in kwargs and 'Referer' not in kwargs['headers']:
            kwargs['headers']['Referer'] = self.url
        return kwargs

    def urljoin(self, url):
        return urljoin(self.url, url)

    def request(self, method, url, **kwargs):
        url = self.urljoin(url)
        return self._session.request(method, url, **self._prepare_kwargs(kwargs))

    def get(self, url, **kwargs):
        url = self.urljoin(url)
        return self._session.get(url, **self._prepare_kwargs(kwargs))

    def options(self, url, **kwargs):
        url = self.urljoin(url)
        return self._session.options(url, **self._prepare_kwargs(kwargs))

    def head(self, url, **kwargs):
        url = self.urljoin(url)
        return self._session.head(url, **self._prepare_kwargs(kwargs))

    def post(self, url, **kwargs):
        url = self.urljoin(url)
        return self._session.post(url, **self._prepare_kwargs(kwargs))

    def put(self, url, **kwargs):
        url = self.urljoin(url)
        return self._session.put(url, **self._prepare_kwargs(kwargs))

    def patch(self, url, **kwargs):
        url = self.urljoin(url)
        return self._session.patch(url, **self._prepare_kwargs(kwargs))

    def delete(self, url, **kwargs):
        url = self.urljoin(url)
        return self._session.delete(url, **self._prepare_kwargs(kwargs))

    def get_cookies(self):
        return self._session.get_cookies()

    def set_cookies(self, cookies):
        return self._session.set_cookies(cookies)

    def serialize_form(self, form):
        data = dict()
        for attr in form.find_all(lambda e: e.get('name', None) is not None or e.get('value', None) is not None):
            data[attr.get('name', '')] = attr.get('value', '')
        url = form.get('action')
        return url, data

    def load_full_html_page(self, get_func=None):
        """get_func can be for eg. a function that uses a thread pool"""
        if get_func is None:
            get_func = partial(self.get, raise_for_status=False)
        soup = self.soup()
        for e in soup.select('img[src]') + soup.select('script[src]') + soup.select('style[src]'):
            url = e.get('src')
            get_func(url)

    def to_string(self, include_request=True, include_body=True):
        content = list()

        if include_request and self.request is not None:
            content.append('%s %s' % (self.request.method, _decode(self.request.url)))
            for key, value in self.request.headers.iteritems():
                content.append('%s: %s' % (_decode(key), _decode(value)))
            content.append('')
            if self.request.body:
                content.append(self.request.body[:8192])
                content.append('')

        content.append('%s %s' % (self.status_code, _decode(self.url)))
        for key, value in self.headers.iteritems():
            content.append('%s: %s' % (_decode(key), _decode(value)))
        content.append('')

        if include_body and self.content is not None:
            allowed = False
            content_type = self.headers.get('Content-Type', '').split('; ', 1)[0]
            if content_type.startswith('text/'):
                allowed = True
            elif content_type == 'application/javascript':
                allowed = True
            elif int(self.headers.get('Content-Length', 0)) < 10*1024:
                allowed = True
            if allowed:
                content.append(_decode(self.content))
            else:
                content.append('Content-Type not allowed for debug log')

        return '\n'.join(content)


def _runtime_error(message, method, url):
    return RuntimeError('%s while requesting %s %s' % (message, method, url))


class Session(requests.Session):
    default_timeout = 30

    def request(self, method, url, **kwargs):
        stream = kwargs.pop('stream', False)
        headers = kwargs.pop('headers', dict())
        raise_for_status = kwargs.pop('raise_for_status', True)
        bypass_cloudflare = kwargs.pop('bypass_cloudflare', True)

        # Rules to assert stream=True request
        assert_stream_methods = kwargs.pop('streaming_rules_methods', ('GET', 'POST'))
        max_content_length = kwargs.pop('max_content_length', 25*1024**2)

        if 'range' in kwargs:
            range_ = kwargs.pop('range')
            if range_ is not None:
                start, end = range_
                if start is not None or end is not None:
                    headers['Range'] = 'bytes=%s-%s' % (start or 0, '' if end is None else (end - 1))

        if 'referer' in kwargs:
            headers['Referer'] = kwargs.pop('referer')

        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.default_timeout

        resp = super(Session, self).request(method, url, stream=True, headers=headers, **kwargs)
        resp._session = self
        resp.__class__ = Response

        if bypass_cloudflare and 'URL=/cdn-cgi/' in resp.headers.get('Refresh', '') and resp.headers.get('Server', '') == 'cloudflare-nginx':
            cf_resp = self.solve_cf_challenge(resp, stream, headers, raise_for_status, kwargs)
            if cf_resp is not None:
                return cf_resp

        if raise_for_status:
            try:
                resp.raise_for_status()
            except Exception:
                if stream:
                    resp.close()
                raise

        if not stream:
            # This is to prevent coding mistakes that loads the full response body to memory
            if method.upper() in assert_stream_methods:
                if 'Content-Disposition' in resp.headers:
                    raise _runtime_error('Content-Disposition header found without streaming', method, url)
                if max_content_length is not None:
                    content_length = int(resp.headers.get('Content-Length', 0))
                    if content_length > max_content_length:
                        message = 'Content-Length of %s bytes is bigger than max allowed of %s bytes' % (content_length, max_content_length)
                        raise _runtime_error(message, method, url)
            resp.content # Load response body

        return resp

    def solve_cf_challenge(self, resp, stream, headers, raise_for_status, kwargs):
        if botfv8 is None:
            logger.warning('Cloudflare bypass failed cause no javascript engine is installed')
            return None

        logger.info('Trying to bypass cloudflare for %s', resp.url)
        time.sleep(5) # Cloudflare requires a delay before solving the challenge

        parsed_url = urlparse(resp.url)
        kwargs.pop('params', None) # Don't pass on params

        try:
            challenge = re.search(r'name="jschl_vc" value="(\w+)"', resp.text).group(1)
            challenge_pass = re.search(r'name="pass" value="(.+?)"', resp.text).group(1)

            # Extract the arithmetic operation
            js = re.search(r"setTimeout\(function\(\){\s+(var t,r,a,f.+?\r?\n[\s\S]+?a\.value =.+?)\r?\n", resp.text).group(1)
            js = re.sub(r'a\.value =(.+?) \+ .+?;', r'\1', js)
            js = re.sub(r'\s{3,}[a-z](?: = |\.).+', '', js)
        except Exception:
            # Something is wrong with the page. This may indicate Cloudflare has changed their
            # anti-bot technique. If you see this and are running the latest version,
            # please open a GitHub issue so I can update the code accordingly.
            logger.exception('Unable to bypass cloudflare for %s', resp.url)
            return None

        # Safely evaluate the Javascript expression
        js = re.sub(r"[\n\\']", "", js)
        answer = str(int(botfv8.execute(js)) + len(parsed_url.netloc))

        params = {'jschl_vc': challenge, 'jschl_answer': answer, 'pass': challenge_pass}
        submit_url = '%s://%s/cdn-cgi/l/chk_jschl' % (parsed_url.scheme, parsed_url.netloc)

        resp = resp.get(submit_url, params=params, bypass_cloudflare=False, stream=stream, headers=headers, raise_for_status=raise_for_status, **kwargs)
        resp.cookies.set('__cfduid', resp.cookies.get('__cfduid'))
        return resp

    def set_cookies(self, cookies):
        for cookie in cookies:
            self.session.cookies.set(**cookie)

    def get_cookies(self):
        return [{key: getattr(cookie, key) for key in ('version', 'name', 'value', 'port', 'domain', 'path', 'secure', 'expires', 'discard', 'comment', 'comment_url', 'rfc2109')} for cookie in self.cookies]


def session():
    return Session()
