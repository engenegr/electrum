import json
import asyncio
import aiohttp
import logging
import concurrent


class OmniCoreRPC():
    def __init__(self, url, username, password):
        #self.net = Network.get_instance()
        #if self.net.config.get('testnet'):
        #    self.port = 18332
        #else:
        #    self.port = 8332
        #self.url = ''.join([url, ':', self.port])
        self.url = url
        self.user = username
        self.pwd = password
        self.RequestTimeout = 30

    def make_aiohttp_session(self, headers=None, timeout=None):
        # TODO: consider SSL sessions
        if headers is None:
            headers = {'content-type': "application/json"}
        if timeout is None:
            timeout = aiohttp.ClientTimeout(total=self.RequestTimeout)
        elif isinstance(timeout, (int, float)):
            timeout = aiohttp.ClientTimeout(total=self.RequestTimeout)
        auth = aiohttp.BasicAuth(login=self.user, password=self.pwd)
        return aiohttp.ClientSession(headers=headers, timeout=timeout, auth=auth)


    async def get_response(self, method=None, params=None):
        if not (self.url and self.user and self.pwd):
            return {'error': 'empty credentials'}
        if method == None:
            method = 'omni_getinfo'
        if params == None:
            params = []
        async with self.make_aiohttp_session() as session:
            payload = json.dumps({"method": method, "params": params})
            try:
                async with session.post(self.url, data = payload) as response:
                    response.raise_for_status()
                    # set content_type to None to disable checking MIME type
                    #await session.close()
                    return await response.json(content_type='application/json')
            except concurrent.futures._base.TimeoutError:
                await session.close()
                return {'error': 'timeout'}
            except aiohttp.client_exceptions.ClientResponseError as e:
                if e.message == 'Unauthorized':
                    await session.close()
                    return {'error': 'unauthorized'}


    def make_async_call(self, method=None, params=None, loop=None):
        if not loop:
            loop = asyncio.get_event_loop()
        fut = asyncio.run_coroutine_threadsafe(self.get_response(method=method, params=params), loop)
        return fut.result()

    def is_connected(self):
        result = self.check()
        if 'error' not in result:
            return True
        else:
            return False

    def check(self):
        loop = asyncio.get_event_loop()
        fut = asyncio.run_coroutine_threadsafe(self.get_response(), loop)
        response = fut.result()
        if 'result' in response:
            logging.debug(response['result'])
            print(response['result'])
            return response['result']
        else:
            return response

    def reset(self, url, username, password):
        self.url = url
        self.user = username
        self.pwd = password
        return self.check()
