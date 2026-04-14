import time
import json

import html5lib
from furl import furl
from urllib.parse import urlparse, parse_qs

from . import version


class DuoMfaDenied(BaseException):
    """ Duo MFA was denied """

    def __init__(self, response):
        super(DuoMfaDenied, self).__init__(f'Duo MFA denied: {response}')


class OktaDuoUniversal:
    """ Handles interaction with the Duo Universal Prompt """

    def __init__(self, ui, session, state_token, okta_factor, remember_device, duo_factor='Duo Push', duo_passcode=None):
        self.ui = ui
        self.state_token = state_token
        self.okta_factor = okta_factor
        self.remember_device = remember_device
        self.session = session
        if duo_factor not in ['Duo Push', 'Passcode', 'Phone Call']:
            raise Exception('Preferred Duo Universal factor must be one of: Duo Push, Passcode, Phone Call')
        self.duo_factor = duo_factor
        self.duo_passcode = duo_passcode

    def do_auth(self):
        """ Follow Duo Universal Prompt flow through to an active Okta user session """
        duo_prompt_url, okta_profile_login = self._initiate_okta_factor_verification()
        duo_origin, duo_plugin_form_response = self._handle_duo_plugin_form(duo_prompt_url)

        tx_context = self._build_transaction_context(duo_origin, duo_plugin_form_response)

        self.ui.info(f"Duo Universal: Using {self.duo_factor}...")

        if tx_context['mode'] == 'legacy_form':
            duo_factor, duo_sid, duo_txid, duo_xsrf = self._trigger_legacy_duo_factor(duo_origin, duo_plugin_form_response)
            self._wait_for_duo_universal_transaction(duo_origin, duo_txid, duo_sid)
            self._complete_oidc_exit(duo_origin, duo_txid, duo_sid, duo_factor, duo_xsrf)
        else:
            self._perform_js_bundle_flow(tx_context)

        # The claims_provider factor immediately yields an active user session, no subsequent request for SID required.
        if 'sid' not in self.session.cookies:
            raise Exception('Duo authentication succeeded but Okta session cookie (sid) was not established. This may indicate the authorization URL endpoint is not accessible in your Duo configuration.')

        return {
            'apiResponse': {
                'status': 'SUCCESS',
                'userSession': {
                    "username": okta_profile_login,
                    "session": self.session.cookies['sid'],
                    "device_token": self.session.cookies.get('DT', '')
                },
                'sessionToken': self.session.cookies['sid']
            },
        }

    def _trigger_legacy_duo_factor(self, duo_origin, duo_plugin_form_response):
        # Submit second Duo form (login-form), which triggers a Duo Push, phone call, or accepts the Passcode.
        login_form_action, duo_login_form_data = self._get_duo_universal_login_form_data(duo_plugin_form_response)
        login_form_action_url = furl(duo_origin) / login_form_action
        return self._submit_duo_login_form(duo_login_form_data, login_form_action_url)

    def _complete_oidc_exit(self, duo_origin, duo_txid, duo_sid, duo_factor, duo_xsrf):
        # Once Duo has been approved, load the OIDC exit URL to be redirected to Okta and gain a user session.
        oidc_exit_url = furl(duo_origin) / 'frame/v4/oidc/exit'
        exit_headers = self._get_form_headers()
        exit_response = self._post(
            oidc_exit_url.url,
            data={
                'txid': duo_txid,
                'sid': duo_sid,
                'factor': duo_factor,
                '_xsrf': duo_xsrf,
                'device_key': '',
                'dampen_choice': 'false',
            },
            headers=exit_headers,
        )
        exit_response.raise_for_status()

    def _build_transaction_context(self, duo_origin, prompt_response):
        # Prefer the legacy login-form flow when available.
        doc = html5lib.parse(prompt_response.content, namespaceHTMLElements=False)
        login_form = doc.find('.//form[@id="login-form"]')
        if login_form is not None:
            return {'mode': 'legacy_form'}

        root = doc.find('.//*[@id="pwl-prompt-root"]')
        if root is None:
            raise Exception('Unsupported Duo Universal response: no login-form and no pwl-prompt-root found')

        akey = root.get('data-akey')
        authkey = root.get('data-authkey')
        if not akey or not authkey:
            raise Exception('Unsupported Duo Universal response: missing data-akey/data-authkey for prompt API')

        req_trace_group = root.get('data-req-trace-group')
        if not req_trace_group:
            req_trace_group = parse_qs(urlparse(prompt_response.url).query).get('req_trace_group', [None])[0]
        path_prefix = f'/prompt/{akey}'
        return {
            'mode': 'js_bundle',
            'duo_origin': duo_origin,
            'akey': akey,
            'authkey': authkey,
            'req_trace_group': req_trace_group,
            'preauth_init_url': f'{duo_origin}{path_prefix}/pre_authn/initialization',
            'preauth_eval_url': f'{duo_origin}{path_prefix}/pre_authn/evaluation',
            'push_trigger_urls': [f'{duo_origin}{path_prefix}/auth/factors/push/auth'],
            'push_status_urls': [f'{duo_origin}{path_prefix}/auth/factors/push/status'],
            # React prompt tenants commonly use factor endpoints without the /auth suffix.
            'phone_call_trigger_urls': [
                f'{duo_origin}{path_prefix}/auth/factors/phone_call',
                f'{duo_origin}{path_prefix}/auth/factors/phone_call/auth',
            ],
            'phone_call_status_urls': [
                f'{duo_origin}{path_prefix}/auth/factors/phone_call/status',
                f'{duo_origin}{path_prefix}/auth/factors/phone_call/poll',
            ],
            'passcode_trigger_urls': [
                f'{duo_origin}{path_prefix}/auth/factors/mobile_otp',
            ],
            'auth_payload_url': f'{duo_origin}{path_prefix}/auth/payload',
            'authz_url': f'{duo_origin}{path_prefix}/auth/authorization_url',
            'finalize_auth_url': f'{duo_origin}{path_prefix}/auth/finalize_auth',
        }

    def _perform_js_bundle_flow(self, tx_context):
        headers = self._get_prompt_api_headers(tx_context)
        post_headers = self._get_prompt_api_headers(tx_context, include_origin=True)
        if self.duo_factor == 'Duo Push':
            pkey = self._discover_authenticator_key(tx_context, headers, 'push')
            txid, immediate_result = self._initiate_js_bundle_factor(
                tx_context,
                post_headers,
                tx_context['push_trigger_urls'],
                {'authkey': tx_context['authkey'], 'pkey': pkey, 'otp_code': self.duo_passcode or ''},
            )
            result = immediate_result or self._wait_for_js_bundle_factor(
                tx_context,
                headers,
                txid,
                tx_context['push_status_urls'],
                ['push_txid'],
            )
        elif self.duo_factor == 'Phone Call':
            pkey = self._discover_authenticator_key(tx_context, headers, 'phone_call')
            txid, immediate_result = self._initiate_js_bundle_factor(
                tx_context,
                post_headers,
                tx_context['phone_call_trigger_urls'],
                {'authkey': tx_context['authkey'], 'pkey': pkey},
            )
            result = immediate_result or self._wait_for_js_bundle_factor(
                tx_context,
                headers,
                txid,
                tx_context['phone_call_status_urls'],
                ['txid', 'phone_call_txid'],
            )
        elif self.duo_factor == 'Passcode':
            if not self.duo_passcode:
                raise Exception('Duo passcode is required when using Passcode with the Duo JS-bundle flow')
            self._load_auth_payload(tx_context, headers)
            self._preauth_initialize(tx_context, headers)
            self._preauth_evaluate(tx_context, headers)
            txid, immediate_result = self._initiate_js_bundle_factor(
                tx_context,
                post_headers,
                tx_context['passcode_trigger_urls'],
                {'authkey': tx_context['authkey'], 'mobile_otp': self.duo_passcode},
            )
            result = immediate_result
            if not result:
                raise Exception(f'Did not receive result from pass code submission')
        else:
            raise Exception(f'Factor "{self.duo_factor}" is not supported in Duo JS-bundle fallback')

        self._complete_js_bundle_auth(tx_context, headers, result)

    @staticmethod
    def _get_prompt_referer(tx_context):
        referer_url = f"{tx_context['duo_origin']}/prompt/{tx_context['akey']}?authkey={tx_context['authkey']}"
        if tx_context['req_trace_group']:
            referer_url += f"&req_trace_group={tx_context['req_trace_group']}"
        return referer_url

    def _get_prompt_api_headers(self, tx_context, include_origin=False):
        if not isinstance(tx_context, dict):
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0',
                'Accept': '*/*',
                'Content-Type': 'application/json',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
            }
            if tx_context:
                headers['X-Duo-Req-Trace-Group'] = tx_context
            return headers

        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0',
            'Accept': '*/*',
            'Content-Type': 'application/json',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Referer': self._get_prompt_referer(tx_context),
        }
        if tx_context['req_trace_group']:
            headers['X-Duo-Req-Trace-Group'] = tx_context['req_trace_group']
        if include_origin:
            headers['Origin'] = tx_context['duo_origin']
        return headers

    def _request(self, method, url, **kwargs):
        return self.session.request(method, url, **kwargs)

    def _get(self, url, **kwargs):
        return self._request('GET', url, **kwargs)

    def _post(self, url, **kwargs):
        return self._request('POST', url, **kwargs)


    @staticmethod
    def _flatten_values(value):
        if isinstance(value, dict):
            for nested_value in value.values():
                yield from OktaDuoUniversal._flatten_values(nested_value)
        elif isinstance(value, list):
            for item in value:
                yield from OktaDuoUniversal._flatten_values(item)
        else:
            yield value

    def _load_auth_payload(self, tx_context, headers):
        browser_features = self._get_browser_features()
        payload_response = self._get(
            tx_context['auth_payload_url'],
            params={
                'authkey': tx_context['authkey'],
                'browser_features': json.dumps(browser_features, separators=(',', ':')),
            },
            headers=headers,
        )
        payload_response.raise_for_status()
        payload_data = payload_response.json()
        if payload_data.get('stat') != 'OK':
            raise Exception(f"Duo auth payload load failed: {payload_response.text}")
        return payload_data.get('response', {})

    def _preauth_initialize(self, tx_context, headers):
        init_response = self._get(
            tx_context['preauth_init_url'],
            params={
                'authkey': tx_context['authkey'],
                'is_ipad': 'false',
            },
            headers=headers,
        )
        init_response.raise_for_status()
        init_data = init_response.json()
        if init_data.get('stat') != 'OK':
            raise Exception(f"Duo pre-auth initialization failed: {init_response.text}")
        return init_data.get('response', {})

    def _preauth_evaluate(self, tx_context, headers):
        browser_features = self._get_browser_features()
        eval_response = self._get(
            tx_context['preauth_eval_url'],
            params={
                'authkey': tx_context['authkey'],
                'browser_features': json.dumps(browser_features, separators=(',', ':')),
                'local_trust_choice': 'undecided',
            },
            headers=headers,
        )
        eval_response.raise_for_status()
        data = eval_response.json()
        if data.get('stat') != 'OK':
            raise Exception(f"Duo pre-auth evaluation failed: {eval_response.text}")

        return data.get('response', {})

    def _discover_authenticator_key(self, tx_context, headers, factor_type):
        self._load_auth_payload(tx_context, headers)
        self._preauth_initialize(tx_context, headers)
        response_data = self._preauth_evaluate(tx_context, headers)

        pkey = self._find_first_factor_pkey(response_data, factor_type)
        if not pkey:
            raise Exception(f'Unable to find a Duo authenticator key for factor type "{factor_type}" in pre-auth response')
        return pkey

    def _find_first_factor_pkey(self, value, factor_type):
        if isinstance(value, dict):
            factor_type_value = str(value.get('factor_type', value.get('factorType', ''))).lower()
            if factor_type_value == factor_type:
                for key_path in [
                    ('device_info', 'pkey'),
                    ('phone_info', 'pkey'),
                    ('authenticator_key',),
                    ('pkey',),
                ]:
                    pvalue = value
                    for key in key_path:
                        pvalue = pvalue.get(key) if isinstance(pvalue, dict) else None
                    if pvalue:
                        return pvalue

            if factor_type == 'push' and 'pkey' in value and value.get('pkey'):
                return value['pkey']

            auth_method_type = str(value.get('auth_method_type', value.get('authMethodType', ''))).lower()
            factor = str(value.get('factor', value.get('name', ''))).lower()
            if factor_type == 'push' and auth_method_type == 'push' and value.get('authenticator_key'):
                return value['authenticator_key']
            if factor_type == 'push' and factor in ['duo push', 'push'] and value.get('authenticator_key'):
                return value['authenticator_key']

            for nested_value in value.values():
                found = self._find_first_factor_pkey(nested_value, factor_type)
                if found:
                    return found
        elif isinstance(value, list):
            for item in value:
                found = self._find_first_factor_pkey(item, factor_type)
                if found:
                    return found
        return None

    @staticmethod
    def _ensure_list(value):
        if isinstance(value, list):
            return value
        return [value]

    def _initiate_js_bundle_factor(self, tx_context, headers, trigger_urls, payload):
        trigger_urls = self._ensure_list(trigger_urls)
        last_404_error = None
        factor_response = None

        for trigger_url in trigger_urls:
            factor_response = self._post(
                trigger_url,
                json=payload,
                headers=headers,
            )
            try:
                factor_response.raise_for_status()
                break
            except Exception as err:
                status_code = getattr(getattr(err, 'response', None), 'status_code', None)
                if status_code == 404 and len(trigger_urls) > 1:
                    last_404_error = err
                    continue
                raise
        else:
            if last_404_error:
                raise last_404_error
            raise Exception('Failed to trigger Duo MFA factor')

        factor_data = factor_response.json()
        if factor_data.get('stat') != 'OK':
            raise Exception(f"Triggering Duo MFA failed: {factor_response.text}")

        response_data = factor_data.get('response', {})
        txid = (
            response_data.get('push_txid')
            or response_data.get('pushTxid')
            or response_data.get('phone_call_txid')
            or response_data.get('phoneCallTxid')
            or response_data.get('txid')
        )

        # Some factor endpoints can return a final auth result immediately.
        auth_result = response_data.get('result', {})
        if isinstance(auth_result, dict):
            status_code = str(auth_result.get('status_code', '')).lower()
            result = str(auth_result.get('result', '')).upper()
            if result == 'SUCCESS' or status_code == 'allow':
                return txid, factor_data
            if result == 'FAILURE' or status_code == 'deny':
                raise DuoMfaDenied(factor_data)

        authn_eval = response_data.get('authn_evaluation', {})
        authz_eval = response_data.get('authz_evaluation', {})
        if authn_eval or authz_eval:
            if authn_eval.get('is_allowed') and authz_eval.get('is_allowed', True):
                return txid, factor_data
            raise DuoMfaDenied(factor_data)

        if not txid:
            raise Exception('Duo factor trigger response did not contain a transaction id')
        return txid, None

    def _wait_for_js_bundle_factor(self, tx_context, headers, txid, status_urls, txid_param_names):
        status_urls = self._ensure_list(status_urls)
        txid_param_names = self._ensure_list(txid_param_names)
        tries = 0
        while tries < 16:
            tries += 1
            time.sleep(0.5)
            status_response = None
            status_retrieved = False
            last_404_error = None

            for status_url in status_urls:
                for txid_param_name in txid_param_names:
                    params = {
                        'authkey': tx_context['authkey'],
                        txid_param_name: txid,
                    }
                    if not status_url.endswith('/poll'):
                        params['saw_good_news'] = 'false'

                    status_response = self._get(
                        status_url,
                        params=params,
                        headers=headers,
                    )
                    try:
                        status_response.raise_for_status()
                        status_retrieved = True
                        break
                    except Exception as err:
                        status_code = getattr(getattr(err, 'response', None), 'status_code', None)
                        if status_code in (400, 404) and (len(status_urls) > 1 or len(txid_param_names) > 1):
                            last_404_error = err
                            continue
                        raise
                if status_retrieved:
                    break

            if not status_retrieved:
                if last_404_error:
                    raise last_404_error
                raise Exception('Failed to read Duo MFA status')

            status_data = status_response.json()
            if status_data.get('stat') != 'OK':
                raise Exception(f"Error checking Duo MFA status: {status_response.text}")

            response_data = status_data.get('response', {})
            result_data = response_data.get('result', response_data)
            if isinstance(result_data, dict):
                result = str(result_data.get('result', '')).upper()
                status_code = str(result_data.get('status_code', '')).lower()
            else:
                # Some poll endpoints return a scalar state such as "STATUS" while in progress.
                result = str(result_data).upper()
                status_code = str(response_data.get('status_code', '')).lower()

            if result == 'SUCCESS' or status_code == 'allow':
                return status_data
            if result == 'FAILURE' or status_code == 'deny':
                raise DuoMfaDenied(status_data)

        raise Exception('Timed out waiting for Duo MFA')

    def _complete_js_bundle_auth(self, tx_context, headers, push_result):
        # After push approval, use the OIDC external exit endpoint to complete auth
        response_data = push_result.get('response', {})
        result_data = response_data.get('result', {})
        if isinstance(result_data, dict) and result_data:
            auth_result = result_data.get('auth_result', {})
        else:
            auth_result = response_data.get('auth_result', {}) or response_data
        authn_eval = auth_result.get('authn_evaluation', {})

        if not authn_eval.get('is_allowed'):
            raise Exception('Duo authentication evaluation failed: is_allowed=false')

        finalize_response = self._get(
            tx_context['finalize_auth_url'],
            allow_redirects=True,
            headers=headers,
            params={
                'authkey': tx_context['authkey'],
            }
        )
        finalize_response.raise_for_status()
        finalize_json = finalize_response.json()
        if finalize_json.get('stat') == 'OK':
            exit_response = self._get(
                finalize_json['response']['url'],
                allow_redirects=True,
                headers={'User-Agent': headers['User-Agent'], 'Referer': headers['Referer'], 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'},
            )
            exit_response.raise_for_status()


    @staticmethod
    def _get_browser_features():
        # Mirror the fields sent by Duo's web client for pre-auth and auth payload endpoints.
        return {
            'touch_supported': False,
            'platform_authenticator_status': 'unavailable',
            'webauthn_supported': False,
            'screen_resolution_height': 0,
            'screen_resolution_width': 0,
            'screen_color_depth': 0,
            'is_uvpa_available': False,
            'client_capabilities_uvpa': False,
        }

    def _submit_duo_login_form(self, duo_login_form_data, login_form_action_url):
        # Submit Duo's form id=login-form, which triggers a Duo Push, phone call, or accepts a Passcode.
        duo_login_form_response = self._post(
            login_form_action_url.url,
            data=duo_login_form_data,
            headers=self._get_form_headers(),
        )
        duo_login_form_response.raise_for_status()
        duo_sid = duo_login_form_data['sid']
        duo_factor = duo_login_form_data['factor']
        duo_xsrf = duo_login_form_data['_xsrf']
        duo_login_response_data = duo_login_form_response.json()
        if duo_login_response_data['stat'] != 'OK':
            raise Exception(f"Triggering Duo MFA failed: {duo_login_form_response.text}")
        duo_txid = duo_login_response_data['response']['txid']
        return duo_factor, duo_sid, duo_txid, duo_xsrf

    def _handle_duo_plugin_form(self, duo_prompt_url):
        # Request Duo prompt
        verify_get_response = self._get(
            duo_prompt_url,
        )
        verify_get_response.raise_for_status()
        duo_origin = furl(verify_get_response.url).origin

        # New prompt deployments can return JS prompt directly with no plugin_form.
        doc = html5lib.parse(verify_get_response.content, namespaceHTMLElements=False)
        if doc.find('.//form[@id="plugin_form"]') is None:

            return duo_origin, verify_get_response

        # Submit first Duo form (plugin_form)
        form_data = self._get_duo_universal_plugin_form_data(verify_get_response)
        duo_plugin_form_response = self._post(
            verify_get_response.url,
            data=form_data,
            headers=self._get_form_headers(),
        )
        duo_plugin_form_response.raise_for_status()
        return duo_origin, duo_plugin_form_response

    def _initiate_okta_factor_verification(self):
        # POST to the Okta factor verify URL gives us the URL to request to load Duo
        verify_post_response = self._post(
            self.okta_factor['_links']['verify']['href'],
            params={'rememberDevice': self.remember_device},
            json={'stateToken': self.state_token},
        )
        verify_post_response.raise_for_status()
        verify_response_data = verify_post_response.json()
        duo_prompt_url = verify_response_data['_links']['next']['href']
        okta_profile_login = verify_response_data['_embedded']['user']['profile']['login']
        return duo_prompt_url, okta_profile_login

    def _wait_for_duo_universal_transaction(self, duo_host, txid, sid):
        status_url = furl(duo_host) / 'frame/v4/status'
        status_data = {
            'txid': txid,
            'sid': sid
        }
        headers = self._get_form_headers()

        tries = 0
        while tries < 16:
            tries += 1
            time.sleep(0.5)

            status_response = self._post(
                status_url.url,
                data=status_data,
                headers=headers,
            )
            status_response.raise_for_status()

            json_response = status_response.json()
            if json_response['stat'] != 'OK':
                raise Exception(f"Error checking Duo MFA status: {status_response.text}")

            if json_response['response']['status_code'] == 'allow':
                return txid
            if json_response['response']['status_code'] == 'deny':
                raise DuoMfaDenied(json_response)

        raise Exception('Timed out waiting for Duo MFA')

    @staticmethod
    def _get_form_headers():
        form_headers = {
            'User-Agent': "gimme-aws-creds {}".format(version),
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
        }
        return form_headers

    def _get_duo_universal_login_form_data(self, plugin_form_response):
        """ Get form data to post when submitting the Duo login-form """

        doc = html5lib.parse(plugin_form_response.content, namespaceHTMLElements=False)
        form_action = doc.find('.//form[@id="login-form"]').get('action')
        form_data = {}
        for field in doc.iterfind('.//form[@id="login-form"]/input'):
            form_data[field.get('name')] = field.get('value')

        preferred_device = self._find_device_to_use(doc)

        form_data['factor'] = self.duo_factor
        form_data['device'] = preferred_device
        form_data['postAuthDestination'] = 'OIDC_EXIT'
        if self.duo_passcode:
            form_data['passcode'] = self.duo_passcode

        return form_action, form_data

    @staticmethod
    def _find_device_to_use(doc):
        device = doc.find('.//input[@name="preferred_device"]').get('value')
        if device is None or device == '':
            device = doc.find('.//select[@name="device"]/option').get('value')
        return device

    @staticmethod
    def _get_duo_universal_plugin_form_data(response):
        """ Get form data to post when submitting the Duo plugin_form """

        doc = html5lib.parse(response.content, namespaceHTMLElements=False)
        form_data = {}
        for field in doc.iterfind('.//form[@id="plugin_form"]/input'):
            form_data[field.get('name')] = field.get('value')

        return form_data
