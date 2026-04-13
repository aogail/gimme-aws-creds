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
        exit_response = self.session.post(
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
        path_prefix = f'/prompt/{akey}'
        return {
            'mode': 'js_bundle',
            'duo_origin': duo_origin,
            'akey': akey,
            'authkey': authkey,
            'req_trace_group': req_trace_group,
            'preauth_init_url': f'{duo_origin}{path_prefix}/pre_authn/initialization',
            'preauth_eval_url': f'{duo_origin}{path_prefix}/pre_authn/evaluation',
            'push_trigger_url': f'{duo_origin}{path_prefix}/auth/factors/push/auth',
            'push_status_url': f'{duo_origin}{path_prefix}/auth/factors/push/status',
            'auth_payload_url': f'{duo_origin}{path_prefix}/auth/payload',
            'authz_url': f'{duo_origin}{path_prefix}/auth/authorization_url',
            'finalize_auth_url': f'{duo_origin}{path_prefix}/auth/finalize_auth',
        }

    def _perform_js_bundle_flow(self, tx_context):
        if self.duo_factor != 'Duo Push':
            raise Exception(f'Factor "{self.duo_factor}" is not supported in Duo JS-bundle fallback yet. Use Duo Push.')

        headers = self._get_prompt_api_headers(tx_context['req_trace_group'])
        pkey = self._discover_push_authenticator_key(tx_context, headers)
        push_txid = self._initiate_js_bundle_push(tx_context, headers, pkey)
        push_result = self._wait_for_js_bundle_push(tx_context, headers, push_txid)
        self._complete_js_bundle_auth(tx_context, headers, push_result)

    def _get_prompt_api_headers(self, req_trace_group):
        headers = {
            'User-Agent': "gimme-aws-creds {}".format(version),
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        if req_trace_group:
            headers['x-duo-request-id'] = req_trace_group
        return headers

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

    def _discover_push_authenticator_key(self, tx_context, headers):
        browser_features = self._get_browser_features()
        init_response = self.session.get(
            tx_context['preauth_init_url'],
            params={
                'authkey': tx_context['authkey'],
                'is_ipad': 'false',
            },
            headers=headers,
        )
        init_response.raise_for_status()

        eval_response = self.session.get(
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

        response_data = data.get('response', {})
        pkey = self._find_first_push_pkey(response_data)
        if not pkey:
            raise Exception('Unable to find a Duo Push authenticator key in pre-auth response')
        return pkey

    def _find_first_push_pkey(self, value):
        if isinstance(value, dict):
            if 'pkey' in value and value.get('pkey'):
                return value['pkey']
            auth_method_type = str(value.get('auth_method_type', value.get('authMethodType', ''))).lower()
            factor = str(value.get('factor', value.get('name', ''))).lower()
            if auth_method_type == 'push' and value.get('authenticator_key'):
                return value['authenticator_key']
            if factor in ['duo push', 'push'] and value.get('authenticator_key'):
                return value['authenticator_key']
            for nested_value in value.values():
                found = self._find_first_push_pkey(nested_value)
                if found:
                    return found
        elif isinstance(value, list):
            for item in value:
                found = self._find_first_push_pkey(item)
                if found:
                    return found
        return None

    def _initiate_js_bundle_push(self, tx_context, headers, pkey):
        push_response = self.session.post(
            tx_context['push_trigger_url'],
            json={
                'authkey': tx_context['authkey'],
                'pkey': pkey,
                'otp_code': self.duo_passcode or '',
            },
            headers=headers,
        )
        push_response.raise_for_status()
        push_data = push_response.json()
        if push_data.get('stat') != 'OK':
            raise Exception(f"Triggering Duo MFA failed: {push_response.text}")

        response_data = push_data.get('response', {})
        push_txid = response_data.get('push_txid') or response_data.get('pushTxid') or response_data.get('txid')
        if not push_txid:
            raise Exception('Duo push trigger response did not contain push txid')
        return push_txid

    def _wait_for_js_bundle_push(self, tx_context, headers, push_txid):
        tries = 0
        while tries < 16:
            tries += 1
            time.sleep(0.5)
            status_response = self.session.get(
                tx_context['push_status_url'],
                params={
                    'authkey': tx_context['authkey'],
                    'push_txid': push_txid,
                    'saw_good_news': 'false',
                },
                headers=headers,
            )
            status_response.raise_for_status()
            status_data = status_response.json()
            if status_data.get('stat') != 'OK':
                raise Exception(f"Error checking Duo MFA status: {status_response.text}")

            result_data = status_data.get('response', {}).get('result', status_data.get('response', {}))
            result = str(result_data.get('result', '')).upper()
            status_code = str(result_data.get('status_code', '')).lower()

            if result == 'SUCCESS' or status_code == 'allow':
                # finalize_response = self.session.get(
                #     tx_context['finalize_auth_url'],
                #     params={
                #         'authkey': tx_context['authkey'],
                #     }
                # )
                # print(finalize_response.text)
                return status_data
            if result == 'FAILURE' or status_code == 'deny':
                raise DuoMfaDenied(status_data)

        raise Exception('Timed out waiting for Duo MFA')

    def _complete_js_bundle_auth(self, tx_context, headers, push_result):
        # After push approval, use the OIDC external exit endpoint to complete auth
        auth_result = push_result.get('response', {}).get('result', {}).get('auth_result', {})
        authn_eval = auth_result.get('authn_evaluation', {})

        if not authn_eval.get('is_allowed'):
            raise Exception('Duo authentication evaluation failed: is_allowed=false')

        finalize_response = self.session.get(
            tx_context['finalize_auth_url'],
            allow_redirects=True,
            params={
                'authkey': tx_context['authkey'],
            }
        )
        finalize_response.raise_for_status()
        finalize_json = finalize_response.json()
        if finalize_json.get('stat') == 'OK':
            exit_response = self.session.get(
                finalize_json['response']['url'],
                allow_redirects=True,
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
        duo_login_form_response = self.session.post(
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
        verify_get_response = self.session.get(
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
        duo_plugin_form_response = self.session.post(
            verify_get_response.url,
            data=form_data,
            headers=self._get_form_headers(),
        )
        duo_plugin_form_response.raise_for_status()
        return duo_origin, duo_plugin_form_response

    def _initiate_okta_factor_verification(self):
        # POST to the Okta factor verify URL gives us the URL to request to load Duo
        verify_post_response = self.session.post(
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

            status_response = self.session.post(
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
