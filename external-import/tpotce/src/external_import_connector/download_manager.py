import hashlib
import ipaddress
import logging
import os
import re
import tempfile
import uuid
from time import sleep
from urllib.parse import urlparse

import magic
import requests
from pymispwarninglists import WarningLists


class DownloadManager:
    def __init__(self, helper, proxy_url=None):
        self.proxy_url = proxy_url
        self.session = requests.Session()
        self.helper = helper

        if proxy_url:
            try:
                self.proxy_url = self.validate_proxy_url(proxy_url)
                self.session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
                self.helper.log_info(f"Proxy set to: {self.proxy_url}")
            except ValueError as e:
                logging.error(str(e))
                self.proxy_url = None  # Fallback to no proxy

        # Load MISP warning lists
        self.warninglists = WarningLists()

    def extract_strings(self, file_path):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    def validate_proxy_url(self, proxy_url):
        parsed = urlparse(proxy_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                f"Malformed proxy URL: {proxy_url}. Ensure it includes the scheme (http/https) and the host."
            )
        return proxy_url

    def detect_file_type(self, file_path):
        file_type = magic.from_file(file_path, mime=True)
        return file_type

    def is_bash_script(self, file_path):
        # Check if the file is identified as text/plain and has a .sh extension
        file_type = self.detect_file_type(file_path)
        _, file_extension = os.path.splitext(file_path)
        return file_type == "text/plain" and file_extension.lower() == ".sh"

    def validate_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Filter out private IPs but allow VPN IPs based on MISP warning lists
            if (
                self.warninglists.search(ip)
                or ip_obj.is_private
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_loopback
            ):
                return False
            return True
        except ValueError:
            return False

    def validate_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def extract_network_indicators(self, strings):
        # IP address regex
        ip_regex = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

        # URL regex
        url_regex = re.compile(
            r"(https?://(?:www\.)?[-\w@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-\w@:%_\+.~#?&//=]*))"
        )

        # SSH-RSA key regex
        ssh_key_regex = re.compile(r"ssh-rsa\s+([A-Za-z0-9+/=]+)")

        # Find all IPs and URLs in the input string
        ips = set(ip_regex.findall(strings))
        urls = set(url_regex.findall(strings))

        # Find SSH keys in the input string
        ssh_keys = set(ssh_key_regex.findall(strings))

        # Validate IPs and URLs
        ips = {ip for ip in ips if self.validate_ip(ip)}
        urls = {url for url in urls if self.validate_url(url)}

        # Log the extracted indicators
        self.helper.log_info(f"Filtered and Validated IPs: {ips}")
        self.helper.log_info(f"Filtered and Validated URLs: {urls}")
        self.helper.log_info(
            f"Extracted SSH-RSA Keys: {ssh_keys}"
        )  # Added logging for SSH keys

        # Return the found indicators
        return {
            "ips": list(ips),
            "urls": list(urls),
            "ssh_keys": list(ssh_keys),  # Include the extracted SSH keys
        }

    def download_and_extract_file_info(self, url, timeout=10):
        """
        Download the file from the URL and calculate its properties including hashes, size, and MIME type.
        :param url: URL to download the file from.
        :param timeout: Timeout for the HTTP request.
        :return: tuple (sha256, sha1, md5, sha512, file_size, mime_type, file_name, parsed_data, file_path)
        """
        try:
            # Download the file using the session (which will use the proxy if configured)
            response = self.download_with_retry(url, timeout=timeout)
            if not response:
                return (
                    None,
                    None,
                    None,
                    None,
                    0,
                    "application/octet-stream",
                    None,
                    {},
                    None,
                )

            # Use a temporary file path
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                file_path = temp_file.name
                file_name = os.path.basename(urlparse(url).path) or str(uuid.uuid4())

            # Calculate hashes
            sha256 = hashlib.sha256()
            sha1 = hashlib.sha1()
            md5 = hashlib.md5()
            sha512 = hashlib.sha512()

            file_size = os.path.getsize(file_path)  # Get file size
            mime_type = magic.from_file(file_path, mime=True)  # Detect MIME type

            with open(file_path, "rb") as file:
                while chunk := file.read(8192):
                    sha256.update(chunk)
                    sha1.update(chunk)
                    md5.update(chunk)
                    sha512.update(chunk)

            self.helper.log_info(f"\t\tDetected sha256 for {url}: {sha256.hexdigest()}")
            self.helper.log_info(f"\t\tDetected sha1 for {url}: {sha1.hexdigest()}")
            self.helper.log_info(f"\t\tDetected md5 for {url}: {md5.hexdigest()}")
            self.helper.log_info(f"\t\tDetected sha512 for {url}: {sha512.hexdigest()}")
            self.helper.log_info(f"\t\tFile size: {file_size} bytes")
            self.helper.log_info(f"\t\tMIME type: {mime_type}")

            # Return file details
            return (
                sha256.hexdigest(),
                sha1.hexdigest(),
                md5.hexdigest(),
                sha512.hexdigest(),
                file_size,
                mime_type,
                file_name,
                {},
                file_path,
            )

        except requests.exceptions.Timeout:
            logging.error(f"Timeout occurred when trying to download file from {url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error downloading or hashing file from {url}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error occurred: {e}")

        return None, None, None, None, 0, "application/octet-stream", None, {}, None

    def download_with_retry(self, url, retries=3, backoff=2, timeout=10):
        """Download the file with retry logic and exponential backoff in case of failure."""
        for attempt in range(retries):
            try:
                self.helper.log_info(f"Attempt {attempt + 1} to download {url}")
                response = self.session.get(url, stream=True, timeout=timeout)
                response.raise_for_status()  # Check if the request was successful
                return response
            except requests.exceptions.ProxyError:
                logging.error(
                    f"Proxy error during attempt {attempt + 1}. Check the proxy URL: {self.proxy_url}"
                )
                break  # No need to retry if the proxy itself is invalid
            except requests.exceptions.RequestException as e:
                logging.error(f"Attempt {attempt + 1} failed: {e}")
                sleep(backoff * (attempt + 1))  # Exponential backoff
        return None
