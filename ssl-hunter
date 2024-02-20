#!/bin/python3

import re
import ssl
import os
import subprocess
import asyncio

# from cryptography import x509
# from cryptography.hazmat.backends import default_backend
import json
from OpenSSL import crypto
import aiohttp
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup, SoupStrainer


class SSLChecker:
    def __init__(
        self,
        ssl_port=443,
        custom_ports=None,
        mass_scan_results_file="masscanResults.txt",
        ips_file="ips.txt",
        masscan_rate=10000,
        timeout=3,
        chunkSize=2000,
        MAX_CONCURRENT=100,
        semaphore_limit=70,
        protocols=["http://", "https/"],
        server_url="http://127.0.0.1:5000/insert",
    ):
        self.ssl_port = ssl_port
        self.custom_ports = custom_ports if custom_ports else [80]  # Change to custom_ports
        self.mass_scan_results_file = mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate
        self.protocols = protocols
        self.server_url = server_url
        self.timeout = timeout
        self.chunkSize = chunkSize
        self.semaphore = asyncio.Semaphore(semaphore_limit)
        self.MAX_CONCURRENT = MAX_CONCURRENT

    def is_valid_domain(self, common_name):
        # Regular expression pattern for a valid domain name
        domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(domain_pattern, common_name) is not None

    async def makeGetRequest(
        self, session, protocol, ip, common_name, makeRequestByIP=True
    ):
        async def parseResponse(url, port):
            try:
                if self.semaphore.locked():
                    # print("Concurrency limit reached, waiting ...")
                    await asyncio.sleep(1)

                redirected_domain = ""
                response_headers = {}
                first_300_words = ""
                title = ""

                async with session.get(
                    url, allow_redirects=True, timeout=self.timeout, ssl=False
                ) as res:
                    response = await res.text(encoding="utf-8")
                    content_type = res.headers.get("Content-Type")

                    if res.headers is not None:
                        for key, value in res.headers.items():
                            response_headers[key] = value.encode(
                                "utf-8", "surrogatepass"
                            ).decode("utf-8")

                    if res.history:
                        redirected_domain = str(res.url)

                    if response is not None and content_type is not None:
                        if "xml" in content_type:
                            root = ET.fromstring(response)
                            xmlwords = []
                            count = 0
                            # iter, loops over the all the subelements  in the XML document
                            for elem in root.iter():
                                if elem.text:
                                    xmlwords.extend(elem.text.split())
                                    count += len(xmlwords)
                                    if count >= 300:
                                        break
                            if xmlwords:
                                first_300_words = " ".join(xmlwords[:300])

                        elif "html" in content_type:
                            strainer = SoupStrainer(["title", "body"])
                            soup = BeautifulSoup(
                                response,
                                "html.parser",
                                parse_only=strainer,
                            )
                            title_tag = soup.title
                            body_tag = soup.body

                            # .string accesses the string content of the title
                            if title_tag and title_tag.string:
                                title = title_tag.string.strip()

                            if body_tag:
                                # Get all the text within the body tag including text from nested elements
                                body_text = body_tag.get_text(separator=" ", strip=True)
                                # Split the text into words
                                words = body_text.split()
                                # Take the first 300 words
                                first_300_words = " ".join(words[:300])

                            # Sometimes there is just text on the website without title/body, Beautifulsoup can't get those, updated the line right below so if both title and body can't be parsed,this usually happens with websites use React or dynamically renderer html
                            if not body_tag and not title_tag:
                                words = response.split()
                                # Take the first 300 words
                                first_300_words = " ".join(words[:300])

                        # For content-type text/plain
                        elif "plain" in content_type:
                            words = response.split()
                            first_300_words = " ".join(words[:300])

                        elif "json" in content_type:
                            first_300_words = response[:300]

                        if makeRequestByIP:
                            print(f"Title: {title} , {protocol}{ip}:{port}")
                        else:
                            print(f"Title:{title} ,{common_name}")

                            # Create a dictionary for the result
                        result_dict = {
                            "title": title.encode("utf-8", "surrogatepass").decode(
                                "utf-8"
                            ),
                            "request": f"{protocol}{ip if makeRequestByIP else common_name}:{port}",
                            "redirected_url": redirected_domain,
                            "ip": ip,
                            "port": str(port),
                            "domain": common_name,
                            "response_text": first_300_words,
                            "response_headers": response_headers,
                        }

                        return result_dict

            except ET.ParseError as e:
                print(f"Error parsing XML: {e}")
            except Exception as e:
                if makeRequestByIP:
                    print(f"Error for: {protocol}{ip}:{port} , {e}")
                else:
                    print(f"Error for: {protocol}{common_name}:{port}, {e}")
            # Return None if there's an error and the try block doesn't complete
            return None

        url = ""
        if makeRequestByIP:
            if protocol == "http://":
                httpResults = []
                for port in self.custom_ports:
                    url = f"{protocol}{ip}:{port}"
                    result = await parseResponse(url, port)
                    if result is not None:
                        httpResults.append(result)
                if httpResults:
                    return httpResults
                else:
                    return None
            else:
                url = f"{protocol}{ip}:{self.ssl_port}"
                return await parseResponse(url, self.ssl_port)

        else:
            port = "80" if protocol == "http://" else self.ssl_port
            url = f"{protocol}{common_name}:{port}"
            return await parseResponse(url, port)

    async def check_site(self, session, ip, common_name):
        try:
            async with self.semaphore:
                temp_dict = {}

                if "*" in common_name or not self.is_valid_domain(common_name):
                    # If there is an asterisk in the common_name then make a request to the IP address, but sometimes if we use http://ip we get a different result and sometimes if we use https://ip we get a different result so we make HTTP and HTTPS requests for the IP so 2 requests in total
                    for protocol in self.protocols:
                        dict_res = await self.makeGetRequest(
                            session, protocol, ip, common_name, True
                        )
                        temp_dict[
                            f'{protocol.replace("://", "")}_responseForIP'
                        ] = dict_res

                else:
                    # If we found a proper domain name from ssl certificate, then make a request to that domain using http:// and https:// and also make request using IP address so in total 4 requests
                    for protocol in self.protocols:
                        dict_res = await self.makeGetRequest(
                            session, protocol, ip, common_name, False
                        )
                        temp_dict[
                            f'{protocol.replace("://", "")}_responseForDomainName'
                        ] = dict_res

                    # Also make a request using to http:// and https:// using the IP address
                    for protocol in self.protocols:
                        dict_res = await self.makeGetRequest(
                            session, protocol, ip, common_name, True
                        )
                        temp_dict[
                            f'{protocol.replace("://", "")}_responseForIP'
                        ] = dict_res

                # Filter out None values from temp_dict
                temp_dict = {k: v for k, v in temp_dict.items() if v is not None}
                # Only append non-empty dictionaries to the results
                if temp_dict:
                    return temp_dict

        except Exception as e:
            print("Error for", ip, ":", e)

        # If something goes wrong like a timeout we must return None
        return None

    async def fetch_certificate(self, ip):
        try:
            # cert_data = await asyncio.to_thread(
            #     ssl.get_server_certificate, (ip, 443), ssl_version=ssl.PROTOCOL_TLS
            # )
            # x509_cert = x509.load_pem_x509_certificate(
            #     cert_data.encode(), default_backend()
            # )
            # common_name = x509_cert.subject.get_attributes_for_oid(
            #     x509.NameOID.COMMON_NAME
            # )[0].value

            cert = await asyncio.to_thread(
                ssl.get_server_certificate, (ip, self.ssl_port), timeout=self.timeout
            )

            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            subject = x509.get_subject()
            common_name = subject.CN
            print(common_name)

            return ip, common_name

        except asyncio.TimeoutError as e:
            print(f"Timeout while fetching certificate for {ip}: {e}")

        except Exception as e:
            print(f"Error for {ip} , {e}")

        # If we get to the line below, there will be timeout so ip did not response in that case return None and we wont process these ips with none
        return ip, ""

    async def extract_domains(self):
        try:
            with open(self.mass_scan_results_file, "r") as file:
                content = file.read()

            ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            ip_addresses = re.findall(ip_pattern, content)

            for i in range(0, len(ip_addresses), self.chunkSize):
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(limit=self.MAX_CONCURRENT, ssl=False)
                ) as session:
                    chunk_Of_IPs = ip_addresses[i : i + self.chunkSize]
                    ip_and_common_names = []

                    ip_and_common_names = await asyncio.gather(
                        *[self.fetch_certificate(ip) for ip in chunk_Of_IPs]
                    )

                    allResponses = await asyncio.gather(
                        *[
                            self.check_site(session, ip, common_name)
                            for ip, common_name in ip_and_common_names
                        ]
                    )

                    # Filter out None/ null values
                    allResponses = [
                        response for response in allResponses if response is not None
                    ]

                    results_json = json.dumps(allResponses)
                    headers = {"Content-Type": "application/json"}

                    async with session.post(
                        self.server_url, data=results_json, headers=headers, ssl=False
                    ) as res:
                        if res.status == 201 or res.status == 200:
                            print(
                                "****************Results inserted successfully**************"
                            )
                        else:
                            print(
                                f"Failed to insert results. Status code: {res.status}"
                            )
                        print(await res.text())

                        await session.close()

                        # Clear variables
                        del allResponses
                        del results_json
                        del ip_and_common_names

        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def run_masscan(self):
        try:
            # This rate limit is the ideal to get the maximum amount of ip addresses
            command = f"sudo masscan -p443 --rate {self.masscan_rate} --wait 0 -iL {self.ips_file} -oH {self.mass_scan_results_file}"
            subprocess.run(command, shell=True, check=True)

        except subprocess.CalledProcessError as e:
            print(f"Error while running masscan: {e}")
        except FileNotFoundError:
            print("Masscan executable not found.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def check_and_create_files(self, *file_paths):
        for file_path in file_paths:
            if not os.path.exists(file_path):
                # If the file doesn't exist, create it
                with open(file_path, "w") as file:
                    pass

                print(f'File "{file_path}" has been created.')

    async def main(self):
        self.check_and_create_files(self.mass_scan_results_file, self.ips_file)
        self.run_masscan()
        await self.extract_domains()


if __name__ == "__main__":
    # Prompt user for custom ports
    custom_ports = input("Enter custom ports to scan (comma-separated): ")
    custom_ports = [int(port.strip()) for port in custom_ports.split(",")]

    ssl_checker = SSLChecker(custom_ports=custom_ports)
    asyncio.run(ssl_checker.main())
