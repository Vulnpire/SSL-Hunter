# SSL Hunter

SSL Hunter is a powerful Python script designed for Bug Bounty Hunters and cybersecurity professionals. It facilitates efficient network reconnaissance by combining Masscan for rapid port scanning and SSL certificate retrieval. With SSL Hunter, users can swiftly identify potential vulnerabilities, extract critical SSL certificate details, and bolster their security defenses with actionable insights.

## Key Features

- Rapid Port Scanning: Leverages Masscan for high-speed port scanning, enabling swift identification of accessible hosts.
- SSL Certificate Extraction: Retrieves SSL certificates from discovered hosts, extracting vital domain information for analysis.
- Asynchronous Processing: Implements asynchronous processing for enhanced performance, ensuring efficient handling of large-scale scans.
- Customizable Scans: Offers flexibility with customizable port selection, allowing users to tailor scans based on specific requirements.


## Usage:

- Clone the Repository:
`
git clone https://github.com/byt3scr1b3/ssl-hunter.git
`

- Navigate to the Project Directory:

`
cd ./ssl-hunter
`

- IPs to scan:

`
echo $IPs > ips.txt
`

- Execute the Script:

`
./ssl-hunter
`
## Requirements:

```
Flask
pymongo
bson
MongoDB
gunicorn
aiohttp
json
```

- Example:

```
Enter custom ports to scan (comma-separated): 22,80,443,502,1337,5000,7000,8000,8080,9001
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2024-02-20 15:48:32 GMT
Initiating SYN Stealth Scan
Scanning 136896 hosts [1 port/host]

--SNIP--
Error for: http://3.1.69.179:22 , 
Title: Eyeglasses | Glasses Frames | Optical Shop Hong Kong - Swisscoat , http://3.1.237.181:80
Error for: http://3.1.13.116:80 , 
Error for: http://3.1.151.204:80 ,
Title: Welcome to your Strapi app , http://3.0.86.14:1337 ,
Error for: http://3.1.39.226:7000 , 
Title: 400 The plain HTTP request was sent to HTTPS port , http://3.1.228.168:443
Title: Apache2 Ubuntu Default Page: It works , http://3.0.221.21:80
Title:  , http://3.0.132.64:80
Title:  , http://3.0.247.35:80
Error for: http://3.0.254.61:80 , [Errno 104] Connection reset by peer
Title:  , http://3.0.6.92:80
Title: suntec-office-backend , http://3.1.94.13:80
Title: TinyCP , http://3.1.118.253:8080
--SNIP--
****************Results inserted successfully**************
{
  "message": "Inserted"
}
```

## Customization

SSL Hunter offers extensive customization options, allowing users to tailor scans according to their specific preferences. Modify parameters such as SSL port, custom ports, and scanning rates to optimize the scanning process for your unique requirements.

# Database

Python script for interacting with a database to store SSL scan results obtained by SSL Hunter. It connects to a database server, creates tables for storing scan data, and inserts scan results into the database.

## Key Features

- Database Integration: Establishes connections to MongoDB databases, ensuring reliable storage and retrieval of scan results.
- Automated Setup: Streamlines the setup of MongoDB databases and table creation, eliminating manual configuration complexities.
- Efficient Data Insertion: Simplifies the insertion of scan results into databases, promoting efficient data management practices.
- Versatile Compatibility: Designed to work seamlessly with MongoDB databases, with potential for compatibility with other systems.

## Navigation

    /insert: Endpoint for inserting scan results into the database.
    /bytitle: Endpoint for querying scan results by title.
        Parameters:
            title: Title to search for.
            from: Starting index for pagination.
            to: Ending index for pagination.
    /bydomain: Endpoint for querying scan results by domain.
        Parameters:
            domain: Domain to search for.
    /byip: Endpoint for querying scan results by IP address.
        Parameters:
            ip: IP address to search for.
    /byport: Endpoint for querying scan results by port.
        Parameters:
            port: Port number to search for.
            from: Starting index for pagination.
            to: Ending index for pagination.
    /byhtml: Endpoint for querying scan results by HTML content.
        Parameters:
            html: HTML content to search for.
            from: Starting index for pagination.
            to: Ending index for pagination.
    /byhresponse: Endpoint for querying scan results by response headers content.
        Parameters:
            hresponse: Response header content to search for.
            from: Starting index for pagination.
            to: Ending index for pagination.
    /byhkeyresponse: Endpoint for querying scan results by response header keys.
        Parameters:
            hkeyresponse: Response header key to search for.
            from: Starting index for pagination.
            to: Ending index for pagination.

